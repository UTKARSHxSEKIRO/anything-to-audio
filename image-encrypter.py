import io
import os
import struct
import threading
import numpy as np
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
from scipy.io import wavfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from pydub import AudioSegment

# ----------------- Modem & Audio Parameters -----------------
SAMPLE_RATE = 44100
CARRIER_FREQ = 1764             # 1.76 kHz: warm synth tone (eliminates harsh screech)
BAUD_RATE = 2205                # 2,205 symbols/sec (44100 / 20)
SAMPLES_PER_SYMBOL = SAMPLE_RATE // BAUD_RATE  # 20 samples per symbol

# 16-QAM Constellation Grid
LEVELS = np.array([-3.0, -1.0, 1.0, 3.0]) / np.sqrt(10.0)
CONSTELLATION = np.array([
    complex(LEVELS[i], LEVELS[q]) for i in range(4) for q in range(4)
])

# 32-symbol Barker synchronization header
SYNC_SYMBOLS = np.array([
    1+1j, -1-1j, 1-1j, -1+1j, 1+1j, 1+1j, -1-1j, 1-1j,
    -1-1j, 1+1j, -1+1j, -1-1j, 1+1j, -1-1j, 1-1j, 1+1j,
    1+1j, -1-1j, 1-1j, -1+1j, 1+1j, 1+1j, -1-1j, 1-1j,
    -1-1j, 1+1j, -1+1j, -1-1j, 1+1j, -1-1j, 1-1j, 1+1j
], dtype=np.complex64)

# ----------------- Image & Crypto Logic -----------------
def compress_image(image_path: str, target_kb: float = 8.5) -> bytes:
    """Scales and compresses an image to fit within target KB."""
    target_bytes = int(target_kb * 1024)
    img = Image.open(image_path).convert("RGB")

    for size in (320, 256, 200, 160):
        img_resized = img.resize((size, size), Image.Resampling.LANCZOS)
        for quality in range(75, 20, -10):
            buf = io.BytesIO()
            img_resized.save(buf, format="WEBP", quality=quality, method=6)
            data = buf.getvalue()
            if len(data) <= target_bytes:
                return data

    buf = io.BytesIO()
    img.resize((160, 160)).save(buf, format="WEBP", quality=25)
    return buf.getvalue()

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(passphrase.encode("utf-8"))

def encrypt_payload(data: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return struct.pack("!I", len(ciphertext)) + salt + nonce + ciphertext

def decrypt_payload(payload: bytes, passphrase: str) -> bytes:
    length = struct.unpack("!I", payload[:4])[0]
    salt = payload[4:20]
    nonce = payload[20:32]
    ciphertext = payload[32:32 + length]
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# ----------------- Smooth Modulation & Demodulation -----------------
def modulate_to_audio(data: bytes, output_mp3: str):
    symbols = []
    for byte in data:
        symbols.append(CONSTELLATION[(byte >> 4) & 0x0F])
        symbols.append(CONSTELLATION[byte & 0x0F])
    
    full_stream = np.concatenate([SYNC_SYMBOLS, np.array(symbols, dtype=np.complex64)])
    upsampled = np.repeat(full_stream, SAMPLES_PER_SYMBOL)
    t = np.arange(len(upsampled)) / SAMPLE_RATE
    carrier = np.exp(1j * 2 * np.pi * CARRIER_FREQ * t)
    rf_signal = np.real(upsampled * carrier)

    # Apply Hann window shaping across symbol boundaries to soften transitions
    window = np.hanning(SAMPLES_PER_SYMBOL)
    for i in range(len(rf_signal) // SAMPLES_PER_SYMBOL):
        start = i * SAMPLES_PER_SYMBOL
        end = start + SAMPLES_PER_SYMBOL
        rf_signal[start:end] *= (0.35 + 0.65 * window)

    # Scale to moderate amplitude (16000 max) to prevent speaker clipping
    max_val = np.max(np.abs(rf_signal))
    if max_val > 0:
        rf_signal = (rf_signal / max_val) * 16000

    temp_wav = "temp_qam_gui.wav"
    wavfile.write(temp_wav, SAMPLE_RATE, rf_signal.astype(np.int16))

    sound = AudioSegment.from_wav(temp_wav)
    sound.export(output_mp3, format="mp3", bitrate="320k")
    if os.path.exists(temp_wav):
        os.remove(temp_wav)

def demodulate_from_audio(mp3_path: str) -> bytes:
    sound = AudioSegment.from_file(mp3_path)
    if sound.frame_rate != SAMPLE_RATE:
        sound = sound.set_frame_rate(SAMPLE_RATE)
    samples = np.array(sound.get_array_of_samples(), dtype=np.float32)

    t = np.arange(len(samples)) / SAMPLE_RATE
    carrier = np.exp(-1j * 2 * np.pi * CARRIER_FREQ * t)
    baseband = samples * carrier

    num_symbols = len(baseband) // SAMPLES_PER_SYMBOL
    demod_symbols = np.zeros(num_symbols, dtype=np.complex64)

    for i in range(num_symbols):
        chunk = baseband[i * SAMPLES_PER_SYMBOL : (i + 1) * SAMPLES_PER_SYMBOL]
        demod_symbols[i] = np.mean(chunk)

    corr = np.abs(np.correlate(demod_symbols, SYNC_SYMBOLS, mode="valid"))
    sync_idx = int(np.argmax(corr)) + len(SYNC_SYMBOLS)
    payload_symbols = demod_symbols[sync_idx:]

    nibbles = []
    for s in payload_symbols:
        distances = np.abs(CONSTELLATION - s)
        nibbles.append(int(np.argmin(distances)))

    raw_bytes = bytearray()
    for i in range(0, len(nibbles) - 1, 2):
        byte = (nibbles[i] << 4) | nibbles[i + 1]
        raw_bytes.append(byte)

    return bytes(raw_bytes)

# ----------------- GUI Interface -----------------
class ImageModemGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Acoustic Image Cryptographer")
        self.geometry("700x640")
        self.resizable(False, False)

        style = ttk.Style(self)
        style.theme_use("clam")

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)

        self.tab_encode = ttk.Frame(notebook)
        self.tab_decode = ttk.Frame(notebook)

        notebook.add(self.tab_encode, text="  Encode Image to MP3  ")
        notebook.add(self.tab_decode, text="  Decode MP3 to Image  ")

        self.selected_image_path = None
        self.preview_photo_enc = None
        self.preview_photo_dec = None

        self.build_encode_tab()
        self.build_decode_tab()

    def build_encode_tab(self):
        top_frame = ttk.Frame(self.tab_encode)
        top_frame.pack(fill="x", padx=15, pady=(15, 5))

        self.lbl_enc_file = ttk.Label(top_frame, text="No image selected", width=50)
        self.lbl_enc_file.pack(side="left", fill="x", expand=True)

        btn_browse = ttk.Button(top_frame, text="Select Image...", command=self.select_image)
        btn_browse.pack(side="right")

        self.canvas_enc = tk.Canvas(self.tab_encode, width=220, height=220, bg="#2b2b2b", relief="sunken")
        self.canvas_enc.pack(pady=10)

        lbl_pwd = ttk.Label(self.tab_encode, text="Encryption Password:", font=("Arial", 9, "bold"))
        lbl_pwd.pack(anchor="w", padx=15, pady=(5, 2))

        self.ent_enc_pwd = ttk.Entry(self.tab_encode, show="*", width=35)
        self.ent_enc_pwd.pack(anchor="w", padx=15, pady=2)

        self.btn_encode = ttk.Button(self.tab_encode, text="Compress, Encrypt & Generate MP3", command=self.start_encode_thread)
        self.btn_encode.pack(pady=15)

        self.lbl_enc_status = ttk.Label(self.tab_encode, text="", foreground="blue")
        self.lbl_enc_status.pack()

    def build_decode_tab(self):
        top_frame = ttk.Frame(self.tab_decode)
        top_frame.pack(fill="x", padx=15, pady=(15, 5))

        self.ent_audio_path = ttk.Entry(top_frame, width=50)
        self.ent_audio_path.pack(side="left", fill="x", expand=True)

        btn_browse_audio = ttk.Button(top_frame, text="Select Audio...", command=self.select_audio)
        btn_browse_audio.pack(side="right", padx=(5, 0))

        lbl_pwd = ttk.Label(self.tab_decode, text="Decryption Password:", font=("Arial", 9, "bold"))
        lbl_pwd.pack(anchor="w", padx=15, pady=(10, 2))

        self.ent_dec_pwd = ttk.Entry(self.tab_decode, show="*", width=35)
        self.ent_dec_pwd.pack(anchor="w", padx=15, pady=2)

        self.btn_decode = ttk.Button(self.tab_decode, text="Demodulate & Decrypt Image", command=self.start_decode_thread)
        self.btn_decode.pack(pady=15)

        self.lbl_dec_status = ttk.Label(self.tab_decode, text="", foreground="blue")
        self.lbl_dec_status.pack()

        lbl_preview = ttk.Label(self.tab_decode, text="Restored Image Preview:", font=("Arial", 9, "bold"))
        lbl_preview.pack(anchor="w", padx=15, pady=(5, 2))

        self.canvas_dec = tk.Canvas(self.tab_decode, width=220, height=220, bg="#2b2b2b", relief="sunken")
        self.canvas_dec.pack(pady=5)

    def select_image(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Images", "*.png *.jpg *.jpeg *.webp *.bmp"), ("All Files", "*.*")]
        )
        if file_path:
            self.selected_image_path = file_path
            self.lbl_enc_file.config(text=os.path.basename(file_path))
            
            img = Image.open(file_path)
            img.thumbnail((220, 220))
            self.preview_photo_enc = ImageTk.PhotoImage(img)
            self.canvas_enc.create_image(110, 110, image=self.preview_photo_enc)

    def select_audio(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Audio Files", "*.mp3 *.wav"), ("All Files", "*.*")]
        )
        if file_path:
            self.ent_audio_path.delete(0, tk.END)
            self.ent_audio_path.insert(0, file_path)

    def start_encode_thread(self):
        threading.Thread(target=self.run_encode, daemon=True).start()

    def run_encode(self):
        if not self.selected_image_path:
            messagebox.showwarning("Warning", "Please choose an image to encode.")
            return
        pwd = self.ent_enc_pwd.get().strip()
        if not pwd:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".mp3",
            filetypes=[("MP3 Audio", "*.mp3")],
            title="Save Audio Signal"
        )
        if not save_path:
            return

        try:
            self.btn_encode.config(state="disabled")
            self.lbl_enc_status.config(text="Compressing image to target size...")
            
            compressed = compress_image(self.selected_image_path, target_kb=8.5)
            self.lbl_enc_status.config(text=f"Compressed size: {len(compressed)/1024:.2f} KB. Encrypting...")
            
            encrypted = encrypt_payload(compressed, pwd)
            self.lbl_enc_status.config(text="Generating smooth audio signal...")
            
            modulate_to_audio(encrypted, save_path)
            
            duration = (len(encrypted) * 2 + len(SYNC_SYMBOLS)) / BAUD_RATE
            self.lbl_enc_status.config(text=f"Completed! Duration: ~{duration:.1f}s")
            messagebox.showinfo("Success", f"Audio saved:\n{save_path}\nDuration: ~{duration:.1f} seconds")
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {e}")
            self.lbl_enc_status.config(text="")
        finally:
            self.btn_encode.config(state="normal")

    def start_decode_thread(self):
        threading.Thread(target=self.run_decode, daemon=True).start()

    def run_decode(self):
        audio_path = self.ent_audio_path.get().strip()
        pwd = self.ent_dec_pwd.get().strip()

        if not audio_path or not os.path.exists(audio_path):
            messagebox.showwarning("Warning", "Select a valid audio file.")
            return
        if not pwd:
            messagebox.showwarning("Warning", "Enter the decryption password.")
            return

        try:
            self.btn_decode.config(state="disabled")
            self.lbl_dec_status.config(text="Demodulating audio carrier & symbols...")
            
            payload = demodulate_from_audio(audio_path)
            self.lbl_dec_status.config(text="Decrypting payload with AES-GCM...")
            
            img_bytes = decrypt_payload(payload, pwd)
            
            img = Image.open(io.BytesIO(img_bytes))
            img_display = img.copy()
            img_display.thumbnail((220, 220))
            self.preview_photo_dec = ImageTk.PhotoImage(img_display)
            self.canvas_dec.create_image(110, 110, image=self.preview_photo_dec)

            save_img_path = filedialog.asksaveasfilename(
                defaultextension=".webp",
                filetypes=[("WebP Image", "*.webp"), ("PNG Image", "*.png")],
                title="Save Restored Image"
            )
            if save_img_path:
                img.save(save_img_path)

            self.lbl_dec_status.config(text="Image restored successfully!")
            messagebox.showinfo("Success", "Decrypted and restored the image successfully!")
        except Exception as e:
            messagebox.showerror("Decoding Failed", f"Could not decode audio: {e}\n\nCheck if password is correct and file is intact.")
            self.lbl_dec_status.config(text="")
        finally:
            self.btn_decode.config(state="normal")

if __name__ == "__main__":
    app = ImageModemGUI()
    app.mainloop()