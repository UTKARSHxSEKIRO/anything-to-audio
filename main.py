import os
import struct
import numpy as np
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scipy.io import wavfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from pydub import AudioSegment

# ----------------- Acoustic / FSK Settings -----------------
SAMPLE_RATE = 44100
BAUD_RATE = 100                 # 100 bits/sec (resilient against lossy MP3 compression)
SAMPLES_PER_BIT = int(SAMPLE_RATE / BAUD_RATE)

FREQ_MARK = 2400                # Bit 1 (Hz)
FREQ_SPACE = 1200               # Bit 0 (Hz)
PREAMBLE = b"\xAA\xAA\xAA\xAA"   # Synchronization bit pattern

# ----------------- Crypto Helpers -----------------
def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key from a passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(passphrase.encode('utf-8'))

def encrypt_payload(plaintext: str, passphrase: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    
    # Format: PREAMBLE + [Length (2B)] + [Salt (16B)] + [Nonce (12B)] + [Ciphertext + Tag]
    payload = struct.pack("!H", len(ciphertext)) + salt + nonce + ciphertext
    return PREAMBLE + payload

def decrypt_payload(payload: bytes, passphrase: str) -> str:
    # Unpack header
    length = struct.unpack("!H", payload[:2])[0]
    salt = payload[2:18]
    nonce = payload[18:30]
    ciphertext = payload[30:30 + length]

    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted.decode('utf-8')

# ----------------- DSP / Audio Modulation -----------------
def modulate_to_mp3(data: bytes, output_path: str):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    t = np.arange(SAMPLES_PER_BIT) / SAMPLE_RATE
    wave_mark = np.sin(2 * np.pi * FREQ_MARK * t)
    wave_space = np.sin(2 * np.pi * FREQ_SPACE * t)

    audio_samples = []
    for bit in bits:
        audio_samples.extend(wave_mark if bit == 1 else wave_space)

    audio_array = np.array(audio_samples, dtype=np.float32)
    temp_wav = "temp_render.wav"
    wavfile.write(temp_wav, SAMPLE_RATE, (audio_array * 32767).astype(np.int16))

    # Convert to MP3
    sound = AudioSegment.from_wav(temp_wav)
    sound.export(output_path, format="mp3", bitrate="192k")

    if os.path.exists(temp_wav):
        os.remove(temp_wav)

def demodulate_from_audio(audio_path: str) -> bytes:
    sound = AudioSegment.from_file(audio_path)
    samples = np.array(sound.get_array_of_samples(), dtype=np.float32)

    num_bits = len(samples) // SAMPLES_PER_BIT
    recovered_bits = []

    t = np.arange(SAMPLES_PER_BIT) / SAMPLE_RATE
    ref_mark = np.exp(-2j * np.pi * FREQ_MARK * t)
    ref_space = np.exp(-2j * np.pi * FREQ_SPACE * t)

    for i in range(num_bits):
        chunk = samples[i * SAMPLES_PER_BIT : (i + 1) * SAMPLES_PER_BIT]
        energy_mark = np.abs(np.dot(chunk, ref_mark))
        energy_space = np.abs(np.dot(chunk, ref_space))
        recovered_bits.append(1 if energy_mark > energy_space else 0)

    raw_bytes = bytearray()
    for i in range(0, len(recovered_bits) - 7, 8):
        byte_val = 0
        for bit in recovered_bits[i:i + 8]:
            byte_val = (byte_val << 1) | bit
        raw_bytes.append(byte_val)

    preamble_idx = bytes(raw_bytes).find(PREAMBLE)
    if preamble_idx == -1:
        raise ValueError("No valid transmission preamble detected in audio.")

    return bytes(raw_bytes[preamble_idx + len(PREAMBLE):])

# ----------------- GUI Code -----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Acoustic Crypto Modem")
        self.geometry("620x540")
        self.resizable(False, False)

        # Style configuration
        style = ttk.Style(self)
        style.theme_use("clam")

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)

        self.tab_encode = ttk.Frame(notebook)
        self.tab_decode = ttk.Frame(notebook)

        notebook.add(self.tab_encode, text="  Encode & Transmit  ")
        notebook.add(self.tab_decode, text="  Receive & Decode  ")

        self.setup_encode_ui()
        self.setup_decode_ui()

    def setup_encode_ui(self):
        # Plaintext input
        lbl_msg = ttk.Label(self.tab_encode, text="Secret Message:", font=("Arial", 10, "bold"))
        lbl_msg.pack(anchor="w", padx=15, pady=(15, 2))
        
        self.txt_message = tk.Text(self.tab_encode, height=6, width=65, wrap="word")
        self.txt_message.pack(padx=15, pady=5)

        # Passphrase input
        lbl_pwd = ttk.Label(self.tab_encode, text="Encryption Password / Key:", font=("Arial", 10, "bold"))
        lbl_pwd.pack(anchor="w", padx=15, pady=(10, 2))
        
        self.entry_enc_pwd = ttk.Entry(self.tab_encode, show="*", width=45)
        self.entry_enc_pwd.pack(anchor="w", padx=15, pady=5)

        # Action button
        btn_encode = ttk.Button(self.tab_encode, text="Generate .MP3 Signal", command=self.handle_encode)
        btn_encode.pack(pady=20)

        self.lbl_enc_status = ttk.Label(self.tab_encode, text="", foreground="blue")
        self.lbl_enc_status.pack()

    def setup_decode_ui(self):
        # File selector
        lbl_file = ttk.Label(self.tab_decode, text="Select Audio File (.mp3 / .wav):", font=("Arial", 10, "bold"))
        lbl_file.pack(anchor="w", padx=15, pady=(15, 2))

        file_frame = ttk.Frame(self.tab_decode)
        file_frame.pack(fill="x", padx=15, pady=5)

        self.entry_file_path = ttk.Entry(file_frame, width=48)
        self.entry_file_path.pack(side="left", fill="x", expand=True)

        btn_browse = ttk.Button(file_frame, text="Browse...", command=self.handle_browse)
        btn_browse.pack(side="left", padx=(8, 0))

        # Passphrase input
        lbl_pwd = ttk.Label(self.tab_decode, text="Decryption Password / Key:", font=("Arial", 10, "bold"))
        lbl_pwd.pack(anchor="w", padx=15, pady=(10, 2))

        self.entry_dec_pwd = ttk.Entry(self.tab_decode, show="*", width=45)
        self.entry_dec_pwd.pack(anchor="w", padx=15, pady=5)

        # Action button
        btn_decode = ttk.Button(self.tab_decode, text="Demodulate & Decrypt", command=self.handle_decode)
        btn_decode.pack(pady=15)

        # Output text
        lbl_out = ttk.Label(self.tab_decode, text="Decoded Message:", font=("Arial", 10, "bold"))
        lbl_out.pack(anchor="w", padx=15, pady=(5, 2))

        self.txt_decoded = tk.Text(self.tab_decode, height=6, width=65, wrap="word", state="disabled")
        self.txt_decoded.pack(padx=15, pady=5)

    def handle_encode(self):
        msg = self.txt_message.get("1.0", tk.END).strip()
        pwd = self.entry_enc_pwd.get().strip()

        if not msg:
            messagebox.showwarning("Warning", "Please enter a message to encode.")
            return
        if not pwd:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".mp3",
            filetypes=[("MP3 Audio Files", "*.mp3"), ("All Files", "*.*")],
            title="Save Modulated MP3"
        )
        if not save_path:
            return

        try:
            self.lbl_enc_status.config(text="Modulating to audio... please wait.")
            self.update_idletasks()
            
            payload = encrypt_payload(msg, pwd)
            modulate_to_mp3(payload, save_path)
            
            self.lbl_enc_status.config(text="")
            messagebox.showinfo("Success", f"Signal generated successfully:\n{save_path}")
        except Exception as e:
            self.lbl_enc_status.config(text="")
            messagebox.showerror("Error", f"Failed to encode: {e}")

    def handle_browse(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Audio Files", "*.mp3 *.wav"), ("All Files", "*.*")],
            title="Select Signal File"
        )
        if file_path:
            self.entry_file_path.delete(0, tk.END)
            self.entry_file_path.insert(0, file_path)

    def handle_decode(self):
        audio_path = self.entry_file_path.get().strip()
        pwd = self.entry_dec_pwd.get().strip()

        if not audio_path or not os.path.exists(audio_path):
            messagebox.showwarning("Warning", "Please select a valid audio file.")
            return
        if not pwd:
            messagebox.showwarning("Warning", "Please provide the decryption password.")
            return

        try:
            raw_payload = demodulate_from_audio(audio_path)
            plaintext = decrypt_payload(raw_payload, pwd)

            self.txt_decoded.config(state="normal")
            self.txt_decoded.delete("1.0", tk.END)
            self.txt_decoded.insert(tk.END, plaintext)
            self.txt_decoded.config(state="disabled")

            messagebox.showinfo("Success", "Audio demodulated and payload decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Demodulation/Decryption failed:\n{e}\n\n(Verify that the password is correct and file is untampered)")

if __name__ == "__main__":
    app = App()
    app.mainloop()