import os
import struct
import numpy as np
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scipy.io import wavfile
from scipy.signal import chirp, correlate
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from pydub import AudioSegment

SAMPLE_RATE = 44100
BAUD_RATE = 100  # 100 bits per second
SAMPLES_PER_BIT = int(SAMPLE_RATE / BAUD_RATE)

HIGH_TONE = 2400  # Bit 1
LOW_TONE = 1200   # Bit 0

# Preamble: 0.25-second linear chirp to locate exact bit alignment
CHIRP_DURATION = 0.25
CHIRP_SAMPLES = int(SAMPLE_RATE * CHIRP_DURATION)
CHIRP_REF = chirp(
    np.linspace(0, CHIRP_DURATION, CHIRP_SAMPLES, endpoint=False),
    f0=500,
    t1=CHIRP_DURATION,
    f1=3500,
    method="linear",
).astype(np.float32)

START_MARKER = b"\xAA\x55\xAA\x55"

def make_key(secret_word: str, salt: bytes) -> bytes:
    hasher = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return hasher.derive(secret_word.encode("utf-8"))

def lock_text(plain_words: str, secret_word: str) -> bytes:
    salt = os.urandom(16)
    key = make_key(secret_word, salt)
    lock = AESGCM(key)
    nonce = os.urandom(12)
    locked_data = lock.encrypt(nonce, plain_words.encode("utf-8"), None)
    
    payload = START_MARKER + struct.pack("!I", len(locked_data)) + salt + nonce + locked_data
    return payload

def unlock_text(raw_data: bytes, secret_word: str) -> str:
    marker_pos = raw_data.find(START_MARKER)
    if marker_pos == -1:
        raise ValueError("Could not locate sync header.")
    
    stream = raw_data[marker_pos + len(START_MARKER):]
    if len(stream) < 4 + 16 + 12:
        raise ValueError("Audio payload corrupted or incomplete.")
        
    (total_len,) = struct.unpack("!I", stream[:4])
    salt = stream[4:20]
    nonce = stream[20:32]
    locked_data = stream[32:32 + total_len]

    if len(locked_data) != total_len:
        raise ValueError("Truncated payload data.")

    key = make_key(secret_word, salt)
    lock = AESGCM(key)
    plain_bytes = lock.decrypt(nonce, locked_data, None)
    return plain_bytes.decode("utf-8")

def turn_data_to_audio(data: bytes, file_name: str):
    bits = []
    for single_byte in data:
        for i in range(7, -1, -1):
            bits.append((single_byte >> i) & 1)

    t = np.arange(SAMPLES_PER_BIT) / SAMPLE_RATE
    one_sound = np.sin(2 * np.pi * HIGH_TONE * t).astype(np.float32)
    zero_sound = np.sin(2 * np.pi * LOW_TONE * t).astype(np.float32)

    # Lead-in: 0.1s silence + Chirp Sync Pulse + 0.05s guard tone
    lead_silence = np.zeros(int(SAMPLE_RATE * 0.1), dtype=np.float32)
    guard = np.sin(2 * np.pi * LOW_TONE * np.arange(int(SAMPLE_RATE * 0.05)) / SAMPLE_RATE).astype(np.float32)

    bit_audio = [one_sound if b == 1 else zero_sound for b in bits]
    full_audio = np.concatenate([lead_silence, CHIRP_REF, guard] + bit_audio)

    # Normalize to prevent clipping
    full_audio = (full_audio / np.max(np.abs(full_audio)) * 32767).astype(np.int16)
    wavfile.write(file_name, SAMPLE_RATE, full_audio)

def turn_audio_to_data(file_name: str) -> bytes:
    sound = AudioSegment.from_file(file_name).set_channels(1).set_frame_rate(SAMPLE_RATE)
    samples = np.array(sound.get_array_of_samples(), dtype=np.float32)

    if len(samples) < CHIRP_SAMPLES:
        raise ValueError("Audio file is too short.")

    # Cross-correlate against the reference chirp to find exact bit transmission start
    corr = correlate(samples, CHIRP_REF, mode="valid")
    sync_peak_idx = int(np.argmax(corr))

    # Data begins directly after the chirp + guard space
    guard_samples = int(SAMPLE_RATE * 0.05)
    data_start = sync_peak_idx + CHIRP_SAMPLES + guard_samples

    t_bit = np.arange(SAMPLES_PER_BIT) / SAMPLE_RATE
    one_ref = np.exp(-2j * np.pi * HIGH_TONE * t_bit)
    zero_ref = np.exp(-2j * np.pi * LOW_TONE * t_bit)

    total_bits = (len(samples) - data_start) // SAMPLES_PER_BIT
    if total_bits <= 0:
        raise ValueError("No demodulatable payload found after synchronization marker.")

    read_bits = []
    for i in range(total_bits):
        start = data_start + (i * SAMPLES_PER_BIT)
        chunk = samples[start : start + SAMPLES_PER_BIT]
        one_mag = np.abs(np.dot(chunk, one_ref))
        zero_mag = np.abs(np.dot(chunk, zero_ref))
        read_bits.append(1 if one_mag > zero_mag else 0)

    # Convert bitstream back to bytes
    byte_chunks = bytearray()
    for i in range(0, len(read_bits) - 7, 8):
        byte_val = 0
        for bit in read_bits[i : i + 8]:
            byte_val = (byte_val << 1) | bit
        byte_chunks.append(byte_val)

    return bytes(byte_chunks)

class SimpleTextAudioApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Audio Steganography Tool")
        self.geometry("620x540")
        self.resizable(False, False)

        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=12, pady=12)

        self.tab_hide = ttk.Frame(tabs)
        self.tab_read = ttk.Frame(tabs)

        tabs.add(self.tab_hide, text=" Turn Text to Sound ")
        tabs.add(self.tab_read, text=" Read Sound Back to Text ")

        self.build_hide_screen()
        self.build_read_screen()

    def build_hide_screen(self):
        ttk.Label(self.tab_hide, text="Write your message:").pack(anchor="w", padx=15, pady=(15, 2))
        self.box_input = tk.Text(self.tab_hide, height=6, width=65, wrap="word")
        self.box_input.pack(padx=15, pady=5)

        ttk.Label(self.tab_hide, text="Password:").pack(anchor="w", padx=15, pady=(10, 2))
        self.pass_box = ttk.Entry(self.tab_hide, show="*", width=45)
        self.pass_box.pack(anchor="w", padx=15, pady=5)

        ttk.Button(self.tab_hide, text="Save as WAV", command=self.save_sound).pack(pady=20)
        self.status_hide = ttk.Label(self.tab_hide, text="")
        self.status_hide.pack()

    def build_read_screen(self):
        ttk.Label(self.tab_read, text="Pick the sound file (.wav):").pack(anchor="w", padx=15, pady=(15, 2))
        row = ttk.Frame(self.tab_read)
        row.pack(fill="x", padx=15, pady=5)

        self.file_box = ttk.Entry(row, width=48)
        self.file_box.pack(side="left", fill="x", expand=True)

        ttk.Button(row, text="Browse", command=self.pick_sound).pack(side="left", padx=(8, 0))

        ttk.Label(self.tab_read, text="Password:").pack(anchor="w", padx=15, pady=(10, 2))
        self.pass_read_box = ttk.Entry(self.tab_read, show="*", width=45)
        self.pass_read_box.pack(anchor="w", padx=15, pady=5)

        ttk.Button(self.tab_read, text="Open Message", command=self.open_message).pack(pady=15)

        ttk.Label(self.tab_read, text="Decoded Message:").pack(anchor="w", padx=15, pady=(5, 2))
        self.box_output = tk.Text(self.tab_read, height=6, width=65, wrap="word", state="disabled")
        self.box_output.pack(padx=15, pady=5)

    def save_sound(self):
        text = self.box_input.get("1.0", tk.END).strip()
        pwd = self.pass_box.get().strip()

        if not text or not pwd:
            messagebox.showwarning("Missing Data", "Please provide both text and a password.")
            return

        where = filedialog.asksaveasfilename(
            defaultextension=".wav",
            filetypes=[("WAV Audio", "*.wav")],
            title="Save Audio Output"
        )
        if not where:
            return

        try:
            self.status_hide.config(text="Generating sound...")
            self.update_idletasks()
            packed = lock_text(text, pwd)
            turn_data_to_audio(packed, where)
            self.status_hide.config(text="")
            messagebox.showinfo("Success", f"Audio written to:\n{where}")
        except Exception as err:
            self.status_hide.config(text="")
            messagebox.showerror("Error", f"Failed: {err}")

    def pick_sound(self):
        path = filedialog.askopenfilename(
            filetypes=[("WAV Audio", "*.wav"), ("All audio", "*.*")],
            title="Select Encoded File"
        )
        if path:
            self.file_box.delete(0, tk.END)
            self.file_box.insert(0, path)

    def open_message(self):
        path = self.file_box.get().strip()
        pwd = self.pass_read_box.get().strip()

        if not path or not os.path.exists(path) or not pwd:
            messagebox.showwarning("Missing Data", "Select a valid file and enter password.")
            return

        try:
            raw_bytes = turn_audio_to_data(path)
            message = unlock_text(raw_bytes, pwd)

            self.box_output.config(state="normal")
            self.box_output.delete("1.0", tk.END)
            self.box_output.insert(tk.END, message)
            self.box_output.config(state="disabled")
            messagebox.showinfo("Success", "Decrypted successfully.")
        except Exception as err:
            messagebox.showerror("Error", f"Decoding failed: {err}\n\n(Verify password and file integrity)")

if __name__ == "__main__":
    app = SimpleTextAudioApp()
    app.mainloop()