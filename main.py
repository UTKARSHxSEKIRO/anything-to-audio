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

# basic sound setup
SAMPLE_RATE = 44100
SPEED = 100
SAMPLES_PER_BIT = int(SAMPLE_RATE / SPEED)

HIGH_TONE = 2400
LOW_TONE = 1200
START_CODE = b"\xAA\xAA\xAA\xAA"

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
    tag = os.urandom(12)
    locked_data = lock.encrypt(tag, plain_words.encode("utf-8"), None)
    return START_CODE + struct.pack("!H", len(locked_data)) + salt + tag + locked_data

def unlock_text(raw_data: bytes, secret_word: str) -> str:
    total_len = struct.unpack("!H", raw_data[:2])[0]
    salt = raw_data[2:18]
    tag = raw_data[18:30]
    locked_data = raw_data[30:30 + total_len]

    key = make_key(secret_word, salt)
    lock = AESGCM(key)
    plain_bytes = lock.decrypt(tag, locked_data, None)
    return plain_bytes.decode("utf-8")

def turn_data_to_audio(data: bytes, file_name: str):
    bits = []
    for single_byte in data:
        for i in range(7, -1, -1):
            bits.append((single_byte >> i) & 1)

    time_steps = np.arange(SAMPLES_PER_BIT) / SAMPLE_RATE
    one_sound = np.sin(2 * np.pi * HIGH_TONE * time_steps)
    zero_sound = np.sin(2 * np.pi * LOW_TONE * time_steps)

    all_sounds = []
    for b in bits:
        all_sounds.extend(one_sound if b == 1 else zero_sound)

    sound_list = np.array(all_sounds, dtype=np.float32)
    temp_file = "temp_render.wav"
    wavfile.write(temp_file, SAMPLE_RATE, (sound_list * 32767).astype(np.int16))

    loaded_sound = AudioSegment.from_wav(temp_file)
    loaded_sound.export(file_name, format="mp3", bitrate="192k")

    if os.path.exists(temp_file):
        os.remove(temp_file)

def turn_audio_to_data(file_name: str) -> bytes:
    loaded_sound = AudioSegment.from_file(file_name)
    all_numbers = np.array(loaded_sound.get_array_of_samples(), dtype=np.float32)

    total_bits = len(all_numbers) // SAMPLES_PER_BIT
    read_bits = []

    time_steps = np.arange(SAMPLES_PER_BIT) / SAMPLE_RATE
    one_check = np.exp(-2j * np.pi * HIGH_TONE * time_steps)
    zero_check = np.exp(-2j * np.pi * LOW_TONE * time_steps)

    for i in range(total_bits):
        part = all_numbers[i * SAMPLES_PER_BIT : (i + 1) * SAMPLES_PER_BIT]
        one_energy = np.abs(np.dot(part, one_check))
        zero_energy = np.abs(np.dot(part, zero_check))
        read_bits.append(1 if one_energy > zero_energy else 0)

    found_bytes = bytearray()
    for i in range(0, len(read_bits) - 7, 8):
        byte_num = 0
        for b in read_bits[i:i + 8]:
            byte_num = (byte_num << 1) | b
        found_bytes.append(byte_num)

    start_spot = bytes(found_bytes).find(START_CODE)
    if start_spot == -1:
        raise ValueError("Couldn't find the starting beep pattern.")

    return bytes(found_bytes[start_spot + len(START_CODE):])

class SimpleTextAudioApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Text to Sound Tool")
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

        ttk.Button(self.tab_hide, text="Save as MP3", command=self.save_mp3).pack(pady=20)
        self.status_hide = ttk.Label(self.tab_hide, text="")
        self.status_hide.pack()

    def build_read_screen(self):
        ttk.Label(self.tab_read, text="Pick the sound file (.mp3 or .wav):").pack(anchor="w", padx=15, pady=(15, 2))
        row = ttk.Frame(self.tab_read)
        row.pack(fill="x", padx=15, pady=5)

        self.file_box = ttk.Entry(row, width=48)
        self.file_box.pack(side="left", fill="x", expand=True)

        ttk.Button(row, text="Browse", command=self.pick_sound).pack(side="left", padx=(8, 0))

        ttk.Label(self.tab_read, text="Password:").pack(anchor="w", padx=15, pady=(10, 2))
        self.pass_read_box = ttk.Entry(self.tab_read, show="*", width=45)
        self.pass_read_box.pack(anchor="w", padx=15, pady=5)

        ttk.Button(self.tab_read, text="Open Message", command=self.open_message).pack(pady=15)

        ttk.Label(self.tab_read, text="Your message:").pack(anchor="w", padx=15, pady=(5, 2))
        self.box_output = tk.Text(self.tab_read, height=6, width=65, wrap="word", state="disabled")
        self.box_output.pack(padx=15, pady=5)

    def save_mp3(self):
        text = self.box_input.get("1.0", tk.END).strip()
        pwd = self.pass_box.get().strip()

        if not text:
            messagebox.showwarning("Empty", "Type something first.")
            return
        if not pwd:
            messagebox.showwarning("Empty", "Type a password.")
            return

        where = filedialog.asksaveasfilename(
            defaultextension=".mp3",
            filetypes=[("Sound files", "*.mp3"), ("All", "*.*")],
            title="Where to save sound"
        )
        if not where:
            return

        try:
            self.status_hide.config(text="Writing audio...")
            self.update_idletasks()
            packed = lock_text(text, pwd)
            turn_data_to_audio(packed, where)
            self.status_hide.config(text="")
            messagebox.showinfo("Done", f"Saved to:\n{where}")
        except Exception as err:
            self.status_hide.config(text="")
            messagebox.showerror("Error", f"Failed: {err}")

    def pick_sound(self):
        path = filedialog.askopenfilename(
            filetypes=[("Audio", "*.mp3 *.wav"), ("All", "*.*")],
            title="Pick a sound file"
        )
        if path:
            self.file_box.delete(0, tk.END)
            self.file_box.insert(0, path)

    def open_message(self):
        path = self.file_box.get().strip()
        pwd = self.pass_read_box.get().strip()

        if not path or not os.path.exists(path):
            messagebox.showwarning("Missing", "Select an actual file first.")
            return
        if not pwd:
            messagebox.showwarning("Missing", "Type the password.")
            return

        try:
            raw_bytes = turn_audio_to_data(path)
            message = unlock_text(raw_bytes, pwd)

            self.box_output.config(state="normal")
            self.box_output.delete("1.0", tk.END)
            self.box_output.insert(tk.END, message)
            self.box_output.config(state="disabled")
            messagebox.showinfo("Done", "Message read successfully.")
        except Exception as err:
            messagebox.showerror("Error", f"Could not read it: {err}\n\n(Wrong password or broken sound file)")

if __name__ == "__main__":
    app = SimpleTextAudioApp()
    app.mainloop()