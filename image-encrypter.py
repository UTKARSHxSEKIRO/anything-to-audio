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

# sound settings
SAMPLE_RATE = 44100
MAIN_TONE = 1764
SPEED = 2205
SAMPLES_PER_PULSE = SAMPLE_RATE // SPEED

# sound steps
GRID = np.array([-3.0, -1.0, 1.0, 3.0]) / np.sqrt(10.0)
SOUND_MAP = np.array([
    complex(GRID[i], GRID[q]) for i in range(4) for q in range(4)
])

# starter tune
HEADER_PULSES = np.array([
    1+1j, -1-1j, 1-1j, -1+1j, 1+1j, 1+1j, -1-1j, 1-1j,
    -1-1j, 1+1j, -1+1j, -1-1j, 1+1j, -1-1j, 1-1j, 1+1j,
    1+1j, -1-1j, 1-1j, -1+1j, 1+1j, 1+1j, -1-1j, 1-1j,
    -1-1j, 1+1j, -1+1j, -1-1j, 1+1j, -1-1j, 1-1j, 1+1j
], dtype=np.complex64)

def shrink_picture(path: str, max_kb: float = 8.5) -> bytes:
    limit = int(max_kb * 1024)
    pic = Image.open(path).convert("RGB")

    for size in (320, 256, 200, 160):
        pic_smaller = pic.resize((size, size), Image.Resampling.LANCZOS)
        for q in range(75, 20, -10):
            buf = io.BytesIO()
            pic_smaller.save(buf, format="WEBP", quality=q, method=6)
            data = buf.getvalue()
            if len(data) <= limit:
                return data

    buf = io.BytesIO()
    pic.resize((160, 160)).save(buf, format="WEBP", quality=25)
    return buf.getvalue()

def make_key(secret_word: str, salt: bytes) -> bytes:
    hasher = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return hasher.derive(secret_word.encode("utf-8"))

def lock_picture(pic_bytes: bytes, secret_word: str) -> bytes:
    salt = os.urandom(16)
    key = make_key(secret_word, salt)
    lock = AESGCM(key)
    tag = os.urandom(12)
    locked_data = lock.encrypt(tag, pic_bytes, None)
    return struct.pack("!I", len(locked_data)) + salt + tag + locked_data

def unlock_picture(raw_data: bytes, secret_word: str) -> bytes:
    total_len = struct.unpack("!I", raw_data[:4])[0]
    salt = raw_data[4:20]
    tag = raw_data[20:32]
    locked_data = raw_data[32:32 + total_len]
    key = make_key(secret_word, salt)
    lock = AESGCM(key)
    return lock.decrypt(tag, locked_data, None)

def data_to_sound(data: bytes, output_file: str):
    pulses = []
    for b in data:
        pulses.append(SOUND_MAP[(b >> 4) & 0x0F])
        pulses.append(SOUND_MAP[b & 0x0F])

    full_chain = np.concatenate([HEADER_PULSES, np.array(pulses, dtype=np.complex64)])
    stretched = np.repeat(full_chain, SAMPLES_PER_PULSE)
    time_steps = np.arange(len(stretched)) / SAMPLE_RATE
    carrier = np.exp(1j * 2 * np.pi * MAIN_TONE * time_steps)
    wave = np.real(stretched * carrier)

    # smooth rough edges so it doesn't hurt ears
    fade_shape = np.hanning(SAMPLES_PER_PULSE)
    for i in range(len(wave) // SAMPLES_PER_PULSE):
        start = i * SAMPLES_PER_PULSE
        end = start + SAMPLES_PER_PULSE
        wave[start:end] *= (0.35 + 0.65 * fade_shape)

    peak = np.max(np.abs(wave))
    if peak > 0:
        wave = (wave / peak) * 16000

    temp_file = "temp_sound.wav"
    wavfile.write(temp_file, SAMPLE_RATE, wave.astype(np.int16))

    audio = AudioSegment.from_wav(temp_file)
    audio.export(output_file, format="mp3", bitrate="320k")
    if os.path.exists(temp_file):
        os.remove(temp_file)

def sound_to_data(audio_file: str) -> bytes:
    audio = AudioSegment.from_file(audio_file)
    if audio.frame_rate != SAMPLE_RATE:
        audio = audio.set_frame_rate(SAMPLE_RATE)
    all_numbers = np.array(audio.get_array_of_samples(), dtype=np.float32)

    time_steps = np.arange(len(all_numbers)) / SAMPLE_RATE
    carrier = np.exp(-1j * 2 * np.pi * MAIN_TONE * time_steps)
    base_wave = all_numbers * carrier

    total_pulses = len(base_wave) // SAMPLES_PER_PULSE
    found_pulses = np.zeros(total_pulses, dtype=np.complex64)

    for i in range(total_pulses):
        part = base_wave[i * SAMPLES_PER_PULSE : (i + 1) * SAMPLES_PER_PULSE]
        found_pulses[i] = np.mean(part)

    best_match = np.abs(np.correlate(found_pulses, HEADER_PULSES, mode="valid"))
    start_point = int(np.argmax(best_match)) + len(HEADER_PULSES)
    data_pulses = found_pulses[start_point:]

    half_bytes = []
    for p in data_pulses:
        dist = np.abs(SOUND_MAP - p)
        half_bytes.append(int(np.argmin(dist)))

    real_bytes = bytearray()
    for i in range(0, len(half_bytes) - 1, 2):
        b = (half_bytes[i] << 4) | half_bytes[i + 1]
        real_bytes.append(b)

    return bytes(real_bytes)

class SimpleImageAudioApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Picture to Sound Tool")
        self.geometry("700x640")
        self.resizable(False, False)

        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=12, pady=12)

        self.tab_hide = ttk.Frame(tabs)
        self.tab_read = ttk.Frame(tabs)

        tabs.add(self.tab_hide, text=" Turn Picture to Sound ")
        tabs.add(self.tab_read, text=" Read Sound Back to Picture ")

        self.chosen_picture = None
        self.pic_view_hide = None
        self.pic_view_read = None

        self.build_hide_screen()
        self.build_read_screen()

    def build_hide_screen(self):
        top_row = ttk.Frame(self.tab_hide)
        top_row.pack(fill="x", padx=15, pady=(15, 5))

        self.lbl_chosen_pic = ttk.Label(top_row, text="No picture chosen yet", width=50)
        self.lbl_chosen_pic.pack(side="left", fill="x", expand=True)

        ttk.Button(top_row, text="Pick Picture", command=self.pick_picture).pack(side="right")

        self.preview_hide = tk.Canvas(self.tab_hide, width=220, height=220, bg="#2b2b2b", relief="sunken")
        self.preview_hide.pack(pady=10)

        ttk.Label(self.tab_hide, text="Password:").pack(anchor="w", padx=15, pady=(5, 2))
        self.pass_hide_box = ttk.Entry(self.tab_hide, show="*", width=35)
        self.pass_hide_box.pack(anchor="w", padx=15, pady=2)

        self.btn_save_sound = ttk.Button(self.tab_hide, text="Turn Into Sound File", command=self.start_hide_thread)
        self.btn_save_sound.pack(pady=15)

        self.status_hide = ttk.Label(self.tab_hide, text="")
        self.status_hide.pack()

    def build_read_screen(self):
        top_row = ttk.Frame(self.tab_read)
        top_row.pack(fill="x", padx=15, pady=(15, 5))

        self.audio_input_box = ttk.Entry(top_row, width=50)
        self.audio_input_box.pack(side="left", fill="x", expand=True)

        ttk.Button(top_row, text="Pick Sound File", command=self.pick_sound).pack(side="right", padx=(5, 0))

        ttk.Label(self.tab_read, text="Password:").pack(anchor="w", padx=15, pady=(10, 2))
        self.pass_read_box = ttk.Entry(self.tab_read, show="*", width=35)
        self.pass_read_box.pack(anchor="w", padx=15, pady=2)

        self.btn_open_sound = ttk.Button(self.tab_read, text="Get Picture Back", command=self.start_read_thread)
        self.btn_open_sound.pack(pady=15)

        self.status_read = ttk.Label(self.tab_read, text="")
        self.status_read.pack()

        ttk.Label(self.tab_read, text="Recovered Picture:").pack(anchor="w", padx=15, pady=(5, 2))
        self.preview_read = tk.Canvas(self.tab_read, width=220, height=220, bg="#2b2b2b", relief="sunken")
        self.preview_read.pack(pady=5)

    def pick_picture(self):
        path = filedialog.askopenfilename(
            filetypes=[("Pictures", "*.png *.jpg *.jpeg *.webp *.bmp"), ("All", "*.*")]
        )
        if path:
            self.chosen_picture = path
            self.lbl_chosen_pic.config(text=os.path.basename(path))

            pic = Image.open(path)
            pic.thumbnail((220, 220))
            self.pic_view_hide = ImageTk.PhotoImage(pic)
            self.preview_hide.create_image(110, 110, image=self.pic_view_hide)

    def pick_sound(self):
        path = filedialog.askopenfilename(
            filetypes=[("Sound files", "*.mp3 *.wav"), ("All", "*.*")]
        )
        if path:
            self.audio_input_box.delete(0, tk.END)
            self.audio_input_box.insert(0, path)

    def start_hide_thread(self):
        threading.Thread(target=self.run_hide, daemon=True).start()

    def run_hide(self):
        if not self.chosen_picture:
            messagebox.showwarning("Missing", "Choose a picture first.")
            return
        pwd = self.pass_hide_box.get().strip()
        if not pwd:
            messagebox.showwarning("Missing", "Set a password first.")
            return

        where = filedialog.asksaveasfilename(
            defaultextension=".mp3",
            filetypes=[("Sound file", "*.mp3")],
            title="Save sound"
        )
        if not where:
            return

        try:
            self.btn_save_sound.config(state="disabled")
            self.status_hide.config(text="Shrinking picture...")

            small_pic = shrink_picture(self.chosen_picture, max_kb=8.5)
            self.status_hide.config(text="Locking...")

            locked = lock_picture(small_pic, pwd)
            self.status_hide.config(text="Making sound...")

            data_to_sound(locked, where)
            self.status_hide.config(text="Done.")
            messagebox.showinfo("Done", f"Sound saved to:\n{where}")
        except Exception as err:
            messagebox.showerror("Error", f"Failed: {err}")
            self.status_hide.config(text="")
        finally:
            self.btn_save_sound.config(state="normal")

    def start_read_thread(self):
        threading.Thread(target=self.run_read, daemon=True).start()

    def run_read(self):
        audio_path = self.audio_input_box.get().strip()
        pwd = self.pass_read_box.get().strip()

        if not audio_path or not os.path.exists(audio_path):
            messagebox.showwarning("Missing", "Select an actual sound file.")
            return
        if not pwd:
            messagebox.showwarning("Missing", "Type the password.")
            return

        try:
            self.btn_open_sound.config(state="disabled")
            self.status_read.config(text="Listening to sound...")

            raw_bytes = sound_to_data(audio_path)
            self.status_read.config(text="Unlocking...")

            pic_bytes = unlock_picture(raw_bytes, pwd)

            pic = Image.open(io.BytesIO(pic_bytes))
            pic_copy = pic.copy()
            pic_copy.thumbnail((220, 220))
            self.pic_view_read = ImageTk.PhotoImage(pic_copy)
            self.preview_read.create_image(110, 110, image=self.pic_view_read)

            save_where = filedialog.asksaveasfilename(
                defaultextension=".webp",
                filetypes=[("WebP", "*.webp"), ("PNG", "*.png")],
                title="Save picture"
            )
            if save_where:
                pic.save(save_where)

            self.status_read.config(text="Picture restored.")
            messagebox.showinfo("Done", "Got the picture back.")
        except Exception as err:
            messagebox.showerror("Error", f"Couldn't read it: {err}\n\n(Check password or if file got damaged)")
            self.status_read.config(text="")
        finally:
            self.btn_open_sound.config(state="normal")

if __name__ == "__main__":
    app = SimpleImageAudioApp()
    app.mainloop()