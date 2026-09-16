# Encrypted Audio FSK Modem

A software-defined acoustic modem and encryption utility in Python. The application encrypts plaintext using AES-256-GCM, modulates the encrypted bitstream into audible sound using Frequency-Shift Keying (FSK), and demodulates the audio back into clear text via cross-correlation synchronization and discrete matched filtering.

---

## Features

- **Authenticated Cryptography:** Encrypts data using AES-256-GCM with unique nonces, guaranteeing both confidentiality and tamper-evident authentication.
- **Key Derivation (KDF):** Derives cryptographic keys from user passphrases via PBKDF2 (HMAC-SHA256, 100,000 rounds) and a 16-byte random salt.
- **Audio FSK Modulation:** Encodes bits directly as audible sine wave frequencies (similar to legacy dial-up acoustic couplers).
- **Chirp-Based Frame Synchronization:** Uses a linear frequency sweep (chirp) preamble and cross-correlation to lock onto transmission start offsets down to individual samples.
- **Simple GUI Interface:** Tkinter-based dual-panel UI for modulation and demodulation pipelines.

---

## Architecture & Signal Flow

[Plaintext]
│
▼ (PBKDF2-HMAC-SHA256 + AES-256-GCM)
[Ciphertext + Nonce + Salt]
│
▼ (Bit-Packing & Header Framing)
[Raw Bitstream]
│
▼ (Chirp Prepended + 1200/2400 Hz FSK Modulator)
[.WAV Acoustic Waveform]
│
▼ (Cross-Correlation Sample Sync)
[Matched-Filter Demodulation]
│
▼ (Packet Extraction & AES-GCM Decryption)
[Original Plaintext]

### 1. Frame Structure
Every modulated burst carries a structured binary packet:

| Field | Size | Description |
|---|---|---|
| **Sync Marker** | 4 Bytes | Magic sequence (`0xAA55AA55`) for byte-level boundary verification |
| **Length** | 4 Bytes | Big-endian unsigned int (`uint32`) specifying ciphertext byte count |
| **Salt** | 16 Bytes | Random salt for PBKDF2 key derivation |
| **Nonce** | 12 Bytes | Unique initialization vector for AES-GCM |
| **Payload** | Variable | Encrypted data followed by the 16-byte GCM authentication tag |

### 2. Physical Layer (PHY) Modulation
- **Modulation Scheme:** Binary Frequency-Shift Keying (2-FSK)
- **Mark Tone (Bit 1):** 2400 Hz
- **Space Tone (Bit 0):** 1200 Hz
- **Baud Rate:** 100 baud (100 bits per second)
- **Preamble:** 0.25-second linear chirp (500 Hz to 3500 Hz) used as a matched-filter target to reliably pinpoint the start of the data frame.

---

## Technical Specifications

| Parameter | Specification |
|---|---|
| **Audio Format** | Uncompressed PCM 16-bit WAV (Mono) |
| **Sample Rate** | 44,100 Hz |
| **Bit Duration** | 441 samples (10 ms per bit) |
| **Cipher** | AES-256-GCM |
| **KDF** | PBKDF2 (HMAC-SHA256, 100,000 iterations) |
| **Channel Synchronization** | Linear chirp pulse cross-correlation |

---

## Requirements

- Python 3.8+
- [FFmpeg](https://ffmpeg.org/) (required by `pydub` to handle audio backend formats)

### Python Dependencies

Install the necessary libraries via `pip`:

```bash
pip install numpy scipy cryptography pydub
```
Running the Application

Launch the desktop interface:
Bash

python main.py

Transmission (Text to Audio)

    Navigate to the Turn Text to Sound tab.

    Enter your message and a secure passphrase.

    Click Save as WAV to generate the modulated audio file.

Reception (Audio to Text)

    Navigate to the Read Sound Back to Text tab.

    Select your modulated .wav file.

    Supply the passphrase used during transmission.

    Click Open Message to demodulate the signal, verify packet integrity, and decrypt the text.

Acoustic Channel Limitations

    Avoid Lossy Encoders: Do not convert output files to .mp3, .aac, or .ogg. Lossy psychoacoustic codecs introduce phase jitter, block padding, and high-frequency roll-offs that destroy bit timing.

    Air-Gap Transmission: While designed for file-based transfer, acoustic over-the-air playback requires room calibration, echo minimization, and forward error correction (FEC) like Reed-Solomon to survive ambient noise and multipath interference.

License

Distributed under the MIT License.



