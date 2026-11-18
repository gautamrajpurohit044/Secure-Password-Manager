# Secure Password Manager  (CSL-G45)
Cyber Security Lab 7CS4-22 / 7CIT4-22, SKIT Jaipur. Gautam Rajpurohit, Roll No. 23ESKCY019.

Master-password protected store, AES-256-GCM encrypted entries, CSPRNG password generator,
auto-lock (60 s idle) and clipboard clear (15 s).

## Run
    pip install cryptography
    python gui_app.py              # first run creates secure_vault.json

## Test
    python test_security.py        # 12 headless security tests
    xvfb-run -a python test_gui.py # 7 end-to-end tests of the real window (Linux; needs Xvfb)
    python benchmark.py            # PBKDF2 / AES-GCM timing on your machine

## Files
    vault_core.py     engine: PBKDF2 + AES-256-GCM vault, generator, auto-lock/clipboard/attempt logic
    gui_app.py        Tkinter interface
    sample_vault.json demo vault with DUMMY data; master password: Correct-Horse#Battery-2026
    screenshots/      real screenshots captured from the running app

Do not use sample_vault.json for real passwords.
