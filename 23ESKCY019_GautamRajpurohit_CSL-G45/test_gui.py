"""
test_gui.py - drives the REAL Tkinter application end-to-end and, optionally,
captures genuine screenshots of it.

    python test_gui.py                  # functional GUI tests only
    python test_gui.py --shots figs     # also save screenshots into ./figs

On a machine without a display use:  xvfb-run -a python test_gui.py
"""

import base64
import json
import os
import sys
import tempfile
import time
import tkinter as tk
from tkinter import ttk

import gui_app
from gui_app import PasswordManagerApp

MASTER = "Correct-Horse#Battery-2026"
LOG = []
SHOTS = None
CALLS = []                                   # recorded message boxes


# ---- message boxes would block a script: record them instead -------------
def _fake(kind):
    def f(title, message="", **kw):
        CALLS.append((kind, title, message))
        return True
    return f


for name in ("showinfo", "showwarning", "showerror", "askyesno"):
    setattr(gui_app.messagebox, name, _fake(name))


def pump(seconds):
    end = time.time() + seconds
    while time.time() < end:
        ROOT.update()
        time.sleep(0.05)


def walk(w):
    for c in w.winfo_children():
        yield c
        yield from walk(c)


def find(parent, cls, text=None):
    out = [w for w in walk(parent) if isinstance(w, cls)]
    if text is not None:
        out = [w for w in out if str(w.cget("text")) == text]
    return out


def shot(name, widget=None):
    if not SHOTS:
        return
    from PIL import ImageGrab
    ROOT.update_idletasks(); ROOT.update(); time.sleep(0.25); ROOT.update()
    w = widget or ROOT
    x, y, wd, ht = w.winfo_rootx(), w.winfo_rooty(), w.winfo_width(), w.winfo_height()
    ImageGrab.grab(bbox=(x, y, x + wd, y + ht)).save(os.path.join(SHOTS, name))


def check(tc, title, fn):
    try:
        detail = fn()
        status = "PASS"
    except Exception as exc:                                  # noqa: BLE001
        status, detail = "FAIL", f"{type(exc).__name__}: {exc}"
    LOG.append((tc, title, status, detail))
    print(f"[{tc}] {title:<48} {status}\n        -> {detail}")


def new_app(path, lock_s=60, clip_s=15, tick=200):
    global ROOT
    ROOT = tk.Tk()
    ROOT.geometry("+0+0")
    app = PasswordManagerApp(ROOT, vault_path=path, auto_lock_seconds=lock_s,
                             clipboard_seconds=clip_s, tick_ms=tick)
    pump(0.4)
    return app


def type_into(entries, *texts):
    for e, t in zip(entries, texts):
        e.delete(0, tk.END)
        e.insert(0, t)
        ROOT.update()


def unlock_via_ui(app, password=MASTER):
    if app.vault.is_unlocked:
        app.lock("test helper"); pump(0.3)
    type_into(find(app.container, ttk.Entry), password)
    find(app.container, ttk.Button, "Unlock")[0].invoke()
    pump(0.3)


# =========================================================================
def phase_screenshots(tmp):
    path = os.path.join(tmp, "demo_vault.json")
    app = new_app(path)
    entries = find(app.container, ttk.Entry)
    type_into(entries, MASTER, MASTER)
    app.container.event_generate("<KeyRelease>")
    entries[0].event_generate("<KeyRelease>", keysym="x")
    pump(0.2)
    shot("fig_5_2_gui_create.png")
    find(app.container, ttk.Button, "Create vault")[0].invoke()
    pump(0.4)

    # add the first entry THROUGH the dialog, including the generator
    app.open_entry_dialog()
    dlg = app.dialog
    ent = find(dlg, ttk.Entry)
    type_into(ent[:2] + ent[3:], "erp.skit.ac.in", "23ESKCY019", "SKIT ERP (demo)")
    find(dlg, ttk.Button, "Generate")[0].invoke()
    pump(0.3)
    shot("fig_5_3_gui_generator.png", dlg)
    find(dlg, ttk.Button, "Encrypt & save")[0].invoke()
    pump(0.3)

    for site, user, pw, note in (("github.com", "gautam-demo", "Gh#demo-Pass-7731", "Git remote"),
                                 ("aws.amazon.com", "cloud-lab", "Aws#demo-Pass-5520", "Sandbox"),
                                 ("moodle.skit.ac.in", "23ESKCY019", "Md#demo-Pass-1184", "LMS")):
        app.vault.add_entry(site, user, pw, note)
    app.reload()
    app.tree.selection_set(app.tree.get_children()[0])
    pump(0.3)
    app.copy_selected()
    pump(1.3)
    shot("fig_5_4_gui_dashboard.png")
    app.lock("Locked manually.")
    pump(0.3)
    shot("fig_5_5_gui_locked.png")
    app.vault.lock()
    with open(path) as fh:
        disk = fh.read()
    with open(os.path.join(SHOTS, "vault_on_disk.txt"), "w") as fh:
        fh.write(disk)
    ROOT.destroy()
    return path


def phase_tests(tmp):
    path = os.path.join(tmp, "gui_test_vault.json")
    app = new_app(path, lock_s=5, clip_s=3)

    def t1():
        type_into(find(app.container, ttk.Entry), MASTER, MASTER)
        find(app.container, ttk.Button, "Create vault")[0].invoke(); pump(0.3)
        assert app.vault.is_unlocked and os.path.exists(path)
        app.vault.add_entry("erp.skit.ac.in", "23ESKCY019", "Demo#Pass-4471", "")
        app.reload()
        return "vault created through the real UI; entry appears in the table"
    check("GUI-01", "Create vault via UI", t1)

    def t2():
        app.lock("test"); pump(0.3)
        CALLS.clear()
        unlock_via_ui(app, "Totally-Wrong-Password")
        assert not app.vault.is_unlocked and any(c[0] == "showerror" for c in CALLS)
        return "wrong master password -> error dialog, vault stays locked"
    check("GUI-02", "Wrong password rejected in UI", t2)

    def t3():
        for _ in range(3):
            unlock_via_ui(app, "bad-guess-bad-guess")
        CALLS.clear()
        unlock_via_ui(app, MASTER)                          # correct, but inside throttle window
        assert not app.vault.is_unlocked and any("wait" in c[2].lower() or "Try again" in c[2] for c in CALLS)
        app.limiter.reset()
        return "after repeated failures even the correct password is refused until the wait expires"
    check("GUI-03", "Brute-force throttle in UI", t3)

    def t4():
        unlock_via_ui(app)
        assert app.vault.is_unlocked
        t0 = time.time()
        pump(2.5)
        ROOT.event_generate("<ButtonPress-1>", x=5, y=5)       # user activity at t=2.5 s
        pump(3.0)                                              # 5.5 s since start > 5 s timeout
        still = app.vault.is_unlocked
        pump(3.0)                                              # now ~5.5 s since the click
        assert still, "locked although user was active"
        assert not app.vault.is_unlocked, "did not auto-lock after inactivity"
        assert not app.records, "decrypted records left in memory after lock"
        return "activity at 2.5 s postponed the lock; 5 s of silence then locked the UI and dropped records"
    check("GUI-04", "Auto-lock on inactivity (5 s test timeout)", t4)

    def t5():
        unlock_via_ui(app)
        app.tree.selection_set(app.tree.get_children()[0])
        app.copy_selected(); pump(0.3)
        assert ROOT.clipboard_get() == "Demo#Pass-4471"
        pump(3.5)
        try:
            now = ROOT.clipboard_get()
        except tk.TclError:
            now = ""
        assert now == "", f"clipboard still holds {now!r}"
        return "password was on the real Tk clipboard, then wiped 3 s later (test timeout)"
    check("GUI-05", "Clipboard auto-clear (3 s test timeout)", t5)

    def t6():
        unlock_via_ui(app)
        app.tree.selection_set(app.tree.get_children()[0])
        app.copy_selected(); pump(0.3)
        assert ROOT.clipboard_get() == "Demo#Pass-4471"
        app.lock("manual"); pump(0.3)
        try:
            now = ROOT.clipboard_get()
        except tk.TclError:
            now = ""
        assert now == "" and not app.vault.is_unlocked
        return "pressing Lock wipes a pending clipboard secret immediately"
    check("GUI-06", "Lock flushes clipboard", t6)

    def t7():
        app.lock("test helper"); pump(0.3)
        doc = json.load(open(path))
        ct = bytearray(base64.b64decode(doc["entries"][0]["ciphertext"]))
        ct[2] ^= 0x80
        doc["entries"][0]["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        json.dump(doc, open(path, "w"))
        CALLS.clear()
        app.limiter.reset()
        unlock_via_ui(app)
        assert any("Integrity" in c[1] for c in CALLS), CALLS
        assert not app.vault.is_unlocked
        return "tampered file -> 'Integrity alert' shown and the app locks itself"
    check("GUI-07", "Tampered vault file detected in UI", t7)
    ROOT.destroy()


def main():
    global SHOTS
    if "--shots" in sys.argv:
        SHOTS = sys.argv[sys.argv.index("--shots") + 1]
        os.makedirs(SHOTS, exist_ok=True)
    print("=" * 78)
    print(" GUI END-TO-END TESTS (real Tkinter window, Xvfb display)")
    print("=" * 78)
    with tempfile.TemporaryDirectory() as tmp:
        if SHOTS:
            phase_screenshots(tmp)
        phase_tests(tmp)
    ok = sum(1 for r in LOG if r[2] == "PASS")
    print("=" * 78)
    print(f" {ok}/{len(LOG)} GUI TESTS PASSED")
    print("=" * 78)
    sys.exit(0 if ok == len(LOG) else 1)


if __name__ == "__main__":
    main()
