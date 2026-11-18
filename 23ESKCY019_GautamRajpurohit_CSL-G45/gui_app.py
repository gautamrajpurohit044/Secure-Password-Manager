"""
gui_app.py  -  Secure Password Manager (Tkinter front-end)
Cyber Security Lab (7CS4-22 / 7CIT4-22), SKIT Jaipur  |  Project CSL-G45

Run:  python gui_app.py
"""

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from vault_core import (AttemptLimiter, AutoLockTimer, ClipboardGuard, CryptoVault,
                        InvalidTag, PasswordGenerator, VaultError)

AUTO_LOCK_SECONDS = 60
CLIPBOARD_CLEAR_SECONDS = 15


class PasswordManagerApp:
    def __init__(self, root: tk.Tk, vault_path: str = "secure_vault.json",
                 auto_lock_seconds: float = AUTO_LOCK_SECONDS,
                 clipboard_seconds: float = CLIPBOARD_CLEAR_SECONDS,
                 tick_ms: int = 500, iterations: int | None = None):
        self.root = root
        self.tick_ms = tick_ms
        self.vault = CryptoVault(vault_path, iterations=iterations)
        self.lock_timer = AutoLockTimer(auto_lock_seconds)
        self.clip_guard = ClipboardGuard(clipboard_seconds)
        self.limiter = AttemptLimiter()
        self.records: dict[str, dict] = {}       # decrypted copies, only while unlocked

        root.title("Secure Password Manager  -  AES-256-GCM Vault")
        root.geometry("860x520")
        root.minsize(760, 440)
        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("DejaVu Sans", 18, "bold"))
        style.configure("Sub.TLabel", font=("DejaVu Sans", 11))
        style.configure("Treeview", rowheight=26)

        self.container = ttk.Frame(root, padding=14)
        self.container.pack(fill=tk.BOTH, expand=True)
        self.status = tk.StringVar(value="Vault locked")
        ttk.Label(root, textvariable=self.status, relief=tk.SUNKEN, anchor=tk.W,
                  padding=(8, 4)).pack(side=tk.BOTTOM, fill=tk.X)

        for ev in ("<Motion>", "<KeyPress>", "<ButtonPress>"):
            root.bind_all(ev, self._on_activity, add="+")

        self._after_id = None
        root.bind("<Destroy>", self._on_destroy, add="+")
        self.show_auth_screen()
        self._tick()

    # ------------------------------------------------------------ helpers
    def _on_activity(self, _event=None):
        if self.vault.is_unlocked:
            self.lock_timer.touch()

    def _on_destroy(self, event):
        if event.widget is self.root and self._after_id:
            self.root.after_cancel(self._after_id)
            self._after_id = None

    def _read_clip(self) -> str:
        try:
            return self.root.clipboard_get()
        except tk.TclError:
            return ""

    def _clear_clip(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append("")      # leave an empty string, not the secret

    def _clear_container(self):
        for w in self.container.winfo_children():
            w.destroy()

    def _tick(self):
        if self.clip_guard.poll(self._read_clip, self._clear_clip):
            self.status.set("Clipboard cleared automatically.")
        if self.vault.is_unlocked:
            left = self.lock_timer.remaining()
            clip = f" | Clipboard clears in {self.clip_guard.remaining()}s" if self.clip_guard.armed else ""
            self.status.set(f"UNLOCKED | AES-256-GCM | Auto-lock in {left}s{clip}")
            if left == 0:
                self.lock("Auto-locked after inactivity.")
        self._after_id = self.root.after(self.tick_ms, self._tick)

    # ------------------------------------------------------------ auth screen
    def show_auth_screen(self):
        self._clear_container()
        is_new = not self.vault.exists()
        frame = ttk.Frame(self.container, padding=24)
        frame.place(relx=0.5, rely=0.45, anchor=tk.CENTER)
        ttk.Label(frame, text="Secure Password Manager", style="Title.TLabel").pack(pady=(0, 4))
        ttk.Label(frame, style="Sub.TLabel",
                  text="Create a new vault" if is_new else "Unlock your vault").pack(pady=(0, 14))

        ttk.Label(frame, text="Master password:").pack(anchor=tk.W)
        pw = ttk.Entry(frame, show="*", width=36)
        pw.pack(pady=(2, 8))
        pw.focus_set()
        confirm = None
        hint = tk.StringVar()
        if is_new:
            ttk.Label(frame, text="Confirm master password:").pack(anchor=tk.W)
            confirm = ttk.Entry(frame, show="*", width=36)
            confirm.pack(pady=(2, 4))
            ttk.Label(frame, textvariable=hint, foreground="#555").pack(anchor=tk.W)
            pw.bind("<KeyRelease>", lambda _e: hint.set(self._master_hint(pw.get())))
            hint.set(f"Minimum {CryptoVault.MIN_MASTER_LENGTH} characters. There is no recovery if you forget it.")

        def submit(_e=None):
            master = pw.get()
            try:
                if is_new:
                    if master != confirm.get():
                        messagebox.showwarning("Mismatch", "The two passwords do not match.")
                        return
                    self.vault.create(master)
                else:
                    wait = self.limiter.wait_seconds()
                    if wait:
                        messagebox.showwarning("Please wait", f"Too many failed attempts. Try again in {wait}s.")
                        return
                    if not self.vault.unlock(master):
                        self.limiter.record_failure()
                        messagebox.showerror("Access denied", "Wrong master password.")
                        pw.delete(0, tk.END)
                        return
                    self.limiter.reset()
            except VaultError as exc:
                messagebox.showerror("Vault error", str(exc))
                return
            self.lock_timer.touch()
            self.show_vault_screen()

        pw.bind("<Return>", submit)
        if confirm is not None:
            confirm.bind("<Return>", submit)
        ttk.Button(frame, text="Create vault" if is_new else "Unlock", command=submit).pack(pady=12)

    @staticmethod
    def _master_hint(text: str) -> str:
        bits = PasswordGenerator.estimate_text_entropy(text)
        return f"{len(text)} chars, ~{bits:.0f} bits ({PasswordGenerator.strength_label(bits)})"

    # ------------------------------------------------------------ vault screen
    def show_vault_screen(self):
        self._clear_container()
        bar = ttk.Frame(self.container)
        bar.pack(fill=tk.X, pady=(0, 8))
        for text, cmd in (("+ Add", self.open_entry_dialog), ("Edit", self.edit_selected),
                          ("Copy password", self.copy_selected), ("Reveal", self.reveal_selected),
                          ("Delete", self.delete_selected), ("Change master", self.change_master)):
            ttk.Button(bar, text=text, command=cmd).pack(side=tk.LEFT, padx=3)
        ttk.Button(bar, text="Lock now", command=lambda: self.lock("Locked manually.")).pack(side=tk.RIGHT, padx=3)

        sbar = ttk.Frame(self.container)
        sbar.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(sbar, text="Search:").pack(side=tk.LEFT)
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self.refresh())
        ttk.Entry(sbar, textvariable=self.search, width=32).pack(side=tk.LEFT, padx=6)

        cols = ("site", "username", "notes", "updated")
        self.tree = ttk.Treeview(self.container, columns=cols, show="headings", selectmode="browse")
        for c, label, w in (("site", "Website / service", 220), ("username", "Username / email", 220),
                            ("notes", "Notes", 190), ("updated", "Last updated", 150)):
            self.tree.heading(c, text=label)
            self.tree.column(c, width=w, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", lambda _e: self.copy_selected())
        self.reload()

    def reload(self):
        try:
            self.records = {r["id"]: r for r in self.vault.get_entries()}
        except InvalidTag:
            messagebox.showerror("Integrity alert",
                                 "An entry failed its GCM authentication check.\n"
                                 "The vault file was modified or is corrupt.")
            self.lock("Locked: integrity check failed.")
            return
        self.refresh()

    def refresh(self):
        if not hasattr(self, "tree") or not self.tree.winfo_exists():
            return
        q = self.search.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        for r in sorted(self.records.values(), key=lambda x: x["site"].lower()):
            if q and q not in r["site"].lower() and q not in r["username"].lower():
                continue
            self.tree.insert("", tk.END, iid=r["id"],
                             values=(r["site"], r["username"], r["notes"], r["updated"]))

    def _selected(self) -> dict | None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select an entry", "Please select an entry first.")
            return None
        return self.records.get(sel[0])

    # ------------------------------------------------------------ actions
    def copy_selected(self):
        rec = self._selected()
        if not rec:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(rec["password"])
        self.clip_guard.arm(rec["password"])
        self.status.set(f"Password for {rec['site']} copied. Clears in {self.clip_guard.timeout:.0f}s.")

    def reveal_selected(self):
        rec = self._selected()
        if rec:
            messagebox.showinfo(rec["site"], f"Username: {rec['username']}\nPassword: {rec['password']}")

    def delete_selected(self):
        rec = self._selected()
        if rec and messagebox.askyesno("Delete", f"Delete the entry for '{rec['site']}'?"):
            self.vault.delete_entry(rec["id"])
            self.reload()

    def edit_selected(self):
        rec = self._selected()
        if rec:
            self.open_entry_dialog(rec)

    def change_master(self):
        old = simpledialog.askstring("Change master password", "Current master password:", show="*", parent=self.root)
        if old is None:
            return
        new = simpledialog.askstring("Change master password", "New master password:", show="*", parent=self.root)
        if new is None:
            return
        again = simpledialog.askstring("Change master password", "Repeat new master password:", show="*", parent=self.root)
        if new != again:
            messagebox.showwarning("Mismatch", "The new passwords do not match.")
            return
        try:
            self.vault.change_master_password(old, new)
            messagebox.showinfo("Done", "Master password changed. All entries were re-encrypted.")
        except VaultError as exc:
            messagebox.showerror("Not changed", str(exc))

    # ------------------------------------------------------------ add / edit dialog
    def open_entry_dialog(self, record: dict | None = None):
        dlg = tk.Toplevel(self.root)
        dlg.title("Edit entry" if record else "Add entry")
        dlg.transient(self.root)
        dlg.resizable(False, False)
        f = ttk.Frame(dlg, padding=14)
        f.pack(fill=tk.BOTH, expand=True)

        vars_ = {k: tk.StringVar(value=(record or {}).get(k, ""))
                 for k in ("site", "username", "password", "notes")}
        for row, (key, label) in enumerate((("site", "Website / service"), ("username", "Username / email"),
                                            ("password", "Password"), ("notes", "Notes"))):
            ttk.Label(f, text=label + ":").grid(row=row, column=0, sticky=tk.W, pady=4)
            ttk.Entry(f, textvariable=vars_[key], width=38,
                      show="*" if key == "password" else "").grid(row=row, column=1, pady=4, padx=(8, 0))
        pw_entry = f.grid_slaves(row=2, column=1)[0]
        show = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Show password", variable=show,
                        command=lambda: pw_entry.config(show="" if show.get() else "*")
                        ).grid(row=4, column=1, sticky=tk.W, padx=(8, 0))

        gen = ttk.LabelFrame(f, text="Password generator (CSPRNG)", padding=10)
        gen.grid(row=5, column=0, columnspan=2, sticky=tk.EW, pady=10)
        length = tk.IntVar(value=20)
        ttk.Label(gen, text="Length:").grid(row=0, column=0, sticky=tk.W)
        ttk.Spinbox(gen, from_=8, to=64, textvariable=length, width=5).grid(row=0, column=1, sticky=tk.W, padx=6)
        flags = {n: tk.BooleanVar(value=True) for n in ("A-Z", "a-z", "0-9", "Symbols")}
        for i, (n, v) in enumerate(flags.items()):
            ttk.Checkbutton(gen, text=n, variable=v).grid(row=1, column=i, sticky=tk.W, padx=(0, 8))
        info = tk.StringVar(value="Entropy: -")
        ttk.Label(gen, textvariable=info).grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=(6, 0))

        def generate():
            try:
                pw, bits = PasswordGenerator.generate(length.get(), flags["A-Z"].get(), flags["a-z"].get(),
                                                      flags["0-9"].get(), flags["Symbols"].get())
            except (ValueError, tk.TclError) as exc:
                messagebox.showwarning("Generator", str(exc), parent=dlg)
                return
            vars_["password"].set(pw)
            info.set(f"Entropy: {bits} bits ({PasswordGenerator.strength_label(bits)})")
            show.set(True)
            pw_entry.config(show="")

        ttk.Button(gen, text="Generate", command=generate).grid(row=2, column=3, sticky=tk.E)

        def save():
            site, user, pw, notes = (vars_[k].get().strip() if k != "password" else vars_[k].get()
                                     for k in ("site", "username", "password", "notes"))
            if not (site and user and pw):
                messagebox.showwarning("Missing data", "Website, username and password are required.", parent=dlg)
                return
            if record:
                self.vault.update_entry(record["id"], site, user, pw, notes)
            else:
                self.vault.add_entry(site, user, pw, notes)
            dlg.destroy()
            self.reload()

        ttk.Button(f, text="Encrypt & save", command=save).grid(row=6, column=0, columnspan=2, pady=(4, 0))
        self.dialog = dlg
        dlg.update_idletasks()
        dlg.geometry(f"+{self.root.winfo_rootx() + 150}+{self.root.winfo_rooty() + 60}")
        dlg.grab_set() if self.root.winfo_viewable() else None

    # ------------------------------------------------------------ locking
    def lock(self, reason: str = "Vault locked."):
        self.clip_guard.flush(self._read_clip, self._clear_clip)   # wipe copied secret now
        self.vault.lock()
        self.records.clear()
        for w in self.root.winfo_children():
            if isinstance(w, tk.Toplevel):
                w.destroy()
        self.show_auth_screen()
        self.status.set(reason)


def main():
    root = tk.Tk()
    PasswordManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
