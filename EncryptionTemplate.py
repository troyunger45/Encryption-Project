import tkinter as tk
from tkinter import ttk, messagebox
import codecs
import re

# -----------------------
# Theme / Utilities
# -----------------------
PRIMARY = "#2E5AAC"     # deep slate blue
PRIMARY_HOVER = "#274e97"
BG = "#E9EEF3"          # app background
CARD = "#FFFFFF"        # panel background
TEXT = "#1E1E24"
SUBTLE = "#6b7280"
FONT = ("Segoe UI", 11)
TITLE_FONT = ("Segoe UI", 18, "bold")
MONO = ("Cascadia Mono", 10)

SSN_RE   = re.compile(r"^\d{3}-\d{2}-\d{4}$")
PHONE_RE = re.compile(r"^\d{3}-\d{3}-\d{4}$")


def apply_theme(root: tk.Tk):
    root.configure(bg=BG)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=CARD, relief="flat")
    style.configure("TLabel", background=BG, foreground=TEXT, font=FONT)
    style.configure("Title.TLabel", background=BG, foreground=TEXT, font=TITLE_FONT)

    style.configure(
        "TEntry",
        fieldbackground="#ffffff",
        padding=(8, 6),
        relief="flat",
    )
    style.map("TEntry", focusfill=[("focus", "#ffffff")])

    style.configure(
        "Accent.TButton",
        background=PRIMARY,
        foreground="#ffffff",
        padding=(16, 8),
        relief="flat",
        borderwidth=0,
        focusthickness=0,
        font=("Segoe UI Semibold", 11)
    )
    style.map(
        "Accent.TButton",
        background=[("active", PRIMARY_HOVER)],
        foreground=[("disabled", "#d1d5db")]
    )

    style.configure(
        "Ghost.TButton",
        background=BG,
        foreground=PRIMARY,
        padding=(14, 8),
        relief="flat",
        borderwidth=0,
        font=("Segoe UI Semibold", 11)
    )
    style.map("Ghost.TButton", background=[("active", "#e8eefc")])


# ---------- Placeholder helper ----------
class PlaceholderEntry(ttk.Entry):
    def __init__(self, master=None, placeholder: str = "", color: str = SUBTLE, **kwargs):
        super().__init__(master, **kwargs)
        self.placeholder = placeholder
        self.placeholder_color = color
        self.default_fg = TEXT
        self._has_placeholder = False
        self._put_placeholder()
        self.bind("<FocusIn>", self._clear_placeholder)
        self.bind("<FocusOut>", self._put_placeholder)

    def _put_placeholder(self, *_):
        if not self.get():
            self._has_placeholder = True
            self.configure(foreground=self.placeholder_color)
            self.insert(0, self.placeholder)

    def _clear_placeholder(self, *_):
        if self._has_placeholder:
            self.delete(0, "end")
            self.configure(foreground=self.default_fg)
            self._has_placeholder = False

    def get_value(self) -> str:
        return "" if self._has_placeholder else self.get()

    def hard_reset(self):
        """Clear and show placeholder (used when returning to the form)."""
        self.delete(0, "end")
        self._has_placeholder = False
        self._put_placeholder()


# -----------------------
# Crypto
# -----------------------
def rot18(text: str) -> str:
    result = []
    for char in text:
        if 'a' <= char <= 'z':  # lowercase letters
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':  # uppercase letters
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        elif '0' <= char <= '9':  # digits
            result.append(chr((ord(char) - ord('0') + 5) % 10 + ord('0')))
        else:  # non-alphanumeric stay the same
            result.append(char)
    return ''.join(result)

# -----------------------
# App Shell with Frame Switching
# -----------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CareCipher — ROT18 Medical Encryptor")
        self.geometry("860x600")
        self.minsize(820, 560)
        self.resizable(True, True)
        apply_theme(self)

        # In-memory 'database' (session only)
        self.users = {"user": "password"}  # default account
        self.current_user = None

        # Container for swapping frames
        container = ttk.Frame(self, style="TFrame")
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (LoginFrame, RegisterFrame, MainMenuFrame, MedicalFormFrame, ResultFrame):
            name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show("LoginFrame")

    def show(self, name: str, **kwargs):
        frame = self.frames[name]
        if hasattr(frame, "on_show"):
            frame.on_show(**kwargs)
        frame.tkraise()


# -----------------------
# Frames
# -----------------------
class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent, padding=30)
        self.controller = controller

        header = ttk.Frame(self, style="Card.TFrame", padding=20)
        header.pack(pady=(10, 20), padx=10, fill="x")
        ttk.Label(header, text="Welcome", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Log in with your credentials to continue.", foreground=SUBTLE).pack(anchor="w", pady=(4,0))

        card = ttk.Frame(self, style="Card.TFrame", padding=24)
        card.pack(padx=10, fill="x")

        form = ttk.Frame(card)
        form.pack(pady=6, fill="x")

        ttk.Label(form, text="Username").grid(row=0, column=0, sticky="w", pady=8)
        self.user_entry = ttk.Entry(form, width=38)
        self.user_entry.grid(row=0, column=1, padx=12, sticky="w")

        ttk.Label(form, text="Password").grid(row=1, column=0, sticky="w", pady=8)
        self.pass_entry = ttk.Entry(form, width=38, show="*")
        self.pass_entry.grid(row=1, column=1, padx=12, sticky="w")

        btns = ttk.Frame(card)
        btns.pack(pady=10)
        ttk.Button(btns, text="Login", style="Accent.TButton", command=self.login).pack(side="left", padx=6)
        ttk.Button(btns, text="Register", style="Ghost.TButton", command=lambda: self.controller.show("RegisterFrame")).pack(side="left", padx=6)

        ttk.Label(self, text="Default account → user / password", foreground=SUBTLE).pack(pady=(12,0))

    def login(self):
        u = self.user_entry.get().strip()
        p = self.pass_entry.get().strip()
        if not u or not p:
            messagebox.showwarning("Missing", "Please enter username and password.")
            return
        if self.controller.users.get(u) == p:
            self.controller.current_user = u
            self.user_entry.delete(0, "end")
            self.pass_entry.delete(0, "end")
            self.controller.show("MainMenuFrame")
        else:
            messagebox.showerror("Login failed", "Invalid username or password.")


class RegisterFrame(ttk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent, padding=30)
        self.controller = controller

        ttk.Label(self, text="Create account", style="Title.TLabel").pack(anchor="w", padx=10, pady=(0,10))
        card = ttk.Frame(self, style="Card.TFrame", padding=24)
        card.pack(padx=10, fill="x")

        form = ttk.Frame(card)
        form.pack(pady=6)

        ttk.Label(form, text="New username").grid(row=0, column=0, sticky="w", pady=8)
        self.user_entry = ttk.Entry(form, width=38)
        self.user_entry.grid(row=0, column=1, padx=12)

        ttk.Label(form, text="New password").grid(row=1, column=0, sticky="w", pady=8)
        self.pass_entry = ttk.Entry(form, width=38, show="*")
        self.pass_entry.grid(row=1, column=1, padx=12)

        btns = ttk.Frame(card)
        btns.pack(pady=12)
        ttk.Button(btns, text="Create Account", style="Accent.TButton", command=self.create).pack(side="left", padx=6)
        ttk.Button(btns, text="Back to Login", style="Ghost.TButton", command=lambda: self.controller.show("LoginFrame")).pack(side="left", padx=6)

    def create(self):
        u = self.user_entry.get().strip()
        p = self.pass_entry.get().strip()
        if not u or not p:
            messagebox.showwarning("Missing", "Username and password are required.")
            return
        if u in self.controller.users:
            messagebox.showerror("Exists", "That username is already registered.")
            return
        self.controller.users[u] = p
        messagebox.showinfo("Success", "Account created. You can log in now.")
        self.controller.show("LoginFrame")


class MainMenuFrame(ttk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent, padding=30)
        self.controller = controller

        ttk.Label(self, text="Main Menu", style="Title.TLabel").pack(anchor="w", padx=10)

        card = ttk.Frame(self, style="Card.TFrame", padding=24)
        card.pack(padx=10, pady=10, fill="x")

        ttk.Label(card, text="Choose an option:").pack(anchor="w")
        ttk.Button(card, text="Encrypt/Decrypt Medical Data", style="Accent.TButton",
                   command=lambda: controller.show("MedicalFormFrame")).pack(pady=(8,0), anchor="w")

        ttk.Button(self, text="Logout", style="Ghost.TButton",
                   command=lambda: controller.show("LoginFrame")).pack(padx=10, pady=20, anchor="w")

    def on_show(self):
        pass


class MedicalFormFrame(ttk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent, padding=30)
        self.controller = controller

        ttk.Label(self, text="Medical Information Form", style="Title.TLabel").pack(anchor="w", padx=10, pady=(0,10))

        card = ttk.Frame(self, style="Card.TFrame", padding=24)
        card.pack(padx=10, fill="x")

        grid = ttk.Frame(card)
        grid.pack(fill="x")

        # Form fields (StringVars used only for non-placeholder entries)
        self.vars = {
            "email": tk.StringVar(),
            "provider": tk.StringVar(),
            "insid": tk.StringVar(),
        }

        def row(r, label, widget):
            ttk.Label(grid, text=label + ":").grid(row=r, column=0, sticky="e", pady=8, padx=(0,12))
            widget.grid(row=r, column=1, sticky="we")

        grid.columnconfigure(1, weight=1)

        # Placeholders for first/last/ssn/phone
        self.first_entry = PlaceholderEntry(grid, placeholder="John", width=40)
        self.last_entry  = PlaceholderEntry(grid, placeholder="Doe",  width=40)
        self.ssn_entry   = PlaceholderEntry(grid, placeholder="XXX-XX-XXXX", width=40)
        self.phone_entry = PlaceholderEntry(grid, placeholder="XXX-XXX-XXXX", width=40)

        row(0, "First name", self.first_entry)
        row(1, "Last name",  self.last_entry)
        row(2, "SSN",        self.ssn_entry)
        row(3, "Email",      ttk.Entry(grid, textvariable=self.vars["email"], width=40))
        row(4, "Phone",      self.phone_entry)
        row(5, "Healthcare provider", ttk.Entry(grid, textvariable=self.vars["provider"], width=40))
        row(6, "Insurance ID",        ttk.Entry(grid, textvariable=self.vars["insid"], width=40))

        btns = ttk.Frame(card)
        btns.pack(pady=16)
        ttk.Button(btns, text="Encrypt", style="Accent.TButton",
                   command=self.encrypt_and_show).pack(side="left", padx=6)
        ttk.Button(btns, text="Back", style="Ghost.TButton",
                   command=lambda: self.controller.show("MainMenuFrame")).pack(side="left", padx=6)

    def on_show(self):
        """Reset the entire form to fresh placeholders every time."""
        # Clear placeholder entries completely
        for e in (self.first_entry, self.last_entry, self.ssn_entry, self.phone_entry):
            e.hard_reset()
        # Reset regular StringVar-backed entries
        for k in self.vars:
            self.vars[k].set("")

    def _compose_block(self) -> str:
        # use get_value() so placeholders don't count as values
        first = self.first_entry.get_value()
        last  = self.last_entry.get_value()
        ssn   = self.ssn_entry.get_value()
        phone = self.phone_entry.get_value()

        email = self.vars["email"].get()
        provider = self.vars["provider"].get()
        insid = self.vars["insid"].get()

        return (
            f"First Name: {first}\n"
            f"Last Name: {last}\n"
            f"SSN: {ssn}\n"
            f"Email: {email}\n"
            f"Phone: {phone}\n"
            f"Healthcare Provider: {provider}\n"
            f"Insurance ID: {insid}\n"
        )

    def encrypt_and_show(self):
        # Validate only if user entered something (placeholders don't count)
        ssn = self.ssn_entry.get_value()
        phone = self.phone_entry.get_value()

        if ssn and not SSN_RE.match(ssn):
            messagebox.showerror("Invalid SSN", "SSN must be in the form XXX-XX-XXXX.")
            return
        if phone and not PHONE_RE.match(phone):
            messagebox.showerror("Invalid phone", "Phone must be in the form XXX-XXX-XXXX.")
            return

        block = self._compose_block()
        encrypted = rot18(block)
        self.controller.show("ResultFrame", text=encrypted, mode="encrypted")


class ResultFrame(ttk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent, padding=30)
        self.controller = controller
        self.mode = "encrypted"  # or "decrypted"

        header = ttk.Frame(self, style="TFrame")
        header.pack(anchor="w", padx=10, fill="x")
        ttk.Label(header, text="Encrypted / Decrypted Output", style="Title.TLabel").pack(side="left")
        self.status_label = ttk.Label(header, text="  [Encrypted]", foreground=SUBTLE)
        self.status_label.pack(side="left", padx=(8,0))

        card = ttk.Frame(self, style="Card.TFrame", padding=16)
        card.pack(padx=10, pady=10, fill="both", expand=True)

        self.text = tk.Text(card, height=18, wrap="word", relief="flat", bd=0)
        self.text.configure(bg="#FCFCFF", fg=TEXT, insertbackground=TEXT, font=MONO)
        self.text.pack(fill="both", expand=True)

        btns = ttk.Frame(self)
        btns.pack(pady=12)
        ttk.Button(btns, text="Encrypt", style="Accent.TButton", command=self.to_encrypted).pack(side="left", padx=6)
        ttk.Button(btns, text="Decrypt", style="Ghost.TButton", command=self.to_decrypted).pack(side="left", padx=6)
        ttk.Button(btns, text="Back", style="Ghost.TButton",
                   command=lambda: self.controller.show("MedicalFormFrame")).pack(side="left", padx=6)

    def on_show(self, text: str = "", mode: str = "encrypted"):
        self.mode = mode
        self._update_status()
        self.text.delete("1.0", "end")
        self.text.insert("1.0", text)

    def _update_status(self):
        self.status_label.configure(text=f"  [{self.mode.capitalize()}]")

    def _get_current(self) -> str:
        return self.text.get("1.0", "end-1c")

    def to_encrypted(self):
        if self.mode != "encrypted":
            cur = self._get_current()
            self.text.delete("1.0", "end")
            self.text.insert("1.0", rot18(cur))
            self.mode = "encrypted"
            self._update_status()

    def to_decrypted(self):
        if self.mode != "decrypted":
            cur = self._get_current()
            self.text.delete("1.0", "end")
            self.text.insert("1.0", rot18(cur))
            self.mode = "decrypted"
            self._update_status()


if __name__ == "__main__":
    App().mainloop()