"""Lockbox — a secure, session-only desktop password generator.

Passwords are generated with ``secrets`` rather than ``random``. Nothing is
written to disk: the visible history exists only for the current app session.
"""

from __future__ import annotations

import math
import secrets
import string
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, ttk

try:
    import pyperclip
except ImportError:  # Allows the app to open and explain the missing feature.
    pyperclip = None


MINIMUM_LENGTH = 8
MAXIMUM_LENGTH = 128
AMBIGUOUS_CHARACTERS = frozenset("0OoIl1")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


@dataclass(frozen=True)
class PasswordOptions:
    """The password policy selected in the UI."""

    length: int
    uppercase: bool
    lowercase: bool
    numbers: bool
    symbols: bool
    exclude_ambiguous: bool


def selected_pools(options: PasswordOptions) -> list[str]:
    """Return the enabled character pools after applying ambiguity filtering."""
    candidates = (
        (options.uppercase, string.ascii_uppercase),
        (options.lowercase, string.ascii_lowercase),
        (options.numbers, string.digits),
        (options.symbols, SYMBOLS),
    )
    pools = []
    for enabled, characters in candidates:
        if not enabled:
            continue
        if options.exclude_ambiguous:
            characters = "".join(char for char in characters if char not in AMBIGUOUS_CHARACTERS)
        if characters:
            pools.append(characters)
    return pools


def validate_options(options: PasswordOptions) -> list[str]:
    """Validate a chosen policy and return its usable character pools."""
    if not MINIMUM_LENGTH <= options.length <= MAXIMUM_LENGTH:
        raise ValueError(f"Choose a length from {MINIMUM_LENGTH} to {MAXIMUM_LENGTH} characters.")

    pools = selected_pools(options)
    if len(pools) < 2:
        raise ValueError("Select at least two character types for a stronger password.")
    if options.length < len(pools):
        raise ValueError("The length must be at least the number of selected character types.")
    return pools


def secure_shuffle(characters: list[str]) -> None:
    """Shuffle in-place with the operating system's secure randomness source."""
    for index in range(len(characters) - 1, 0, -1):
        swap_index = secrets.randbelow(index + 1)
        characters[index], characters[swap_index] = characters[swap_index], characters[index]


def generate_password(options: PasswordOptions) -> str:
    """Create a secure password containing one character from every enabled type."""
    pools = validate_options(options)
    password_characters = [secrets.choice(pool) for pool in pools]
    all_characters = "".join(pools)
    password_characters.extend(
        secrets.choice(all_characters) for _ in range(options.length - len(password_characters))
    )
    secure_shuffle(password_characters)
    return "".join(password_characters)


def strength_for(options: PasswordOptions) -> tuple[str, int, str]:
    """Give a plain-language strength rating based on diversity and search space."""
    pools = selected_pools(options)
    alphabet_size = len("".join(pools))
    entropy_bits = options.length * math.log2(alphabet_size) if alphabet_size else 0

    if len(pools) < 2 or entropy_bits < 50:
        return "Weak", 1, "#ef5b61"
    if entropy_bits < 75:
        return "Medium", 2, "#f5aa42"
    return "Strong", 3, "#36bd7e"


class PasswordGeneratorApp(tk.Tk):
    """The password generator interface and its session-only history."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Lockbox — Secure Password Generator")
        self.geometry("760x630")
        self.minsize(690, 590)
        self.configure(bg="#f5f7ff")
        self.history: list[str] = []

        self.length_var = tk.IntVar(value=16)
        self.uppercase_var = tk.BooleanVar(value=True)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.numbers_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.ambiguous_var = tk.BooleanVar(value=False)
        self.password_var = tk.StringVar(value="Your secure password will appear here")
        self.status_var = tk.StringVar(value="Choose your settings, then generate a password.")
        self.strength_var = tk.StringVar(value="Strong")

        self._configure_styles()
        self._build_interface()
        self._update_strength()

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("Title.TLabel", background="#ffffff", foreground="#242140", font=("Georgia", 27, "bold"))
        style.configure("Sub.TLabel", background="#ffffff", foreground="#77738e", font=("Segoe UI", 10))
        style.configure("Eyebrow.TLabel", background="#ffffff", foreground="#6759e8", font=("Segoe UI", 9, "bold"))
        style.configure("Section.TLabel", background="#ffffff", foreground="#242140", font=("Segoe UI", 12, "bold"))
        style.configure("Detail.TLabel", background="#ffffff", foreground="#77738e", font=("Segoe UI", 9))
        style.configure("Password.TEntry", font=("Cascadia Mono", 15, "bold"), foreground="#302a63", fieldbackground="#f3f1ff", bordercolor="#ded9ff")
        style.configure("Primary.TButton", background="#6759e8", foreground="#ffffff", borderwidth=0, padding=(17, 11), font=("Segoe UI", 10, "bold"))
        style.map("Primary.TButton", background=[("active", "#5547d4")])
        style.configure("Copy.TButton", background="#eceaff", foreground="#5143c7", borderwidth=0, padding=(14, 9), font=("Segoe UI", 9, "bold"))
        style.map("Copy.TButton", background=[("active", "#ddd8ff")])
        style.configure("TCheckbutton", background="#ffffff", foreground="#3d3958", font=("Segoe UI", 10))
        style.map("TCheckbutton", background=[("active", "#ffffff")])

    def _build_interface(self) -> None:
        outer = ttk.Frame(self, padding=(42, 30), style="Card.TFrame")
        outer.pack(fill="both", expand=True, padx=25, pady=25)

        ttk.Label(outer, text="LOCKBOX", style="Eyebrow.TLabel").pack(anchor="w")
        ttk.Label(outer, text="Make a password worth keeping.", style="Title.TLabel").pack(anchor="w", pady=(5, 3))
        ttk.Label(outer, text="Securely generated • copied automatically • never saved to disk", style="Sub.TLabel").pack(anchor="w", pady=(0, 24))

        password_frame = ttk.Frame(outer, style="Card.TFrame")
        password_frame.pack(fill="x")
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, style="Password.TEntry", state="readonly")
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=9)
        ttk.Button(password_frame, text="Copy", style="Copy.TButton", command=self.copy_password).pack(side="left", padx=(10, 0))

        ttk.Label(outer, textvariable=self.status_var, style="Detail.TLabel", wraplength=610).pack(anchor="w", pady=(7, 20))

        controls = ttk.Frame(outer, style="Card.TFrame")
        controls.pack(fill="x")
        controls.columnconfigure(0, weight=1)
        controls.columnconfigure(1, weight=1)

        left = ttk.Frame(controls, style="Card.TFrame")
        left.grid(row=0, column=0, sticky="new", padx=(0, 28))
        ttk.Label(left, text="Password length", style="Section.TLabel").pack(anchor="w")
        length_row = ttk.Frame(left, style="Card.TFrame")
        length_row.pack(fill="x", pady=(11, 5))
        ttk.Scale(length_row, from_=MINIMUM_LENGTH, to=MAXIMUM_LENGTH, variable=self.length_var, command=self._on_setting_change).pack(side="left", fill="x", expand=True)
        self.length_display = ttk.Label(length_row, textvariable=self.length_var, style="Section.TLabel", width=4, anchor="e")
        self.length_display.pack(side="left", padx=(10, 0))
        ttk.Label(left, text="8–128 characters", style="Detail.TLabel").pack(anchor="w")

        right = ttk.Frame(controls, style="Card.TFrame")
        right.grid(row=0, column=1, sticky="new")
        ttk.Label(right, text="Include characters", style="Section.TLabel").pack(anchor="w")
        checks = (
            ("Uppercase  A–Z", self.uppercase_var),
            ("Lowercase  a–z", self.lowercase_var),
            ("Numbers  0–9", self.numbers_var),
            ("Symbols  ! @ # …", self.symbols_var),
        )
        for label, variable in checks:
            ttk.Checkbutton(right, text=label, variable=variable, command=self._on_setting_change).pack(anchor="w", pady=2)

        ttk.Separator(outer).pack(fill="x", pady=22)
        lower = ttk.Frame(outer, style="Card.TFrame")
        lower.pack(fill="x")
        ttk.Checkbutton(
            lower,
            text="Exclude ambiguous characters (0, O, o, I, l, 1)",
            variable=self.ambiguous_var,
            command=self._on_setting_change,
        ).pack(side="left")

        strength_frame = ttk.Frame(outer, style="Card.TFrame")
        strength_frame.pack(fill="x", pady=(21, 15))
        ttk.Label(strength_frame, text="Password strength", style="Section.TLabel").pack(side="left")
        ttk.Label(strength_frame, textvariable=self.strength_var, style="Section.TLabel").pack(side="right")
        self.strength_canvas = tk.Canvas(outer, height=10, highlightthickness=0, bg="#e9e7f4")
        self.strength_canvas.pack(fill="x")

        ttk.Button(outer, text="Generate secure password  →", style="Primary.TButton", command=self.generate).pack(fill="x", pady=(23, 18))

        history_frame = ttk.Frame(outer, style="Card.TFrame")
        history_frame.pack(fill="both", expand=True)
        ttk.Label(history_frame, text="Recent passwords", style="Section.TLabel").pack(anchor="w")
        ttk.Label(history_frame, text="Only the last 5 appear here, and they vanish when you close Lockbox.", style="Detail.TLabel").pack(anchor="w", pady=(2, 7))
        self.history_list = tk.Listbox(
            history_frame, height=5, borderwidth=0, highlightthickness=0,
            bg="#f8f7ff", fg="#514c72", font=("Cascadia Mono", 10), selectbackground="#ddd8ff",
        )
        self.history_list.pack(fill="both", expand=True)
        self.history_list.bind("<Double-Button-1>", self.copy_history_item)

    def _current_options(self) -> PasswordOptions:
        return PasswordOptions(
            length=int(self.length_var.get()),
            uppercase=self.uppercase_var.get(),
            lowercase=self.lowercase_var.get(),
            numbers=self.numbers_var.get(),
            symbols=self.symbols_var.get(),
            exclude_ambiguous=self.ambiguous_var.get(),
        )

    def _on_setting_change(self, _value: object | None = None) -> None:
        self._update_strength()

    def _update_strength(self) -> None:
        label, bars, colour = strength_for(self._current_options())
        self.strength_var.set(label)
        self.strength_canvas.delete("all")
        width = max(self.strength_canvas.winfo_width(), 610)
        gap = 5
        bar_width = (width - (gap * 2)) / 3
        for index in range(3):
            fill = colour if index < bars else "#e9e7f4"
            start = index * (bar_width + gap)
            self.strength_canvas.create_rectangle(start, 0, start + bar_width, 10, fill=fill, outline="")

    def _copy(self, password: str) -> bool:
        if pyperclip is None:
            self.status_var.set("Install pyperclip to use clipboard copying: py -m pip install pyperclip")
            return False
        try:
            pyperclip.copy(password)
            return True
        except Exception:
            self.status_var.set("Clipboard access is unavailable on this computer. Your password is still displayed above.")
            return False

    def generate(self) -> None:
        options = self._current_options()
        try:
            password = generate_password(options)
        except ValueError as error:
            messagebox.showwarning("Check your password settings", str(error), parent=self)
            self.status_var.set(str(error))
            return

        self.password_var.set(password)
        self.history.insert(0, password)
        self.history = self.history[:5]
        self._render_history()
        self._update_strength()
        copied = self._copy(password)
        self.status_var.set("Generated securely and copied to your clipboard." if copied else "Generated securely. Use Copy when clipboard access is available.")

    def copy_password(self) -> None:
        password = self.password_var.get()
        if password == "Your secure password will appear here":
            self.status_var.set("Generate a password first.")
            return
        if self._copy(password):
            self.status_var.set("Password copied to your clipboard.")

    def _render_history(self) -> None:
        self.history_list.delete(0, tk.END)
        for index, password in enumerate(self.history, start=1):
            self.history_list.insert(tk.END, f"{index}.  {password}")

    def copy_history_item(self, _event: tk.Event) -> None:
        selection = self.history_list.curselection()
        if not selection:
            return
        password = self.history[selection[0]]
        self.password_var.set(password)
        if self._copy(password):
            self.status_var.set("Selected password copied to your clipboard.")


if __name__ == "__main__":
    PasswordGeneratorApp().mainloop()
