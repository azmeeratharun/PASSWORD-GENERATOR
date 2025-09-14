import tkinter as tk
from tkinter import ttk, messagebox
import random
import string

# Characters to treat as ambiguous when excluding
AMBIGUOUS_CHARS = 'il1Lo0O'

class PasswordGeneratorApp:
    def __init__(self, root):  # Correct constructor with double underscores
        self.root = root
        self.root.title("Advanced Password Generator")
        self.root.geometry("450x350")
        self.root.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        # Password length frame
        length_frame = ttk.Frame(self.root)
        length_frame.pack(pady=10, fill='x', padx=20)

        ttk.Label(length_frame, text="Password Length:").pack(side='left')
        self.length_var = tk.IntVar(value=12)
        self.length_spinbox = ttk.Spinbox(length_frame, from_=8, to=128,
                                          textvariable=self.length_var, width=5)
        self.length_spinbox.pack(side='left', padx=10)

        # Character type options
        char_frame = ttk.LabelFrame(self.root, text="Include Characters")
        char_frame.pack(pady=10, fill='x', padx=20)

        self.include_letters_var = tk.BooleanVar(value=True)
        self.include_numbers_var = tk.BooleanVar(value=True)
        self.include_symbols_var = tk.BooleanVar(value=True)
        self.exclude_ambiguous_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(char_frame, text="Letters (a-z, A-Z)",
                        variable=self.include_letters_var).pack(anchor='w', padx=10, pady=2)
        ttk.Checkbutton(char_frame, text="Numbers (0-9)",
                        variable=self.include_numbers_var).pack(anchor='w', padx=10, pady=2)
        ttk.Checkbutton(char_frame, text="Symbols (!@#$...)",
                        variable=self.include_symbols_var).pack(anchor='w', padx=10, pady=2)
        ttk.Checkbutton(char_frame, text="Exclude Ambiguous (il1Lo0O)",
                        variable=self.exclude_ambiguous_var).pack(anchor='w', padx=10, pady=2)

        # Action buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)

        self.generate_button = ttk.Button(button_frame, text="Generate Password",
                                          command=self.generate_password)
        self.generate_button.pack(side='left', padx=10)

        self.clear_button = ttk.Button(button_frame, text="Clear",
                                       command=self.clear_password)
        self.clear_button.pack(side='left', padx=10)

        # Password output
        output_frame = ttk.Frame(self.root)
        output_frame.pack(pady=10, fill='x', padx=20)

        ttk.Label(output_frame, text="Generated Password:").pack(anchor='w')
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(output_frame, textvariable=self.password_var,
                                        font=("Consolas", 12), state='readonly')
        self.password_entry.pack(fill='x', pady=5)

        # Copy button
        self.copy_button = ttk.Button(output_frame, text="Copy to Clipboard",
                                      command=self.copy_to_clipboard)
        self.copy_button.pack()

        # Strength label
        self.strength_var = tk.StringVar(value="")
        self.strength_label = ttk.Label(self.root, textvariable=self.strength_var,
                                        font=("Arial", 10, "bold"))
        self.strength_label.pack(pady=5)

    def generate_password(self):
        length = self.length_var.get()
        include_letters = self.include_letters_var.get()
        include_numbers = self.include_numbers_var.get()
        include_symbols = self.include_symbols_var.get()
        exclude_ambiguous = self.exclude_ambiguous_var.get()

        # Validation checks
        if length < 8 or length > 128:
            messagebox.showerror("Invalid Length", "Password length must be between 8 and 128.")
            return
        if not (include_letters or include_numbers or include_symbols):
            messagebox.showerror("No Character Types", "Select at least one character type.")
            return

        char_pools = []
        if include_letters:
            letters = string.ascii_letters
            if exclude_ambiguous:
                letters = ''.join(c for c in letters if c not in AMBIGUOUS_CHARS)
            char_pools.append(letters)
        if include_numbers:
            numbers = string.digits
            if exclude_ambiguous:
                numbers = ''.join(c for c in numbers if c not in AMBIGUOUS_CHARS)
            char_pools.append(numbers)
        if include_symbols:
            symbols = string.punctuation
            if exclude_ambiguous:
                symbols = ''.join(c for c in symbols if c not in AMBIGUOUS_CHARS)
            char_pools.append(symbols)

        full_pool = ''.join(char_pools)
        if not full_pool:
            messagebox.showerror("Empty Character Pool", "No characters available after exclusions.")
            return

        # Guarantee at least one character from each selected pool
        password_chars = [random.choice(pool) for pool in char_pools]
        if length < len(password_chars):
            messagebox.showerror("Length Too Short",
                                 f"Length must be at least {len(password_chars)} "
                                 "to include all selected character types.")
            return

        password_chars += random.choices(full_pool, k=length - len(password_chars))
        random.shuffle(password_chars)
        password = ''.join(password_chars)

        self.password_var.set(password)
        self.update_strength(password)

    def update_strength(self, password):
        length = len(password)
        categories = 0
        if any(c.islower() for c in password): categories += 1
        if any(c.isupper() for c in password): categories += 1
        if any(c.isdigit() for c in password): categories += 1
        if any(c in string.punctuation for c in password): categories += 1

        if length >= 12 and categories >= 3:
            strength, color = "Strong", "green"
        elif length >= 8 and categories >= 2:
            strength, color = "Medium", "orange"
        else:
            strength, color = "Weak", "red"

        self.strength_var.set(f"Password Strength: {strength}")
        self.strength_label.config(foreground=color)

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("No Password", "Generate a password first.")

    def clear_password(self):
        self.password_var.set("")
        self.strength_var.set("")

def main():
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
