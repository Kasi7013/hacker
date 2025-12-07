import string
import tkinter as tk
from tkinter import ttk, messagebox
from password_generator import PasswordGenerator

def generate():
    try:
        pg = PasswordGenerator()
        # length
        fixed = fixed_var.get()
        length_val = length_var.get()
        minlen = minlen_var.get()
        maxlen = maxlen_var.get()
        if fixed:
            pg.minlen = pg.maxlen = int(length_val)
        else:
            pg.minlen = int(minlen)
            pg.maxlen = int(maxlen)

        # include/exclude categories
        if not lower_var.get():
            pg.excludelchars = string.ascii_lowercase
            pg.minlchars = 0
        else:
            pg.excludelchars = ""
            pg.minlchars = 1 if require_each_var.get() else 0

        if not upper_var.get():
            pg.excludeuchars = string.ascii_uppercase
            pg.minuchars = 0
        else:
            pg.excludeuchars = ""
            pg.minuchars = 1 if require_each_var.get() else 0

        if not nums_var.get():
            pg.excludenumbers = string.digits
            pg.minnumbers = 0
        else:
            pg.excludenumbers = ""
            pg.minnumbers = 1 if require_each_var.get() else 0

        if not specs_var.get():
            # use generator's schars set by excluding a conservative list of punctuation
            pg.excludeschars = ''.join(pg._schars)
            pg.minschars = 0
        else:
            pg.excludeschars = ""
            pg.minschars = 1 if require_each_var.get() else 0

        # custom excludes
        pg.excludelchars += excl_lower_entry.get().strip()
        pg.excludeuchars += excl_upper_entry.get().strip()
        pg.excludenumbers += excl_nums_entry.get().strip()
        pg.excludeschars += excl_specs_entry.get().strip()

        count = int(count_var.get())
        out.delete("1.0", tk.END)
        for _ in range(max(1, count)):
            out.insert(tk.END, pg.generate() + "\n")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def copy_all():
    txt = out.get("1.0", tk.END).strip()
    if txt:
        root.clipboard_clear()
        root.clipboard_append(txt)
        messagebox.showinfo("Copied", "Passwords copied to clipboard")

root = tk.Tk()
root.title("Password Generator")

frm = ttk.Frame(root, padding=12)
frm.grid()

# Length controls
fixed_var = tk.BooleanVar(value=True)
require_each_var = tk.BooleanVar(value=True)
length_var = tk.IntVar(value=12)
minlen_var = tk.IntVar(value=8)
maxlen_var = tk.IntVar(value=16)
count_var = tk.IntVar(value=1)

ttk.Checkbutton(frm, text="Fixed length", variable=fixed_var).grid(column=0, row=0, sticky="w")
ttk.Label(frm, text="Length:").grid(column=1, row=0, sticky="e")
ttk.Spinbox(frm, from_=4, to=128, textvariable=length_var, width=6).grid(column=2, row=0, sticky="w")

ttk.Label(frm, text="Min:").grid(column=0, row=1, sticky="e")
ttk.Spinbox(frm, from_=4, to=128, textvariable=minlen_var, width=6).grid(column=1, row=1, sticky="w")
ttk.Label(frm, text="Max:").grid(column=2, row=1, sticky="e")
ttk.Spinbox(frm, from_=4, to=128, textvariable=maxlen_var, width=6).grid(column=3, row=1, sticky="w")

# Category includes
lower_var = tk.BooleanVar(value=True)
upper_var = tk.BooleanVar(value=True)
nums_var = tk.BooleanVar(value=True)
specs_var = tk.BooleanVar(value=True)

ttk.Checkbutton(frm, text="Lowercase", variable=lower_var).grid(column=0, row=2, sticky="w")
ttk.Checkbutton(frm, text="Uppercase", variable=upper_var).grid(column=1, row=2, sticky="w")
ttk.Checkbutton(frm, text="Numbers", variable=nums_var).grid(column=2, row=2, sticky="w")
ttk.Checkbutton(frm, text="Symbols", variable=specs_var).grid(column=3, row=2, sticky="w")

ttk.Checkbutton(frm, text="Require at least one of each enabled category", variable=require_each_var).grid(column=0, row=3, columnspan=4, sticky="w")

# Exclude entries
ttk.Label(frm, text="Exclude lower:").grid(column=0, row=4, sticky="e")
excl_lower_entry = ttk.Entry(frm, width=20)
excl_lower_entry.grid(column=1, row=4, columnspan=3, sticky="w")

ttk.Label(frm, text="Exclude upper:").grid(column=0, row=5, sticky="e")
excl_upper_entry = ttk.Entry(frm, width=20)
excl_upper_entry.grid(column=1, row=5, columnspan=3, sticky="w")

ttk.Label(frm, text="Exclude numbers:").grid(column=0, row=6, sticky="e")
excl_nums_entry = ttk.Entry(frm, width=20)
excl_nums_entry.grid(column=1, row=6, columnspan=3, sticky="w")

ttk.Label(frm, text="Exclude symbols:").grid(column=0, row=7, sticky="e")
excl_specs_entry = ttk.Entry(frm, width=20)
excl_specs_entry.grid(column=1, row=7, columnspan=3, sticky="w")

# Count, buttons and output
ttk.Label(frm, text="Count:").grid(column=0, row=8, sticky="e")
ttk.Spinbox(frm, from_=1, to=50, textvariable=count_var, width=6).grid(column=1, row=8, sticky="w")

ttk.Button(frm, text="Generate", command=generate).grid(column=2, row=8)
ttk.Button(frm, text="Copy", command=copy_all).grid(column=3, row=8)

out = tk.Text(frm, width=60, height=8)
out.grid(column=0, row=9, columnspan=4, pady=8)

root.mainloop()