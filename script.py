import argparse
import os
import struct
import sys
import json
from datetime import datetime
from typing import Tuple

try:
    from Crypto.Cipher import DES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256, HMAC
    from Crypto.Random import get_random_bytes
except Exception as e:
    print("Missing dependency. Install with: pip install pycryptodome")
    raise

MAGIC = b"LDES"
VERSION = 1
SALT_LEN = 16
IV_LEN = 8
HMAC_LEN = 32
PBKDF2_ITERS = 200_000
BLOCK_SIZE = 8

HEADER_STRUCT = struct.Struct(">4sB")
HISTORY_FILE = os.path.expanduser("~/.des_encryptor_history.json")

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding.")
    return data[:-pad_len]

def derive_key_iv(passphrase: str, salt: bytes) -> Tuple[bytes, bytes]:
    dk = PBKDF2(passphrase, salt, dkLen=16, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
    return dk[:8], dk[8:16]

def compute_hmac(salt: bytes, iv: bytes, ciphertext: bytes, passphrase: str) -> bytes:
    mac_key = PBKDF2(passphrase, salt + b"mac", dkLen=32, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(bytes([VERSION]))
    h.update(salt)
    h.update(iv)
    h.update(ciphertext)
    return h.digest()

def verify_hmac(salt: bytes, iv: bytes, ciphertext: bytes, tag: bytes, passphrase: str) -> None:
    mac_key = PBKDF2(passphrase, salt + b"mac", dkLen=32, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(bytes([VERSION]))
    h.update(salt)
    h.update(iv)
    h.update(ciphertext)
    try:
        h.verify(tag)
    except ValueError:
        raise ValueError("HMAC verification failed. Wrong passphrase or file corrupted.")

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except:
            return []
    return []

def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def add_history_entry(operation, input_file, output_file):
    history = load_history()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "operation": operation,
        "input": input_file,
        "output": output_file
    }
    history.insert(0, entry)
    history = history[:100]
    save_history(history)

def encrypt_file(in_path: str, out_path: str, passphrase: str) -> None:
    if not passphrase:
        raise ValueError("Passphrase must not be empty.")
    with open(in_path, "rb") as f:
        plaintext = f.read()
    salt = get_random_bytes(SALT_LEN)
    key, iv = derive_key_iv(passphrase, salt)
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext, BLOCK_SIZE))
    tag = compute_hmac(salt, iv, ct, passphrase)
    with open(out_path, "wb") as f:
        f.write(HEADER_STRUCT.pack(MAGIC, VERSION))
        f.write(salt)
        f.write(iv)
        f.write(ct)
        f.write(tag)
    add_history_entry("encrypt", in_path, out_path)

def decrypt_file(in_path: str, out_path: str, passphrase: str) -> None:
    with open(in_path, "rb") as f:
        blob = f.read()
    if len(blob) < HEADER_STRUCT.size + SALT_LEN + IV_LEN + HMAC_LEN + BLOCK_SIZE:
        raise ValueError("File too small or not a valid LDES file.")
    magic, version = HEADER_STRUCT.unpack_from(blob, 0)
    if magic != MAGIC:
        raise ValueError("Invalid file magic. Not an LDES file.")
    if version != VERSION:
        raise ValueError(f"Unsupported LDES version: {version}")
    offset = HEADER_STRUCT.size
    salt = blob[offset:offset + SALT_LEN]; offset += SALT_LEN
    iv = blob[offset:offset + IV_LEN]; offset += IV_LEN
    ciphertext = blob[offset:-HMAC_LEN]
    tag = blob[-HMAC_LEN:]
    verify_hmac(salt, iv, ciphertext, tag, passphrase)
    key, _iv = derive_key_iv(passphrase, salt)
    if _iv != iv:
        raise ValueError("Derived IV mismatch.")
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ciphertext)
    plaintext = pkcs7_unpad(padded, BLOCK_SIZE)
    with open(out_path, "wb") as f:
        f.write(plaintext)
    add_history_entry("decrypt", in_path, out_path)

def build_cli():
    p = argparse.ArgumentParser(description="Lightweight File Encryption System Using DES for Securing Student Records at Federal University Dutse")
    sub = p.add_subparsers(dest="cmd", required=True)
    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input", help="Path to input file")
    enc.add_argument("-o", "--output", help="Path to output .enc file (default: input + .enc)")
    enc.add_argument("-p", "--passphrase", help="Passphrase (will prompt if not provided)")
    dec = sub.add_parser("decrypt", help="Decrypt a .enc file")
    dec.add_argument("input", help="Path to .enc file")
    dec.add_argument("-o", "--output", help="Path to output (default: input without .enc)")
    dec.add_argument("-p", "--passphrase", help="Passphrase (will prompt if not provided)")
    gui = sub.add_parser("gui", help="Launch simple Tkinter GUI")
    return p

def prompt_hidden(prompt_text: str) -> str:
    try:
        import getpass
        return getpass.getpass(prompt_text)
    except Exception:
        return input(prompt_text)

def main_cli(argv=None):
    parser = build_cli()
    args = parser.parse_args(argv)
    if args.cmd == "gui":
        launch_gui()
        return 0
    if args.cmd == "encrypt":
        in_path = args.input
        out_path = args.output or (in_path + ".enc")
        passphrase = args.passphrase or prompt_hidden("Enter passphrase: ")
        if not passphrase:
            print("Passphrase cannot be empty.", file=sys.stderr)
            return 2
        encrypt_file(in_path, out_path, passphrase)
        print(f"Encrypted: {in_path} -> {out_path}")
        return 0
    if args.cmd == "decrypt":
        in_path = args.input
        if args.output:
            out_path = args.output
        else:
            out_path = in_path[:-4] if in_path.endswith(".enc") else (in_path + ".dec")
        passphrase = args.passphrase or prompt_hidden("Enter passphrase: ")
        if not passphrase:
            print("Passphrase cannot be empty.", file=sys.stderr)
            return 2
        decrypt_file(in_path, out_path, passphrase)
        print(f"Decrypted: {in_path} -> {out_path}")
        return 0
    parser.print_help()
    return 1

def launch_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    def select_input():
        path = filedialog.askopenfilename(title="Select file")
        if path:
            in_var.set(path)

    def do_encrypt():
        path = in_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Please select a valid input file.")
            return
        out = filedialog.asksaveasfilename(title="Save Encrypted File As", defaultextension=".enc",
                                           initialfile=os.path.basename(path) + ".enc")
        if not out:
            return
        pw = pw_var.get()
        if not pw:
            messagebox.showerror("Error", "Passphrase cannot be empty.")
            return
        try:
            encrypt_file(path, out, pw)
            messagebox.showinfo("Success", f"Encrypted:\n{path}\n→ {out}")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def do_decrypt():
        path = in_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Please select a valid input file.")
            return
        out = filedialog.asksaveasfilename(title="Save Decrypted File As",
                                           initialfile=os.path.basename(path).removesuffix(".enc"))
        if not out:
            return
        pw = pw_var.get()
        if not pw:
            messagebox.showerror("Error", "Passphrase cannot be empty.")
            return
        try:
            decrypt_file(path, out, pw)
            messagebox.showinfo("Success", f"Decrypted:\n{path}\n→ {out}")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def show_history():
        history = load_history()
        if not history:
            messagebox.showinfo("History", "No encryption history found.")
            return

        hist_win = tk.Toplevel(root)
        hist_win.title("Encryption History")
        hist_win.geometry("700x400")

        frame = tk.Frame(hist_win)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        tree = ttk.Treeview(frame, columns=("Time", "Operation", "Input", "Output"), show="headings")
        tree.heading("Time", text="Time")
        tree.heading("Operation", text="Operation")
        tree.heading("Input", text="Input File")
        tree.heading("Output", text="Output File")

        tree.column("Time", width=150)
        tree.column("Operation", width=80)
        tree.column("Input", width=230)
        tree.column("Output", width=230)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for entry in history:
            time_str = datetime.fromisoformat(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            tree.insert("", "end", values=(
                time_str,
                entry["operation"].capitalize(),
                os.path.basename(entry["input"]),
                os.path.basename(entry["output"])
            ))

    root = tk.Tk()
    root.title("Lightweight DES Encryptor")
    frm = tk.Frame(root, padx=14, pady=14)
    frm.pack(fill="both", expand=True)
    tk.Label(frm, text="Input File:").grid(row=0, column=0, sticky="w")
    in_var = tk.StringVar()
    tk.Entry(frm, textvariable=in_var, width=48).grid(row=1, column=0, columnspan=2, sticky="we", pady=(0,6))
    tk.Button(frm, text="Browse…", command=select_input).grid(row=1, column=2, padx=(6,0))
    tk.Label(frm, text="Passphrase:").grid(row=2, column=0, sticky="w", pady=(8,0))
    pw_var = tk.StringVar()
    pw_entry = tk.Entry(frm, textvariable=pw_var, width=48, show="•")
    pw_entry.grid(row=3, column=0, columnspan=3, sticky="we")
    btn_row = tk.Frame(frm)
    btn_row.grid(row=4, column=0, columnspan=3, pady=12, sticky="e")
    tk.Button(btn_row, text="Encrypt", width=14, command=do_encrypt).pack(side="left", padx=6)
    tk.Button(btn_row, text="Decrypt", width=14, command=do_decrypt).pack(side="left", padx=6)
    tk.Button(btn_row, text="History", width=14, command=show_history).pack(side="left", padx=6)
    root.mainloop()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        launch_gui()
        sys.exit(0)
    else:
        sys.exit(main_cli())
