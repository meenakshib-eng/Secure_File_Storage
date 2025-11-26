# main_gui.py
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sqlite3
from io import BytesIO
import datetime

# Import your existing backend modules
from rbac import authenticate, check_permission, get_conn, DB_FILE
from encryption import generate_aes_key, aes_encrypt, aes_decrypt
from key_management import load_public_key, load_private_key, wrap_key, unwrap_key
import integrity

KEY_DIR = "keys"
PUBLIC_KEY = os.path.join(KEY_DIR, "public_key.pem")
PRIVATE_KEY = os.path.join(KEY_DIR, "private_key.pem")
UPLOAD_DIR = "stored_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Helper to list files in DB
def list_files():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, filename, created_at FROM files ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def upload_file_gui(username, password, filepath):
    user = authenticate(username, password)
    if not user:
        raise PermissionError("Invalid credentials")
    if not check_permission(user, "upload"):
        raise PermissionError("Insufficient role to upload")

    with open(filepath, "rb") as f:
        data = f.read()

    # AES encrypt
    aes_key = generate_aes_key()
    enc = aes_encrypt(data, aes_key)
    ciphertext = enc["ciphertext"]
    nonce = enc["nonce"]

    # Wrap AES key using public key
    pub = load_public_key(PUBLIC_KEY)
    wrapped = wrap_key(aes_key, pub)

    # Save ciphertext
    filename = os.path.basename(filepath)
    filepath_saved = os.path.join(UPLOAD_DIR, f"{datetime.datetime.utcnow().timestamp()}_{filename}.bin")
    with open(filepath_saved, "wb") as f:
        f.write(ciphertext)

    # Integrity
    sha3 = integrity.sha3_256_hash(data)
    with open("hmac.key", "rb") as f:
        hmac_key = f.read()
    hmac_hex = integrity.make_hmac(hmac_key, data)

    # Insert DB record
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        INSERT INTO files (filename, filepath, owner_id, wrapped_key, nonce, sha3, hmac, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (filename, filepath_saved, user["id"], wrapped, nonce, sha3, hmac_hex, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return True

def download_file_gui(username, password, file_id, dest_path):
    user = authenticate(username, password)
    if not user:
        raise PermissionError("Invalid credentials")
    if not check_permission(user, "download"):
        raise PermissionError("Insufficient role to download")

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT filepath, wrapped_key, nonce, filename FROM files WHERE id = ?", (file_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise FileNotFoundError("File not found in DB")

    filepath_saved, wrapped_key, nonce, filename = row

    # unwrap AES key with private key
    priv = load_private_key(PRIVATE_KEY)
    aes_key = unwrap_key(wrapped_key, priv)

    with open(filepath_saved, "rb") as f:
        ciphertext = f.read()
    plaintext = aes_decrypt(ciphertext, nonce, aes_key)

    # Save to destination
    out_file = os.path.join(dest_path, filename)
    with open(out_file, "wb") as f:
        f.write(plaintext)
    return out_file

# ----------------- Tkinter GUI -----------------
class SecureStoreApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Storage (RBAC) - Desktop")
        self.geometry("780x520")
        self.resizable(False, False)

        self.create_widgets()
        self.refresh_file_list()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        # Top: login fields
        row = ttk.Frame(frm)
        row.pack(fill=tk.X, pady=6)
        ttk.Label(row, text="Username:").pack(side=tk.LEFT)
        self.username_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.username_var, width=18).pack(side=tk.LEFT, padx=6)
        ttk.Label(row, text="Password:").pack(side=tk.LEFT)
        self.password_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.password_var, width=18, show="*").pack(side=tk.LEFT, padx=6)

        # Middle: Upload and Download controls
        ctrl = ttk.Frame(frm)
        ctrl.pack(fill=tk.X, pady=10)

        ttk.Button(ctrl, text="Upload File", command=self.on_upload).pack(side=tk.LEFT, padx=8)
        ttk.Button(ctrl, text="Download Selected", command=self.on_download).pack(side=tk.LEFT, padx=8)
        ttk.Button(ctrl, text="Refresh List", command=self.refresh_file_list).pack(side=tk.LEFT, padx=8)

        # Files list
        cols = ("id", "filename", "created_at")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", height=18)
        self.tree.heading("id", text="ID"); self.tree.column("id", width=60, anchor=tk.CENTER)
        self.tree.heading("filename", text="Filename"); self.tree.column("filename", width=460, anchor=tk.W)
        self.tree.heading("created_at", text="Uploaded at"); self.tree.column("created_at", width=200, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, pady=6)

        # Footer: status
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status.pack(side=tk.BOTTOM, fill=tk.X)

    def refresh_file_list(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        try:
            rows = list_files()
            for r in rows:
                self.tree.insert("", tk.END, values=r)
            self.status_var.set(f"Loaded {len(rows)} files")
        except Exception as e:
            self.status_var.set(f"Error loading files: {e}")

    def on_upload(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if not (username and password):
            messagebox.showwarning("Auth required", "Enter username & password")
            return
        file_path = filedialog.askopenfilename(title="Select file to upload")
        if not file_path:
            return
        try:
            upload_file_gui(username, password, file_path)
            messagebox.showinfo("Uploaded", "File uploaded and encrypted successfully.")
            self.refresh_file_list()
        except PermissionError as pe:
            messagebox.showerror("Permission denied", str(pe))
        except Exception as e:
            messagebox.showerror("Upload error", str(e))

    def on_download(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if not (username and password):
            messagebox.showwarning("Auth required", "Enter username & password")
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select file", "Choose a file in the list first")
            return
        file_id = self.tree.item(sel[0])["values"][0]
        dest_dir = filedialog.askdirectory(title="Select folder to save decrypted file")
        if not dest_dir:
            return
        try:
            out_file = download_file_gui(username, password, file_id, dest_dir)
            messagebox.showinfo("Downloaded", f"File saved to: {out_file}")
        except PermissionError as pe:
            messagebox.showerror("Permission denied", str(pe))
        except FileNotFoundError as fnf:
            messagebox.showerror("Not found", str(fnf))
        except Exception as e:
            messagebox.showerror("Download error", str(e))

if __name__ == "__main__":
    app = SecureStoreApp()
    app.mainloop()
