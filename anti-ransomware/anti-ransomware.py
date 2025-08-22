import os
import psutil
import time
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from collections import deque
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
import queue


class OptimizedRansomwareDetector:
    def __init__(self):
        self.is_monitoring = False
        self.detected_processes = set()
        self.monitoring_thread = None
        self.event_queue = queue.Queue()

        # Configuración optimizada
        # Escaneo cada 1 segundo (más rápido que el atacante)
        self.SCAN_INTERVAL = 1.0
        self.SUSPICIOUS_FILE_THRESHOLD = 3  # Archivos .locked para alertar
        self.HIGH_CPU_THRESHOLD = 15.0  # % CPU sospechoso para procesos Python
        self.MAX_LOG_ENTRIES = 200  # Limitar logs para mejor rendimiento

        # Extensiones sospechosas prioritarias
        self.ransomware_extensions = [
            '.locked', '.encrypted', '.crypto', '.vault']

        # Directorios monitoreados (optimizado para sandbox)
        self.monitored_dirs = [
            Path(r"C:\ransom_sandbox"),  # Tu directorio de pruebas
            Path.home() / "Desktop",      # Solo Desktop del usuario
            Path.home() / "Documents"     # Solo Documents del usuario
        ]

        # Buffer de eventos ligero
        self.recent_events = deque(maxlen=50)

        # Setup GUI optimizado
        self.setup_lightweight_gui()

        # Auto-inicio del monitoreo
        self.root.after(1000, self.start_monitoring)

    def setup_lightweight_gui(self):
        """GUI simplificada para mejor rendimiento"""
        self.root = tk.Tk()
        self.root.title("Detector Ransomware v2.0 - Optimizado")
        self.root.geometry("800x500")
        self.root.configure(bg="#1e1e1e")

        # Header
        header = tk.Frame(self.root, bg="#2d2d2d", height=60)
        header.pack(fill=tk.X, padx=5, pady=5)
        header.pack_propagate(False)

        tk.Label(
            header,
            text="🛡️ DETECTOR RANSOMWARE OPTIMIZADO",
            font=("Segoe UI", 16, "bold"),
            fg="#00ff88",
            bg="#2d2d2d"
        ).pack(pady=15)

        # Status bar
        self.status_frame = tk.Frame(self.root, bg="#404040", height=40)
        self.status_frame.pack(fill=tk.X, padx=5, pady=2)
        self.status_frame.pack_propagate(False)

        self.status_label = tk.Label(
            self.status_frame,
            text="🔴 PREPARANDO SISTEMA...",
            font=("Segoe UI", 10, "bold"),
            fg="#ff4444",
            bg="#404040"
        )
        self.status_label.pack(pady=8)

        # Control buttons
        btn_frame = tk.Frame(self.root, bg="#1e1e1e")
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        self.start_btn = tk.Button(
            btn_frame,
            text="▶ INICIAR",
            font=("Segoe UI", 10, "bold"),
            bg="#28a745",
            fg="white",
            command=self.start_monitoring,
            relief=tk.FLAT,
            padx=15
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(
            btn_frame,
            text="⏹ DETENER",
            font=("Segoe UI", 10, "bold"),
            bg="#dc3545",
            fg="white",
            command=self.stop_monitoring,
            relief=tk.FLAT,
            padx=15
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Stats (simplified)
        stats_frame = tk.Frame(self.root, bg="#2d2d2d")
        stats_frame.pack(fill=tk.X, padx=5, pady=2)

        self.stats_label = tk.Label(
            stats_frame,
            text="Archivos monitoreados: 0 | Procesos escaneados: 0 | Amenazas: 0",
            font=("Segoe UI", 9),
            fg="#cccccc",
            bg="#2d2d2d"
        )
        self.stats_label.pack(pady=5)

        # Log area (optimized)
        log_frame = tk.Frame(self.root, bg="#2d2d2d")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        tk.Label(
            log_frame,
            text="📋 LOG DE DETECCIÓN",
            font=("Segoe UI", 11, "bold"),
            fg="#ffffff",
            bg="#2d2d2d"
        ).pack(anchor=tk.W, pady=(5, 2))

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            font=("Consolas", 9),
            bg="#0d1117",
            fg="#f0f6fc",
            relief=tk.FLAT,
            wrap=tk.WORD,
            height=15
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log_event(
            "🔧 Sistema optimizado inicializado - Listo para detectar amenazas")

    def log_event(self, message, level="INFO"):
        """Sistema de logging optimizado"""
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Emoji por nivel para identificación rápida
        emojis = {
            "INFO": "ℹ️",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "CRITICAL": "🚨",
            "SUCCESS": "✅"
        }

        emoji = emojis.get(level, "📝")
        log_entry = f"[{timestamp}] {emoji} {message}\n"

        # Añadir al log con límite
        self.log_text.insert(tk.END, log_entry)

        # Mantener solo las últimas entradas para rendimiento
        lines = int(self.log_text.index('end-1c').split('.')[0])
        if lines > self.MAX_LOG_ENTRIES:
            self.log_text.delete("1.0", f"{lines - self.MAX_LOG_ENTRIES}.0")

        self.log_text.see(tk.END)

        # Agregar a eventos recientes
        self.recent_events.append({
            'timestamp': datetime.now(),
            'level': level,
            'message': message
        })

    def start_monitoring(self):
        """Iniciar monitoreo optimizado"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.status_label.config(
                text="🟢 SISTEMA ACTIVO - MONITOREANDO AMENAZAS",
                fg="#00ff88"
            )
            self.log_event(
                "🚀 Monitoreo activo - Escaneando cada segundo", "SUCCESS")

            # Thread optimizado para monitoreo
            self.monitoring_thread = threading.Thread(
                target=self.optimized_monitor_loop,
                daemon=True
            )
            self.monitoring_thread.start()

            # Update stats every 2 seconds
            self.update_ui_loop()

    def stop_monitoring(self):
        """Detener monitoreo"""
        self.is_monitoring = False
        self.status_label.config(
            text="🔴 SISTEMA DETENIDO",
            fg="#ff4444"
        )
        self.log_event("⏹️ Monitoreo detenido", "WARNING")

    def optimized_monitor_loop(self):
        """Loop principal optimizado - Detecta más rápido que el atacante"""
        self.log_event("🔍 Iniciando detección de alta velocidad")

        # Baseline inicial
        baseline_files = self.scan_for_encrypted_files()
        suspicious_processes = set()  # PIDs de procesos sospechosos

        while self.is_monitoring:
            try:
                # 1. DETECCIÓN RÁPIDA DE ARCHIVOS CIFRADOS
                current_encrypted = self.scan_for_encrypted_files()
                new_encrypted = current_encrypted - baseline_files

                if new_encrypted:
                    self.log_event(
                        f"🚨 {len(new_encrypted)} ARCHIVOS CIFRADOS DETECTADOS!", "CRITICAL")
                    self.handle_encryption_detected(new_encrypted)
                    baseline_files = current_encrypted

                # 2. MONITOREO DE PROCESOS CON ACTIVIDAD SOSPECHOSA
                current_suspicious_procs = self.get_suspicious_processes()
                new_procs = current_suspicious_procs - suspicious_processes

                for pid in new_procs:
                    try:
                        proc = psutil.Process(pid)
                        proc_info = {'name': proc.name(), 'pid': pid}
                        self.log_event(
                            f"🔍 Proceso con alta CPU: {proc_info['name']} (PID: {pid})", "INFO")

                        # Solo alertar si realmente está cifrando archivos
                        if self.analyze_process_behavior(pid, proc_info):
                            self.log_event(
                                f"🚨 RANSOMWARE CONFIRMADO: {proc_info['name']} (PID: {pid})", "CRITICAL")
                            self.eliminate_threat(pid, proc_info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                suspicious_processes = current_suspicious_procs

                # Dormir menos tiempo que el atacante (1s vs 5s del atacante)
                time.sleep(self.SCAN_INTERVAL)

            except Exception as e:
                self.log_event(f"❌ Error en monitoreo: {str(e)}", "ERROR")
                time.sleep(2)

    def scan_for_encrypted_files(self):
        """Escaneo ultra-rápido de archivos cifrados"""
        encrypted_files = set()

        for directory in self.monitored_dirs:
            if not directory.exists():
                continue

            try:
                # Escaneo rápido solo en directorio principal + subdirectorios inmediatos
                for item in directory.iterdir():
                    if item.is_file() and any(str(item).endswith(ext) for ext in self.ransomware_extensions):
                        encrypted_files.add(item)
                    elif item.is_dir():
                        # Solo 1 nivel de profundidad para velocidad
                        try:
                            for subitem in item.iterdir():
                                if subitem.is_file() and any(str(subitem).endswith(ext) for ext in self.ransomware_extensions):
                                    encrypted_files.add(subitem)
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue

        return encrypted_files

    def get_suspicious_processes(self):
        """Obtener procesos con comportamiento sospechoso de cifrado"""
        suspicious_procs = set()
        current_pid = os.getpid()  # PID de este detector para excluirlo

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                proc_info = proc.info
                pid = proc_info['pid']

                # NUNCA detectar a nosotros mismos
                if pid == current_pid:
                    continue

                # Solo procesos con alta actividad de CPU (indicativo de cifrado)
                if proc_info['cpu_percent'] > self.HIGH_CPU_THRESHOLD:
                    suspicious_procs.add(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return suspicious_procs

    def analyze_process_behavior(self, pid, proc_info):
        """Análisis específico de comportamiento de cifrado - NO solo por ser Python"""
        if pid == os.getpid():  # NUNCA analizarnos a nosotros mismos
            return False

        try:
            proc = psutil.Process(pid)
            ransomware_score = 0

            # 1. Verificar archivos abiertos para cifrado REAL
            try:
                open_files = proc.open_files()
                encrypted_files_accessed = 0
                sandbox_files_accessed = 0

                for file_info in open_files:
                    file_path = str(file_info.path).lower()

                    # Detectar acceso a archivos en sandbox (fuerte indicador)
                    if "ransom_sandbox" in file_path:
                        sandbox_files_accessed += 1
                        ransomware_score += 5

                    # Detectar archivos .locked (confirmación de ransomware)
                    if any(ext in file_path for ext in self.ransomware_extensions):
                        encrypted_files_accessed += 1
                        ransomware_score += 20  # Puntuación muy alta
                        self.log_event(
                            f"🎯 Acceso a archivo cifrado: {file_path}", "CRITICAL")

                # Log de actividad detectada
                if sandbox_files_accessed > 0:
                    self.log_event(
                        f"📁 Archivos sandbox accedidos: {sandbox_files_accessed}", "WARNING")
                if encrypted_files_accessed > 0:
                    self.log_event(
                        f"🔒 Archivos .locked accedidos: {encrypted_files_accessed}", "CRITICAL")

            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # 2. Verificar línea de comandos para palabras clave de cifrado
            try:
                cmdline = ' '.join(proc.cmdline()).lower()

                # Palabras clave específicas de ransomware/cifrado
                critical_keywords = [
                    'aesgcm', 'encrypt_file', '.locked', 'ransom_sandbox']
                warning_keywords = ['encrypt', 'cipher', 'crypto']

                for keyword in critical_keywords:
                    if keyword in cmdline:
                        ransomware_score += 15
                        self.log_event(
                            f"🚨 Palabra clave crítica '{keyword}' en comando", "CRITICAL")

                for keyword in warning_keywords:
                    if keyword in cmdline:
                        ransomware_score += 5
                        self.log_event(
                            f"⚠️ Palabra clave sospechosa '{keyword}' en comando", "WARNING")

            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # 3. CRITERIO DECISIVO: Solo marcar como ransomware con evidencia sólida
            # Umbral alto para evitar falsos positivos
            is_ransomware = ransomware_score >= 20

            if is_ransomware:
                self.log_event(
                    f"🎯 RANSOMWARE IDENTIFICADO - PID {pid} - Puntuación: {ransomware_score}", "CRITICAL")
            elif ransomware_score > 0:
                self.log_event(
                    f"🔍 Actividad sospechosa - PID {pid} - Puntuación: {ransomware_score}", "INFO")

            return is_ransomware

        except psutil.NoSuchProcess:
            return False

    def handle_encryption_detected(self, encrypted_files):
        """Manejo cuando se detectan archivos cifrados"""
        self.log_event(
            f"🚨 ALERTA CRÍTICA: {len(encrypted_files)} archivos fueron cifrados", "CRITICAL")

        # Mostrar alerta inmediata
        self.root.after(
            0, lambda: self.show_ransomware_alert(len(encrypted_files)))

        # Buscar y eliminar proceso responsable
        self.root.after(100, self.emergency_threat_hunt)

    def emergency_threat_hunt(self):
        """Búsqueda de emergencia del proceso malicioso"""
        self.log_event(
            "🔍 BÚSQUEDA DE EMERGENCIA - Cazando ransomware activo", "CRITICAL")
        current_pid = os.getpid()

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                if pid == current_pid:  # Saltarnos a nosotros mismos
                    continue

                proc_info = {'name': proc.info['name'], 'pid': pid}
                if self.analyze_process_behavior(pid, proc_info):
                    self.eliminate_threat(pid, proc_info)
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def eliminate_threat(self, pid, proc_info):
        """Eliminación inmediata de amenaza"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc_info.get('name', 'proceso_desconocido')

            self.log_event(
                f"🛡️ ELIMINANDO RANSOMWARE: {proc_name} (PID: {pid})", "CRITICAL")

            # Terminación forzada inmediata
            proc.kill()

            self.log_event(
                f"✅ AMENAZA ELIMINADA: {proc_name} ha sido destruido", "SUCCESS")

            # Mostrar éxito
            self.root.after(0, lambda: messagebox.showinfo(
                "🛡️ RANSOMWARE BLOQUEADO",
                f"¡Amenaza neutralizada con éxito!\n\n"
                f"Proceso eliminado: {proc_name}\n"
                f"PID: {pid}\n\n"
                f"Su sistema está protegido."
            ))

        except Exception as e:
            self.log_event(
                f"❌ Error eliminando amenaza {pid}: {str(e)}", "ERROR")

    def show_ransomware_alert(self, file_count):
        """Alerta visual de ransomware detectado"""
        alert = tk.Toplevel(self.root)
        alert.title("🚨 RANSOMWARE DETECTADO")
        alert.geometry("450x250")
        alert.configure(bg="#8b0000")
        alert.attributes("-topmost", True)

        tk.Label(
            alert,
            text="🚨 RANSOMWARE DETECTADO 🚨",
            font=("Arial", 18, "bold"),
            fg="white",
            bg="#8b0000"
        ).pack(pady=20)

        tk.Label(
            alert,
            text=f"Se detectaron {file_count} archivos cifrados\n\nEl sistema está respondiendo automáticamente...",
            font=("Arial", 12),
            fg="yellow",
            bg="#8b0000",
            justify=tk.CENTER
        ).pack(pady=10)

        tk.Button(
            alert,
            text="ENTENDIDO",
            font=("Arial", 12, "bold"),
            bg="#228b22",
            fg="white",
            command=alert.destroy,
            padx=20
        ).pack(pady=20)

    def update_ui_loop(self):
        """Actualización periódica de la interfaz"""
        if self.is_monitoring:
            # Contar archivos cifrados
            encrypted_count = len(self.scan_for_encrypted_files())

            # Contar procesos con alta CPU (no solo Python)
            high_cpu_count = len([p for p in psutil.process_iter()
                                 if p.cpu_percent() > self.HIGH_CPU_THRESHOLD and p.pid != os.getpid()])

            # Amenazas detectadas
            threat_count = len(self.detected_processes)

            # Actualizar stats
            self.stats_label.config(
                text=f"Archivos cifrados: {encrypted_count} | Procesos alta CPU: {high_cpu_count} | Amenazas neutralizadas: {threat_count}"
            )

            # Repetir cada 2 segundos
            self.root.after(2000, self.update_ui_loop)

    def run(self):
        """Ejecutar el detector"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        """Cierre limpio"""
        self.is_monitoring = False
        self.log_event("👋 Detector desactivado")
        self.root.destroy()


if __name__ == "__main__":
    print("🛡️ Iniciando Detector de Ransomware Optimizado v2.0...")
    print("⚡ Optimizado para alta velocidad y bajo consumo de recursos")
    print("🎯 Especializado en detectar cifrado de archivos .locked")
    print("🚀 Tiempo de respuesta: < 1 segundo")

    detector = OptimizedRansomwareDetector()
    detector.run()
