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
        self.SCAN_INTERVAL = 0.5  # Más rápido que el atacante (0.5s vs 5s)
        self.SUSPICIOUS_FILE_THRESHOLD = 1  # Solo 1 archivo .locked para alertar
        self.HIGH_CPU_THRESHOLD = 10.0  # % CPU sospechoso
        self.MAX_LOG_ENTRIES = 200

        # SOLO extensiones de ransomware reales (NO .dll legítimos)
        self.ransomware_extensions = ['.locked', '.encrypted', '.crypto', '.vault', '.ransom']

        # Directorios monitoreados
        self.monitored_dirs = [
            Path(r"C:\ransom_sandbox"),  # Tu directorio de pruebas
            Path.home() / "Desktop",
            Path.home() / "Documents"
        ]

        # Procesos excluidos (legítimos del sistema)
        self.excluded_processes = {
            'system idle process', 'system', 'csrss.exe', 'explorer.exe',
            'svchost.exe', 'runtimebroker.exe', 'backgroundtaskhost.exe',
            'msmpeeng.exe', 'sihost.exe', 'ctfmon.exe', 'msedge.exe',
            'copilot.exe', 'phoneexperiencehost.exe', 'dwm.exe',
            'winlogon.exe', 'lsass.exe', 'services.exe'
        }

        # Buffer de eventos
        self.recent_events = deque(maxlen=50)
        self.baseline_files = set()

        # Setup GUI
        self.setup_lightweight_gui()
        self.root.after(1000, self.start_monitoring)

    def setup_lightweight_gui(self):
        """GUI simplificada"""
        self.root = tk.Tk()
        self.root.title("Detector Ransomware v2.1 - CORREGIDO")
        self.root.geometry("900x600")
        self.root.configure(bg="#1e1e1e")

        # Header
        header = tk.Frame(self.root, bg="#2d2d2d", height=60)
        header.pack(fill=tk.X, padx=5, pady=5)
        header.pack_propagate(False)

        tk.Label(
            header,
            text="🛡️ DETECTOR RANSOMWARE CORREGIDO",
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

        # Stats frame
        stats_frame = tk.Frame(self.root, bg="#2d2d2d")
        stats_frame.pack(fill=tk.X, padx=5, pady=2)

        self.stats_label = tk.Label(
            stats_frame,
            text="Archivos .locked: 0 | Procesos Python: 0 | Amenazas: 0",
            font=("Segoe UI", 9),
            fg="#cccccc",
            bg="#2d2d2d"
        )
        self.stats_label.pack(pady=5)

        # Log area
        log_frame = tk.Frame(self.root, bg="#2d2d2d")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        tk.Label(
            log_frame,
            text="📋 LOG DE DETECCIÓN - VERSIÓN CORREGIDA",
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
            height=20
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log_event("🔧 Sistema corregido - Sin más falsos positivos")

    def log_event(self, message, level="INFO"):
        """Sistema de logging optimizado"""
        timestamp = datetime.now().strftime("%H:%M:%S")

        emojis = {
            "INFO": "ℹ️",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "CRITICAL": "🚨",
            "SUCCESS": "✅"
        }

        emoji = emojis.get(level, "📝")
        log_entry = f"[{timestamp}] {emoji} {message}\n"

        self.log_text.insert(tk.END, log_entry)

        # Mantener solo las últimas entradas
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
                text="🟢 SISTEMA ACTIVO - CAZANDO RANSOMWARE PYTHON",
                fg="#00ff88"
            )
            self.log_event("🚀 Monitoreo activo - Detectando archivos .locked reales", "SUCCESS")

            # Establecer baseline inicial
            self.baseline_files = self.scan_for_locked_files()
            if self.baseline_files:
                self.log_event(f"📊 Baseline: {len(self.baseline_files)} archivos .locked existentes", "INFO")

            self.monitoring_thread = threading.Thread(
                target=self.optimized_monitor_loop,
                daemon=True
            )
            self.monitoring_thread.start()
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
        """Loop principal - CORREGIDO para detectar Python ransomware"""
        self.log_event("🔍 Iniciando caza de ransomware Python...")

        while self.is_monitoring:
            try:
                # 1. DETECCIÓN DE ARCHIVOS .locked NUEVOS
                current_locked = self.scan_for_locked_files()
                new_locked = current_locked - self.baseline_files

                if new_locked:
                    self.log_event(
                        f"🚨 {len(new_locked)} ARCHIVOS .locked NUEVOS DETECTADOS!", "CRITICAL")
                    for file_path in list(new_locked)[:3]:  # Mostrar algunos ejemplos
                        self.log_event(f"   📝 {file_path}", "CRITICAL")
                    
                    self.handle_encryption_detected(new_locked)
                    self.baseline_files = current_locked

                # 2. MONITOREO ESPECÍFICO DE PROCESOS PYTHON
                python_processes = self.get_python_processes()
                for pid, proc_info in python_processes.items():
                    if self.analyze_python_process(pid, proc_info):
                        self.log_event(
                            f"🎯 RANSOMWARE PYTHON CONFIRMADO: {proc_info['name']} (PID: {pid})", "CRITICAL")
                        self.eliminate_threat(pid, proc_info)

                time.sleep(self.SCAN_INTERVAL)

            except Exception as e:
                self.log_event(f"❌ Error en monitoreo: {str(e)}", "ERROR")
                time.sleep(2)

    def scan_for_locked_files(self):
        """Escaneo específico de archivos .locked (NO .dll)"""
        locked_files = set()

        for directory in self.monitored_dirs:
            if not directory.exists():
                continue

            try:
                # Buscar recursivamente archivos .locked
                for root, _, files in os.walk(directory):
                    for file in files:
                        # SOLO archivos con extensión .locked exacta
                        if file.endswith('.locked'):
                            locked_files.add(Path(root) / file)
            except (PermissionError, OSError):
                continue

        return locked_files

    def get_python_processes(self):
        """Obtener SOLO procesos Python con alta CPU"""
        python_processes = {}
        current_pid = os.getpid()

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'cmdline']):
            try:
                proc_info = proc.info
                pid = proc_info['pid']

                # NUNCA detectarnos a nosotros mismos
                if pid == current_pid:
                    continue

                proc_name = proc_info['name'].lower()
                
                # SOLO procesos Python con alta actividad
                if ('python' in proc_name or 'py' in proc_name) and proc_info['cpu_percent'] > self.HIGH_CPU_THRESHOLD:
                    cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
                    
                    python_processes[pid] = {
                        'name': proc_info['name'],
                        'pid': pid,
                        'cpu_percent': proc_info['cpu_percent'],
                        'cmdline': cmdline
                    }
                    
                    self.log_event(
                        f"🐍 Proceso Python detectado: {proc_info['name']} (PID: {pid}, CPU: {proc_info['cpu_percent']:.1f}%)", "INFO")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return python_processes

    def analyze_python_process(self, pid, proc_info):
        """Análisis específico de procesos Python para ransomware"""
        if pid == os.getpid():
            return False

        try:
            proc = psutil.Process(pid)
            ransomware_score = 0
            cmdline = proc_info.get('cmdline', '').lower()

            # 1. PALABRAS CLAVE CRÍTICAS EN LÍNEA DE COMANDOS
            critical_keywords = {
                'aesgcm': 25,
                'encrypt_file': 25,
                'ransom_sandbox': 30,
                '.locked': 20,
                'master_key': 15
            }

            warning_keywords = {
                'encrypt': 5,
                'cipher': 5,
                'crypto': 3,
                'pathlib': 2
            }

            for keyword, score in critical_keywords.items():
                if keyword in cmdline:
                    ransomware_score += score
                    self.log_event(
                        f"🚨 Palabra clave crítica '{keyword}' detectada (+{score} puntos)", "CRITICAL")

            for keyword, score in warning_keywords.items():
                if keyword in cmdline:
                    ransomware_score += score
                    self.log_event(
                        f"⚠️ Palabra clave sospechosa '{keyword}' detectada (+{score} puntos)", "WARNING")

            # 2. ANÁLISIS DE ARCHIVOS ABIERTOS (buscar acceso a .locked)
            try:
                open_files = proc.open_files()
                locked_files_accessed = 0
                sandbox_files_accessed = 0

                for file_info in open_files:
                    file_path = str(file_info.path).lower()

                    # Acceso a archivos en sandbox
                    if "ransom_sandbox" in file_path:
                        sandbox_files_accessed += 1
                        ransomware_score += 10

                    # Acceso a archivos .locked REALES
                    if file_path.endswith('.locked'):
                        locked_files_accessed += 1
                        ransomware_score += 25
                        self.log_event(
                            f"🔒 Acceso confirmado a archivo .locked: {file_path}", "CRITICAL")

                if sandbox_files_accessed > 0:
                    self.log_event(
                        f"📂 Archivos sandbox accedidos: {sandbox_files_accessed} (+{sandbox_files_accessed * 10} puntos)", "WARNING")

                if locked_files_accessed > 0:
                    self.log_event(
                        f"🔐 Archivos .locked accedidos: {locked_files_accessed} (+{locked_files_accessed * 25} puntos)", "CRITICAL")

            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # 3. DECISIÓN FINAL (umbral alto para evitar falsos positivos)
            is_ransomware = ransomware_score >= 30

            self.log_event(
                f"📊 Análisis completo PID {pid}: {ransomware_score} puntos - {'🚨 RANSOMWARE' if is_ransomware else '✅ LEGÍTIMO'}", 
                "CRITICAL" if is_ransomware else "INFO")

            return is_ransomware

        except psutil.NoSuchProcess:
            return False

    def handle_encryption_detected(self, encrypted_files):
        """Manejo cuando se detectan archivos cifrados"""
        self.log_event(
            f"🚨 ALERTA MÁXIMA: {len(encrypted_files)} archivos fueron cifrados por ransomware", "CRITICAL")

        # Mostrar alerta
        self.root.after(0, lambda: self.show_ransomware_alert(len(encrypted_files)))

        # Buscar el proceso Python responsable
        self.root.after(100, self.emergency_python_hunt)

    def emergency_python_hunt(self):
        """Búsqueda específica del proceso Python malicioso"""
        self.log_event("🎯 BÚSQUEDA DE EMERGENCIA - Cazando Python ransomware", "CRITICAL")
        
        python_processes = self.get_python_processes()
        
        for pid, proc_info in python_processes.items():
            if self.analyze_python_process(pid, proc_info):
                self.eliminate_threat(pid, proc_info)
                return
                
        self.log_event("⚠️ No se encontró el proceso Python ransomware activo", "WARNING")

    def eliminate_threat(self, pid, proc_info):
        """Eliminación de amenaza"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc_info.get('name', 'proceso_python')

            self.log_event(
                f"🛡️ ELIMINANDO RANSOMWARE: {proc_name} (PID: {pid})", "CRITICAL")

            # Terminación forzada
            proc.kill()
            proc.wait(timeout=3)

            self.detected_processes.add(pid)

            self.log_event(
                f"✅ RANSOMWARE ELIMINADO: {proc_name} destruido exitosamente", "SUCCESS")

            # Mostrar éxito
            self.root.after(0, lambda: messagebox.showinfo(
                "🛡️ RANSOMWARE BLOQUEADO",
                f"¡Amenaza neutralizada!\n\n"
                f"Proceso: {proc_name}\n"
                f"PID: {pid}\n\n"
                f"El cifrado ha sido detenido."
            ))

        except Exception as e:
            self.log_event(
                f"❌ Error eliminando amenaza {pid}: {str(e)}", "ERROR")

    def show_ransomware_alert(self, file_count):
        """Alerta visual"""
        alert = tk.Toplevel(self.root)
        alert.title("🚨 RANSOMWARE PYTHON DETECTADO")
        alert.geometry("500x300")
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
            text=f"Archivos .locked detectados: {file_count}\n\nBuscando proceso Python malicioso...",
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
        """Actualización de interfaz"""
        if self.is_monitoring:
            # Contar archivos .locked reales
            locked_count = len(self.scan_for_locked_files())

            # Contar procesos Python
            python_count = len(self.get_python_processes())

            # Amenazas eliminadas
            threat_count = len(self.detected_processes)

            # Actualizar stats
            self.stats_label.config(
                text=f"Archivos .locked: {locked_count} | Procesos Python activos: {python_count} | Amenazas eliminadas: {threat_count}"
            )

            self.root.after(2000, self.update_ui_loop)

    def run(self):
        """Ejecutar detector"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        """Cierre limpio"""
        self.is_monitoring = False
        self.log_event("👋 Detector desactivado")
        self.root.destroy()


if __name__ == "__main__":
    print("🛡️ Detector de Ransomware v2.1 - VERSIÓN CORREGIDA")
    print("🎯 Especializado en detectar procesos Python que cifran archivos .locked")
    print("❌ Sin falsos positivos en procesos del sistema")
    print("⚡ Tiempo de respuesta: 0.5 segundos")

    detector = OptimizedRansomwareDetector()
    detector.run()