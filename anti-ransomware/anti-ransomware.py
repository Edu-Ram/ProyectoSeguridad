import os
import psutil
import win32evtlog
import win32evtlogutil
import win32con
import win32api
import time
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import hashlib
from pathlib import Path
import wmi


class RansomwareDetector:
    def __init__(self):
        self.is_monitoring = False
        self.detected_processes = set()
        self.file_activity_log = defaultdict(lambda: deque(maxlen=100))
        self.suspicious_extensions = [
            '.locked', '.encrypted', '.crypto', '.vault']
        self.monitoring_thread = None
        self.wmi_client = wmi.WMI()

        # Umbrales de detección
        # archivos modificados en ventana de tiempo
        self.RAPID_FILE_CHANGES_THRESHOLD = 10
        self.TIME_WINDOW_SECONDS = 30  # ventana de tiempo para detectar actividad sospechosa
        # Cambio mínimo en tamaño de archivo (porcentaje)
        self.MIN_FILE_SIZE_CHANGE = 0.1

        # Cola para almacenar eventos recientes
        self.recent_events = deque(maxlen=1000)

        # GUI
        self.setup_gui()

    def setup_gui(self):
        """Configura la interfaz gráfica"""
        self.root = tk.Tk()
        self.root.title("Sistema de Detección Autónoma de Ransomware")
        self.root.geometry("900x700")
        self.root.configure(bg="#2c3e50")

        # Marco principal
        main_frame = tk.Frame(self.root, bg="#2c3e50")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Título
        title_label = tk.Label(
            main_frame,
            text="🛡️ DETECTOR DE RANSOMWARE AUTÓNOMO",
            font=("Arial", 18, "bold"),
            fg="#ecf0f1",
            bg="#2c3e50"
        )
        title_label.pack(pady=10)

        # Estado del sistema
        self.status_frame = tk.Frame(
            main_frame, bg="#34495e", relief=tk.RAISED, bd=2)
        self.status_frame.pack(fill=tk.X, pady=5)

        self.status_label = tk.Label(
            self.status_frame,
            text="🔴 SISTEMA DETENIDO",
            font=("Arial", 14, "bold"),
            fg="#e74c3c",
            bg="#34495e"
        )
        self.status_label.pack(pady=10)

        # Botones de control
        button_frame = tk.Frame(main_frame, bg="#2c3e50")
        button_frame.pack(fill=tk.X, pady=10)

        self.start_button = tk.Button(
            button_frame,
            text="🚀 INICIAR MONITOREO",
            font=("Arial", 12, "bold"),
            bg="#27ae60",
            fg="white",
            relief=tk.FLAT,
            padx=20,
            pady=10,
            command=self.start_monitoring
        )
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(
            button_frame,
            text="⏹️ DETENER MONITOREO",
            font=("Arial", 12, "bold"),
            bg="#e74c3c",
            fg="white",
            relief=tk.FLAT,
            padx=20,
            pady=10,
            command=self.stop_monitoring
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Estadísticas
        stats_frame = tk.Frame(main_frame, bg="#34495e",
                               relief=tk.RAISED, bd=2)
        stats_frame.pack(fill=tk.X, pady=5)

        tk.Label(
            stats_frame,
            text="📊 ESTADÍSTICAS DEL SISTEMA",
            font=("Arial", 12, "bold"),
            fg="#ecf0f1",
            bg="#34495e"
        ).pack(pady=5)

        self.stats_text = tk.Text(
            stats_frame,
            height=4,
            font=("Consolas", 10),
            bg="#2c3e50",
            fg="#ecf0f1",
            relief=tk.FLAT
        )
        self.stats_text.pack(fill=tk.X, padx=10, pady=5)

        # Log de eventos
        log_frame = tk.Frame(main_frame, bg="#34495e", relief=tk.RAISED, bd=2)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        tk.Label(
            log_frame,
            text="📋 LOG DE EVENTOS Y DETECCIONES",
            font=("Arial", 12, "bold"),
            fg="#ecf0f1",
            bg="#34495e"
        ).pack(pady=5)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            font=("Consolas", 9),
            bg="#1c2833",
            fg="#ecf0f1",
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Inicializar logs
        self.log_event("🔧 Sistema de detección inicializado", "INFO")
        self.update_stats()

    def log_event(self, message, level="INFO"):
        """Registra un evento en el log con timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Colores por nivel
        colors = {
            "INFO": "#3498db",
            "WARNING": "#f39c12",
            "ERROR": "#e74c3c",
            "CRITICAL": "#8e44ad",
            "SUCCESS": "#27ae60"
        }

        log_entry = f"[{timestamp}] [{level}] {message}\n"

        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.root.update_idletasks()

        # Guardar en cola de eventos recientes
        self.recent_events.append({
            'timestamp': datetime.now(),
            'level': level,
            'message': message
        })

    def update_stats(self):
        """Actualiza las estadísticas del sistema"""
        if hasattr(self, 'stats_text'):
            self.stats_text.delete(1.0, tk.END)

            stats = f"""Procesos monitoreados: {len([p for p in psutil.process_iter()])}
Eventos recientes: {len(self.recent_events)}
Procesos sospechosos detectados: {len(self.detected_processes)}
Estado: {'🟢 ACTIVO' if self.is_monitoring else '🔴 INACTIVO'}"""

            self.stats_text.insert(1.0, stats)

    def start_monitoring(self):
        """Inicia el monitoreo del sistema"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.status_label.config(
                text="🟢 SISTEMA ACTIVO - MONITOREANDO", fg="#27ae60")
            self.log_event(
                "🚀 Monitoreo iniciado - Escaneando sistema cada 2 segundos", "SUCCESS")

            # Iniciar hilo de monitoreo
            self.monitoring_thread = threading.Thread(
                target=self.monitor_system, daemon=True)
            self.monitoring_thread.start()

            # Actualizar estadísticas periódicamente
            self.update_stats_loop()

    def stop_monitoring(self):
        """Detiene el monitoreo del sistema"""
        self.is_monitoring = False
        self.status_label.config(text="🔴 SISTEMA DETENIDO", fg="#e74c3c")
        self.log_event("⏹️ Monitoreo detenido por el usuario", "WARNING")
        self.update_stats()

    def update_stats_loop(self):
        """Loop para actualizar estadísticas periódicamente"""
        if self.is_monitoring:
            self.update_stats()
            # Actualizar cada 2 segundos
            self.root.after(2000, self.update_stats_loop)

    def monitor_system(self):
        """Hilo principal de monitoreo del sistema"""
        self.log_event(
            "🔍 Iniciando monitoreo continuo de archivos y procesos", "INFO")

        while self.is_monitoring:
            try:
                # Monitorear logs de Windows
                self.check_windows_logs()

                # Monitorear procesos sospechosos
                self.monitor_processes()

                # Verificar patrones de comportamiento
                self.analyze_suspicious_patterns()

                # Escanear más rápido que el ransomware (cada 2 segundos vs 5)
                time.sleep(2)

            except Exception as e:
                self.log_event(f"❌ Error en monitoreo: {str(e)}", "ERROR")
                time.sleep(5)

    def check_windows_logs(self):
        """Monitorea los logs de eventos de Windows para detectar actividad sospechosa"""
        try:
            # Monitorear Security Log para cambios en archivos
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events = win32evtlog.ReadEventLog(hand, flags, 0)

            for event in events[:50]:  # Revisar solo eventos recientes
                # Event ID 4663: Intento de acceso a objeto (archivos)
                # Event ID 4656: Handle a un objeto solicitado
                if event.EventID in [4663, 4656]:
                    self.analyze_file_access_event(event)

            win32evtlog.CloseEventLog(hand)

        except Exception as e:
            # Log silencioso ya que puede haber muchos errores de permisos
            pass

    def analyze_file_access_event(self, event):
        """Analiza eventos de acceso a archivos para detectar patrones sospechosos"""
        try:
            # Extraer información del evento
            event_time = event.TimeGenerated

            # Si el evento es muy reciente (últimos 30 segundos)
            if (datetime.now() - event_time).total_seconds() < 30:
                # Registrar actividad de archivos reciente
                self.recent_events.append({
                    'timestamp': event_time,
                    'type': 'file_access',
                    'event_id': event.EventID
                })

        except Exception as e:
            pass

    def monitor_processes(self):
        """Monitorea procesos en busca de comportamiento sospechoso"""
        try:
            current_processes = {}

            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'open_files']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    name = proc_info['name']

                    # Verificar si es un proceso de Python (potencial ransomware)
                    if 'python' in name.lower():
                        self.analyze_python_process(proc, proc_info)

                    current_processes[pid] = proc_info

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            self.log_event(
                f"⚠️ Error monitoreando procesos: {str(e)}", "WARNING")

    def analyze_python_process(self, proc, proc_info):
        """Analiza procesos de Python en busca de actividad sospechosa"""
        try:
            pid = proc_info['pid']

            # Obtener archivos abiertos por el proceso
            try:
                open_files = proc.open_files()

                # Buscar patrones sospechosos en archivos abiertos
                suspicious_activity = 0

                for file_info in open_files:
                    file_path = file_info.path.lower()

                    # Detectar si está accediendo a muchos archivos diferentes
                    if any(ext in file_path for ext in ['.txt', '.doc', '.pdf', '.jpg', '.png']):
                        suspicious_activity += 1

                    # Detectar extensiones de cifrado
                    if any(ext in file_path for ext in self.suspicious_extensions):
                        suspicious_activity += 10
                        self.log_event(
                            f"🚨 ARCHIVO CIFRADO DETECTADO: {file_path}", "CRITICAL")

                # Si hay actividad sospechosa alta, marcar el proceso
                if suspicious_activity > 5:
                    if pid not in self.detected_processes:
                        self.detected_processes.add(pid)
                        self.log_event(
                            f"🔍 Proceso sospechoso detectado: PID {pid} - Actividad: {suspicious_activity}", "WARNING")

                        # Si la actividad es crítica, tomar acción
                        if suspicious_activity > 15:
                            self.take_action_against_process(proc, pid)

            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

        except Exception as e:
            pass

    def analyze_suspicious_patterns(self):
        """Analiza patrones generales de comportamiento sospechoso"""
        now = datetime.now()
        recent_threshold = now - timedelta(seconds=self.TIME_WINDOW_SECONDS)

        # Contar eventos recientes de diferentes tipos
        recent_file_events = [
            e for e in self.recent_events if e['timestamp'] > recent_threshold]

        if len(recent_file_events) > self.RAPID_FILE_CHANGES_THRESHOLD:
            self.log_event(
                f"⚠️ PATRÓN SOSPECHOSO: {len(recent_file_events)} eventos de archivos en {self.TIME_WINDOW_SECONDS}s", "WARNING")

            # Buscar procesos responsables
            self.investigate_recent_activity()

    def investigate_recent_activity(self):
        """Investiga la actividad reciente para identificar procesos responsables"""
        try:
            # Buscar procesos de Python activos que podrían ser ransomware
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'python' in proc.info['name'].lower():
                        cmdline = proc.info.get('cmdline', [])

                        # Buscar indicadores de ransomware en la línea de comandos
                        cmdline_str = ' '.join(cmdline).lower()

                        suspicious_keywords = [
                            'encrypt', 'cipher', 'aes', 'ransom', 'lock']
                        if any(keyword in cmdline_str for keyword in suspicious_keywords):
                            self.log_event(
                                f"🚨 RANSOMWARE POTENCIAL DETECTADO: PID {proc.info['pid']}", "CRITICAL")
                            self.take_action_against_process(
                                proc, proc.info['pid'])

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            self.log_event(
                f"❌ Error investigando actividad: {str(e)}", "ERROR")

    def take_action_against_process(self, proc, pid):
        """Toma acción contra un proceso sospechoso"""
        try:
            proc_name = proc.name()
            self.log_event(
                f"🛡️ INICIANDO CONTENCIÓN DE PROCESO: {proc_name} (PID: {pid})", "CRITICAL")

            # Mostrar alerta crítica
            self.show_critical_alert(proc_name, pid)

            # Intentar terminar el proceso
            try:
                proc.terminate()
                time.sleep(2)

                if proc.is_running():
                    proc.kill()

                self.log_event(
                    f"✅ PROCESO ELIMINADO EXITOSAMENTE: {proc_name} (PID: {pid})", "SUCCESS")

                # Mostrar notificación de éxito
                self.root.after(0, lambda: messagebox.showinfo(
                    "🛡️ RANSOMWARE BLOQUEADO",
                    f"¡Proceso malicioso eliminado!\n\nProceso: {proc_name}\nPID: {pid}\n\n¡Su sistema está protegido!"
                ))

            except Exception as e:
                self.log_event(
                    f"❌ Error eliminando proceso {pid}: {str(e)}", "ERROR")

        except Exception as e:
            self.log_event(f"❌ Error en contención: {str(e)}", "ERROR")

    def show_critical_alert(self, proc_name, pid):
        """Muestra una alerta crítica de ransomware detectado"""
        def show_alert():
            alert_window = tk.Toplevel(self.root)
            alert_window.title("🚨 ALERTA CRÍTICA")
            alert_window.geometry("500x300")
            alert_window.configure(bg="#c0392b")
            alert_window.attributes("-topmost", True)

            tk.Label(
                alert_window,
                text="🚨 RANSOMWARE DETECTADO 🚨",
                font=("Arial", 20, "bold"),
                fg="white",
                bg="#c0392b"
            ).pack(pady=20)

            tk.Label(
                alert_window,
                text=f"Proceso malicioso identificado:\n{proc_name} (PID: {pid})\n\nSe está procediendo a la contención automática...",
                font=("Arial", 12),
                fg="white",
                bg="#c0392b",
                wraplength=400
            ).pack(pady=20)

            tk.Button(
                alert_window,
                text="ENTENDIDO",
                font=("Arial", 14, "bold"),
                bg="#27ae60",
                fg="white",
                relief=tk.FLAT,
                padx=30,
                pady=10,
                command=alert_window.destroy
            ).pack(pady=20)

        self.root.after(0, show_alert)

    def run(self):
        """Ejecuta la aplicación"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        """Maneja el cierre de la aplicación"""
        self.is_monitoring = False
        self.log_event("👋 Cerrando sistema de detección", "INFO")
        self.root.destroy()


if __name__ == "__main__":
    # Verificar permisos de administrador
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            print("⚠️ ADVERTENCIA: Se recomienda ejecutar como administrador para acceso completo a logs del sistema")
    except:
        pass

    print("🛡️ Iniciando Sistema de Detección Autónoma de Ransomware...")
    print("📋 Monitoreo de:")
    print("   • Logs de eventos de Windows")
    print("   • Procesos del sistema")
    print("   • Patrones de acceso a archivos")
    print("   • Extensiones de cifrado sospechosas")
    print("\n🚀 Cargando interfaz gráfica...")

    detector = RansomwareDetector()
    detector.run()
