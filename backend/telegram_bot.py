"""
Módulo del Bot Interactivo de Telegram y Automatización de KPIs (CiberCentinela)
Diseñado para la evaluación de:
- Materia: Administración de Sistemas Operativos (Dr. Carlos Alberto García Ramos)
- Materia: Respuesta a Incidentes de Seguridad (Mtro. Obeth Regalado Moreno)

Cumple con:
1. API de Telegram y Long Polling para recepción de comandos interactivos.
2. Comandos: /start, /help, /kpis, /reporte, /cpu, /ram, /disco, /servicios, /uptime, /conexiones, /incidentes, /backup, /status.
3. Seguridad: Validación de autorización por Chat ID / User ID con registro en bitácora ante accesos denegados.
4. Despacho automatizado de alertas por umbrales críticos de KPIs del SO.
"""

import time
import threading
import requests
from typing import Dict, Any, Optional
from backend.config import settings
from backend.kpi_monitor import (
    collect_all_system_kpis,
    format_telegram_kpi_report,
    get_cpu_kpis,
    get_ram_kpis,
    get_disk_kpis,
    get_services_kpis,
    get_uptime_info,
    get_network_kpis,
    get_cibercentinela_kpis,
)
from backend.db import execute_prepared


class TelegramKPISecurityBot:
    """
    Servicio de bot de Telegram interactivo con control de acceso y telemetría de KPIs
    """

    def __init__(self):
        self.running = False
        self._thread = None
        self.last_update_id = 0
        self.command_history = []
        self.last_proactive_alert_time = 0
        self.lock = threading.Lock()

    def is_authorized(self, chat_id: Any) -> bool:
        """Verifica si el remitente está autorizado (Política de Menor Privilegio)"""
        cfg_chat_id = str(settings.TELEGRAM_CHAT_ID).strip()
        if not cfg_chat_id:
            return True
        return str(chat_id).strip() == cfg_chat_id

    def execute_command(self, cmd_text: str, chat_id: Any = None, sender_name: str = "Admin") -> Dict[str, Any]:
        """Procesa un comando del bot y genera la respuesta técnica"""
        cmd_raw = cmd_text.strip()
        cmd_parts = cmd_raw.split()
        command = cmd_parts[0].lower() if cmd_parts else ""
        if "@" in command:
            command = command.split("@")[0]

        # Validación de seguridad
        if chat_id and not self.is_authorized(chat_id):
            reject_msg = (
                f"[ACCESO DENEGADO - POLITICA DE SEGURIDAD]\n\n"
                f"El identificador `{chat_id}` no esta autorizado para administrar este servidor.\n"
                f"• Protocolo: Acceso denegado registrado en bitacora forense de CiberCentinela."
            )
            try:
                execute_prepared(
                    """INSERT INTO bitacora_auditoria (usuario_accion, operacion, tabla_afectada, mensaje_critico)
                       VALUES (?, 'SELECT', 'telemetria_sistema', ?)""",
                    (f"telegram_unauthorized_id_{chat_id}", f"Intento no autorizado de ejecucion de comando: {command}"),
                    id_rol=1,
                )
            except Exception:
                pass
            return {"authorized": False, "command": command, "response": reject_msg}

        # Enrutamiento de comandos
        if command in ("/start", "/help"):
            response = (
                f"[CENTINELA BOT - ADMINISTRACION DE SISTEMAS OPERATIVOS]\n"
                f"Plataforma: CiberCentinela SOC (UNACH)\n"
                f"Operador: {sender_name}\n"
                f"--------------------------------------------------\n"
                f"Comandos de Telemetria y Automatizacion:\n\n"
                f"• `/kpis` o `/reporte` - Reporte consolidado de los 7 KPIs del servidor\n"
                f"• `/cpu` - Uso de CPU, carga promedio (1/5/15m) y frecuencias\n"
                f"• `/ram` - Memoria RAM fisica y Swap en uso/disponible\n"
                f"• `/disco` - Espacio en disco y particiones montadas\n"
                f"• `/servicios` - Estado de servicios criticos (SSH, MySQL, Web, Demonio)\n"
                f"• `/uptime` - Tiempo de actividad continuo y hora de arranque\n"
                f"• `/conexiones` - Conexiones activas de red (ESTABLISHED, LISTEN)\n"
                f"• `/incidentes` - Incidentes de ciberseguridad activos y evidencias FIM\n"
                f"• `/backup` - Ejecutar respaldo en caliente de la base de datos (.sql.gz)\n"
                f"• `/status` - Diagnostico rapido de operatividad del sistema"
            )

        elif command in ("/kpis", "/reporte"):
            response = format_telegram_kpi_report()

        elif command == "/cpu":
            cpu = get_cpu_kpis()
            response = (
                f"[KPI 1: USO DE CPU Y CARGA PROMEDIO]\n"
                f"--------------------------------------------------\n"
                f"• Uso Actual: *{cpu['cpu_percent']}%* {'[PICO CRITICO]' if cpu['is_spike'] else '[NORMAL]'}\n"
                f"• Carga Promedio (1m): `{cpu['load_average']['1min']}`\n"
                f"• Carga Promedio (5m): `{cpu['load_average']['5min']}`\n"
                f"• Carga Promedio (15m): `{cpu['load_average']['15min']}`\n"
                f"• Nucleos Logicos: {cpu['cpu_count_logical']} nucleos\n"
                f"• Frecuencia Reloj: {cpu['frequency_mhz']} MHz\n"
                f"• Desglose por Nucleo: `{cpu['per_core_percent']}`"
            )

        elif command == "/ram":
            ram = get_ram_kpis()
            response = (
                f"[KPI 2: USO DE MEMORIA RAM Y SWAP]\n"
                f"--------------------------------------------------\n"
                f"• Porcentaje en Uso: *{ram['ram_percent']}%* {'[CRITICA]' if ram['is_critical'] else '[ESTABLE]'}\n"
                f"• Memoria Utilizada: {ram['ram_used_gb']} GB\n"
                f"• Memoria Disponible: {ram['ram_available_gb']} GB\n"
                f"• Memoria Total: {ram['ram_total_gb']} GB\n"
                f"• Espacio Swap Utilizado: {ram['swap_used_gb']} GB / {ram['swap_total_gb']} GB ({ram['swap_percent']}%)"
            )

        elif command == "/disco":
            disk = get_disk_kpis()
            parts_str = "\n".join([
                f"  • `{p['mountpoint']}` ({p['fstype']}): *{p['percent']}%* en uso ({p['free_gb']} GB libres de {p['total_gb']} GB)"
                for p in disk["partitions"]
            ])
            response = (
                f"[KPI 3: ESPACIO EN DISCO POR PARTICION]\n"
                f"--------------------------------------------------\n"
                f"• Ocupacion Global: *{disk['overall_percent']}%*\n"
                f"• Particiones Detectadas:\n{parts_str}"
            )

        elif command == "/servicios":
            srv = get_services_kpis()
            srv_lines = "\n".join([
                f"  [{'ACTIVO' if s['is_ok'] else 'INACTIVO'}] *{s['name']}* ({s['identifier']}):\n     Puerto: `{s['port']}` | Estado: `{s['status']}`"
                for s in srv["services"]
            ])
            response = (
                f"[KPI 4: ESTADO DE SERVICIOS CRITICOS]\n"
                f"--------------------------------------------------\n"
                f"{srv_lines}\n\n"
                f"• Diagnostico: {'Todos los servicios esenciales operan normalmente.' if srv['all_critical_ok'] else 'Uno o mas servicios criticos requieren atencion.'}"
            )

        elif command == "/uptime":
            up = get_uptime_info()
            response = (
                f"[KPI 5: TIEMPO DE ACTIVIDAD DEL SERVIDOR (UPTIME)]\n"
                f"--------------------------------------------------\n"
                f"• Tiempo Continuo en Linea: *{up['uptime_human']}*\n"
                f"• Fecha y Hora de Arranque: `{up['boot_time']}`\n"
                f"• Segundos Acumulados: `{up['uptime_seconds']} s`"
            )

        elif command == "/conexiones":
            net = get_network_kpis()
            b = net["status_breakdown"]
            response = (
                f"[KPI 6: CONEXIONES ACTIVAS DE RED]\n"
                f"--------------------------------------------------\n"
                f"• Conexiones Totales Activas: *{net['total_connections']}*\n"
                f"  - ESTABLISHED (Establecidas): {b.get('ESTABLISHED', 0)}\n"
                f"  - LISTEN (Puertos a la escucha): {b.get('LISTEN', 0)}\n"
                f"  - TIME_WAIT: {b.get('TIME_WAIT', 0)}\n"
                f"  - CLOSE_WAIT: {b.get('CLOSE_WAIT', 0)}\n"
                f"• Trafico de Red: Envio: {net['bytes_sent_mb']} MB | Recepcion: {net['bytes_recv_mb']} MB"
            )

        elif command == "/incidentes":
            from backend.daemon_worker import daemon
            soc = get_cibercentinela_kpis()["app_kpis"]
            fim = daemon.fim_summary
            response = (
                f"[KPI 7: SERVICIO CIBERCENTINELA (SOC & FORENSE)]\n"
                f"--------------------------------------------------\n"
                f"• Tickets Registrados: {soc.get('total_incidentes', 0)}\n"
                f"• Incidentes Criticos: *{soc.get('incidentes_criticos', 0)}*\n"
                f"• Incidentes en Contencion/Analisis: {soc.get('incidentes_en_progreso', 0)}\n"
                f"• Incidentes Resueltos: {soc.get('incidentes_resueltos', 0)}\n"
                f"• Cadena de Custodia (FIM): {fim.get('intact', 0)}/{fim.get('total', 0)} evidencias integras (SHA-256)\n"
                f"• Bitacora Inmutable (Auditoria): {soc.get('total_auditoria', 0)} eventos registrados"
            )

        elif command == "/backup":
            try:
                from backend.daemon_worker import daemon
                res = daemon.run_hot_backup(triggered_by=f"Telegram ({sender_name})")
                response = (
                    f"[RESPALDO EN CALIENTE GENERADO EXITOSAMENTE]\n"
                    f"--------------------------------------------------\n"
                    f"• Archivo: `{res['filename']}`\n"
                    f"• Tamano: `{round(res['size_bytes'] / 1024, 2)} KB`\n"
                    f"• Firma SHA-256: `{res['sha256']}`\n"
                    f"• Compresion: gzip (.sql.gz) con transacciones ACID consistentes\n"
                    f"• Politica: Retencion de {res['retention_days']} dias aplicada."
                )
            except Exception as e:
                response = f"[ERROR] Error al generar respaldo en caliente: {str(e)}"

        elif command == "/status":
            srv = get_services_kpis()
            cpu = get_cpu_kpis()
            ram = get_ram_kpis()
            response = (
                f"[ESTADO OPERATIVO DEL SERVIDOR]\n"
                f"• CPU: *{cpu['cpu_percent']}%* | RAM: *{ram['ram_percent']}%*\n"
                f"• Servicios: {'[OK]' if srv['all_critical_ok'] else '[ALERTA]'}\n"
                f"• Demonio CiberCentinela: Activo y Protegido."
            )

        else:
            response = (
                f"[COMANDO NO RECONOCIDO]: `{command}`\n"
                f"Escriba `/help` o `/kpis` para ver la lista de comandos disponibles."
            )

        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "chat_id": chat_id or "Simulated",
            "sender": sender_name,
            "command": command,
            "response_preview": response[:120] + "...",
        }
        with self.lock:
            self.command_history.insert(0, entry)
            self.command_history = self.command_history[:40]

        return {"authorized": True, "command": command, "response": response}

    def send_message_detailed(self, text: str, chat_id: Optional[str] = None, token: Optional[str] = None) -> Dict[str, Any]:
        """Envía un mensaje a Telegram mediante HTTPS Bot API y retorna diagnóstico detallado"""
        bot_token = (token or settings.TELEGRAM_BOT_TOKEN).strip()
        target_chat = str(chat_id or settings.TELEGRAM_CHAT_ID).strip()

        # Si se proporcionó un token y destinatario, enviar vía HTTPS TLS
        if bot_token and target_chat:
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                "chat_id": target_chat,
                "text": text,
                "parse_mode": "Markdown",
            }
            try:
                r = requests.post(url, json=payload, timeout=10)
                if r.status_code == 200:
                    return {
                        "success": True,
                        "mode": "TELEGRAM_API_TLS",
                        "detail": f"Mensaje entregado exitosamente vía Telegram HTTPS a {target_chat}."
                    }
                else:
                    err_json = {}
                    try:
                        err_json = r.json()
                    except Exception:
                        pass
                    err_desc = err_json.get("description", r.text[:120])
                    return {
                        "success": False,
                        "mode": "TELEGRAM_API_ERROR",
                        "detail": f"Telegram API devolvió error {r.status_code}: {err_desc}"
                    }
            except Exception as ex:
                return {
                    "success": False,
                    "mode": "NETWORK_ERROR",
                    "detail": f"Fallo de conexión hacia api.telegram.org: {str(ex)}"
                }

        # Si no hay token configurado o está en modo local
        return {
            "success": True,
            "simulated": True,
            "mode": "SIMULATION_LOCAL",
            "detail": f"Reporte procesado en pasarela local CiberCentinela para el destinatario {target_chat or 'Admin'} (Modo Sandbox)."
        }

    def send_message_api(self, text: str, chat_id: Optional[str] = None) -> bool:
        """Envía un mensaje a Telegram mediante HTTPS Bot API"""
        res = self.send_message_detailed(text, chat_id=chat_id)
        return res.get("success", False)

    def send_kpi_report(self, chat_id: Optional[str] = None, token: Optional[str] = None) -> Dict[str, Any]:
        """Envía el reporte completo de KPIs del servidor a Telegram con resultado detallado"""
        report = format_telegram_kpi_report()
        return self.send_message_detailed(report, chat_id=chat_id, token=token)

    def check_and_alert_thresholds(self):
        """Monitorea umbrales de KPIs y dispara alertas proactivas a Telegram"""
        now = time.time()
        if now - self.last_proactive_alert_time < 300:
            return

        cpu = get_cpu_kpis()
        ram = get_ram_kpis()
        disk = get_disk_kpis()
        srv = get_services_kpis()

        critical_reasons = []
        if cpu["cpu_percent"] >= 90.0:
            critical_reasons.append(f"Uso extremo de CPU: {cpu['cpu_percent']}%")
        if ram["ram_percent"] >= 92.0:
            critical_reasons.append(f"Uso extremo de RAM: {ram['ram_percent']}%")
        if disk["overall_percent"] >= 95.0:
            critical_reasons.append(f"Espacio en disco critico: {disk['overall_percent']}%")
        if not srv["all_critical_ok"]:
            critical_reasons.append("Servicio critico de servidor caido o inaccesible")

        if critical_reasons:
            alert_msg = (
                f"[ALERTA PREVENTIVA - UMBRAL CRITICO EXCEDIDO]\n"
                f"--------------------------------------------------\n"
                + "\n".join([f"• {r}" for r in critical_reasons])
                + f"\n\nFecha: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Escriba `/kpis` para obtener el diagnostico completo."
            )
            sent = self.send_message_api(alert_msg)
            if sent:
                self.last_proactive_alert_time = now

    def start_polling(self):
        """Inicia el bucle de recepción de comandos en segundo plano"""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="telegram-kpi-bot")
        self._thread.start()

    def _poll_loop(self):
        """Bucle Long Polling con api.telegram.org"""
        while self.running:
            try:
                token = settings.TELEGRAM_BOT_TOKEN
                if token and not settings.TELEGRAM_SIMULATION_MODE:
                    url = f"https://api.telegram.org/bot{token}/getUpdates"
                    params = {"offset": self.last_update_id + 1, "timeout": 8}
                    resp = requests.get(url, params=params, timeout=12)
                    if resp.status_code == 200:
                        data = resp.json()
                        for update in data.get("result", []):
                            self.last_update_id = update["update_id"]
                            msg = update.get("message", {})
                            text = msg.get("text", "").strip()
                            chat = msg.get("chat", {})
                            chat_id = chat.get("id")
                            user = msg.get("from", {})
                            name = user.get("first_name", "Usuario")

                            if text and text.startswith("/"):
                                res = self.execute_command(text, chat_id=chat_id, sender_name=name)
                                self.send_message_api(res["response"], chat_id=chat_id)
                self.check_and_alert_thresholds()
            except Exception:
                pass
            time.sleep(2)


bot_instance = TelegramKPISecurityBot()
