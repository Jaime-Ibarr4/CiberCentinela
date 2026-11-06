#!/bin/bash
# ============================================================================
# CIBERCENTINELA - SCRIPT DE AUTOMATIZACIÓN DE KPIS EN LINUX (CRON JOB)
# Asignatura: Administración de Sistemas Operativos
# Catedrático: Dr. Carlos Alberto García Ramos
# ============================================================================
# Este script automatiza la recopilación de los 7 KPIs del servidor Linux
# y su envío programado hacia el Bot de Telegram de CiberCentinela.
#
# Configuración recomendada en Crontab (crontab -e):
# # Ejecutar reporte diario consolidado a las 08:00 AM y 08:00 PM:
# 0 8,20 * * * /opt/cibercentinela/database/kpi_report_cron.sh >> /var/log/centinela_kpis.log 2>&1
# ============================================================================

set -e

APP_DIR="/opt/cibercentinela"
ENV_FILE="${APP_DIR}/.env"
LOG_FILE="/var/log/centinela_kpis.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "--------------------------------------------------------"
echo "[+] Iniciando recolección automatizada de KPIs: ${TIMESTAMP}"

# Cargar variables de entorno
if [ -f "$ENV_FILE" ]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs -d '\n')
fi

# 1. Verificación de conectividad con la API del demonio local
API_URL="http://127.0.0.1:8090/api/kpis/send-telegram-report"
RESPONSE=$(curl -s -X POST "$API_URL" -H "Content-Type: application/json" || true)

if echo "$RESPONSE" | grep -q '"status":"sent"'; then
    echo "[✓] Reporte de los 7 KPIs transmitido exitosamente a Telegram Bot API."
elif echo "$RESPONSE" | grep -q '"status":"simulated"'; then
    echo "[i] Modo simulación activo. Reporte registrado en bitácora local."
else
    echo "[!] Enviando reporte mediante script Python de respaldo..."
    cd "$APP_DIR" && python3 -c "
import sys
from backend.telegram_bot import bot_instance
ok = bot_instance.send_kpi_report()
print('Despacho Python:', 'Exitoso' if ok else 'Modo local/Simulado')
"
fi

echo "[✓] Tarea programada (cron) finalizada con éxito."
echo "--------------------------------------------------------"
