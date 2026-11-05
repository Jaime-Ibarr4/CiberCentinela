#!/bin/bash
# ============================================================================
# SCRIPT DE AUTOMATIZACIÓN DE RESPALDOS CON ROTACIÓN (CiberCentinela)
# Política de Copias de Seguridad - Retención 7 días (RETENTION_DAYS=7)
# ============================================================================

BACKUP_DIR="/var/backups/mysql_cibercentinela"
DB_NAME="cibercentinela_db"
DB_USER="root"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_${DATE}.sql.gz"
RETENTION_DAYS=7

mkdir -p $BACKUP_DIR

echo "[+] Generando respaldo consistente en caliente de $DB_NAME..."
mysqldump -u $DB_USER -p"${DB_PASSWORD}" \
  --single-transaction \
  --quick \
  --routines \
  --triggers \
  --events \
  $DB_NAME | gzip > $BACKUP_FILE

if [ $? -eq 0 ]; then
  echo "[+] Respaldo completado exitosamente: $BACKUP_FILE"
else
  echo "[-] Error en la generacion del respaldo"
  exit 1
fi

echo "[+] Eliminando respaldos con antiguedad mayor a $RETENTION_DAYS dias..."
find $BACKUP_DIR -name "${DB_NAME}_*.sql.gz" -mtime +$RETENTION_DAYS -exec rm -f {} \;
echo "[+] Mantenimiento finalizado."
