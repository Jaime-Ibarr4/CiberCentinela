import os
import hashlib
import bcrypt
import mysql.connector
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def setup_mysql_database():
    print("[*] Conectando a MySQL 8.0 local para verificar y configurar cibercentinela_db...")
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_ROOT_USER", "root"),
        password=os.getenv("DB_ROOT_PASSWORD", "root"),
    )
    cur = conn.cursor()

    cur.execute("CREATE DATABASE IF NOT EXISTS cibercentinela_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
    cur.execute("USE cibercentinela_db;")

    # 1. Asegurar roles base en la tabla 'roles'
    cur.execute("""
        INSERT IGNORE INTO roles (id_rol, nombre_rol, descripcion) VALUES
        (1, 'Administrador', 'Acceso total al sistema y auditoría'),
        (2, 'Analista Forense', 'Gestión de evidencias y custodia'),
        (3, 'Reportador', 'Registro y consulta de incidentes');
    """)

    # 2. Asegurar usuarios base en la tabla 'usuarios'
    cur.execute("""
        INSERT IGNORE INTO usuarios (id_usuario, nombre_completo, email, password_hash, id_rol, activo) VALUES
        (1, 'Alexis Ibarra', 'aibarra@centinela.local', '$2y$12$simulado_aibarra', 1, 1),
        (2, 'Marvin Camacho', 'mcamacho@centinela.local', '$2y$12$simulado_mcamacho', 2, 1),
        (3, 'Danna Gomez', 'dgomez@centinela.local', '$2y$12$simulado_dgomez', 3, 1),
        (4, 'Ivan Roblero', 'iroblero@centinela.local', '$2y$12$simulado_iroblero', 3, 0);
    """)

    # Asegurar que el 7mo trigger (trg_incidentes_after_delete) también esté creado
    cur.execute("DROP TRIGGER IF EXISTS trg_incidentes_after_delete;")
    cur.execute("""
    CREATE TRIGGER trg_incidentes_after_delete
    AFTER DELETE ON incidentes
    FOR EACH ROW
    BEGIN
        INSERT INTO bitacora_auditoria (usuario_accion, operacion, tabla_afectada, datos_antiguos, mensaje_critico)
        VALUES (
            USER(),
            'DELETE',
            'incidentes',
            JSON_OBJECT(
                'id_incidente', OLD.id_incidente,
                'codigo_ticket', OLD.codigo_ticket,
                'titulo', OLD.titulo,
                'severidad', OLD.severidad
            ),
            'REGISTRO DE INCIDENTE ELIMINADO'
        );
    END
    """)

    # Configurar roles y usuarios de MySQL 8.0
    roles = ["rol_admin", "rol_analista", "rol_reportador"]
    for r in roles:
        cur.execute(f"CREATE ROLE IF NOT EXISTS '{r}';")

    cur.execute("GRANT ALL PRIVILEGES ON cibercentinela_db.* TO 'rol_admin';")
    cur.execute("GRANT SELECT ON cibercentinela_db.* TO 'rol_analista';")
    cur.execute("GRANT INSERT, UPDATE ON cibercentinela_db.incidentes TO 'rol_analista';")
    cur.execute("GRANT INSERT, UPDATE ON cibercentinela_db.evidencias_forenses TO 'rol_analista';")

    cur.execute("GRANT SELECT ON cibercentinela_db.categorias_incidentes TO 'rol_reportador';")
    cur.execute("GRANT SELECT ON cibercentinela_db.estados_incidentes TO 'rol_reportador';")
    cur.execute("GRANT SELECT, INSERT ON cibercentinela_db.incidentes TO 'rol_reportador';")

    db_users = [
        ("usr_admin_ciber", "Admin2026#CiberCentinelaSecure", "rol_admin"),
        ("usr_analista_ciber", "Analyst2026#ForenseSecureKey", "rol_analista"),
        ("usr_reportador_ciber", "Reporter2026#ReportSafePass", "rol_reportador"),
    ]

    for username, pwd, role in db_users:
        for host in ["%", "localhost", "127.0.0.1"]:
            cur.execute(f"CREATE USER IF NOT EXISTS '{username}'@'{host}' IDENTIFIED BY '{pwd}';")
            cur.execute(f"ALTER USER '{username}'@'{host}' IDENTIFIED BY '{pwd}';")
            cur.execute(f"GRANT '{role}' TO '{username}'@'{host}';")
            cur.execute(f"SET DEFAULT ROLE '{role}' TO '{username}'@'{host}';")

    cur.execute("FLUSH PRIVILEGES;")

    # Actualizar hashes bcrypt reales
    demo_passwords = {
        "aibarra@centinela.local": "Admin#Centinela2026!",
        "mcamacho@centinela.local": "Forense$Marvin2026!",
        "dgomez@centinela.local": "Reporta@Danna2026!",
        "iroblero@centinela.local": "Inactivo%Ivan2026!",
    }

    cur.execute("SELECT id_usuario, email, password_hash FROM usuarios;")
    rows = cur.fetchall()
    for uid, email, current_hash in rows:
        if email in demo_passwords and ("simulado" in current_hash or "..." in current_hash or len(current_hash) < 55):
            raw_pwd = demo_passwords[email].encode("utf-8")
            hashed = bcrypt.hashpw(raw_pwd, bcrypt.gensalt(rounds=12)).decode("utf-8")
            hashed_2y = "$2y$" + hashed[4:]
            cur.execute(
                "UPDATE usuarios SET password_hash = %s WHERE id_usuario = %s",
                (hashed_2y, uid),
            )
            
            print(f"[+] Hash bcrypt (12 rondas) actualizado para {email}")

    # Crear archivo físico forense de muestra
    forensics_dir = BASE_DIR / "srv" / "forensics" / "cases" / "TCK-2026-002"
    forensics_dir.mkdir(parents=True, exist_ok=True)
    sample_artifact = forensics_dir / "memdump_srv_db_prod.raw"
    if not sample_artifact.exists():
        sample_content = (
            b"CIBERCENTINELA_FORENSIC_MEMORY_DUMP_HEADER_v1.0\n"
            b"CASE_ID: TCK-2026-002\n"
            b"HOST: SRV-DB-PROD-01 (Ubuntu 22.04 LTS)\n"
            b"ARTIFACT: Volatile RAM Dump - LockBit Ransomware Indicator (.locked)\n"
            b"PROCESS_TREE: mysqld (PID 1142) <- lockbit_payload.elf (PID 9941)\n"
            b"NETWORK_IOC: 185.220.101.44:443 (TOR_EXIT_NODE)\n"
            b"CHAIN_OF_CUSTODY: SEALED BY ANALYST MARVIN CAMACHO (ID 2)\n"
        )
        sample_artifact.write_bytes(sample_content)

    conn.commit()
    cur.close()
    conn.close()
    print("[+] Configuración de cibercentinela_db completada con éxito.")

if __name__ == "__main__":
    setup_mysql_database()