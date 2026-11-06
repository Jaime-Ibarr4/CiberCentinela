import os
import hashlib
import bcrypt
import mysql.connector
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

def setup_mysql_database():
    print("[*] Conectando a MySQL local para verificar y configurar cibercentinela_db...")
    root_pass = os.getenv("DB_ROOT_PASSWORD", "hOLA")
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_ROOT_USER", "root"),
        password=root_pass,
    )
    cur = conn.cursor()

    # 1. Crear base de datos
    cur.execute("CREATE DATABASE IF NOT EXISTS cibercentinela_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
    cur.execute("USE cibercentinela_db;")

    # 2. Ejecutar schema_completo.sql para asegurar todas las tablas
    schema_file = BASE_DIR / "database" / "schema_completo.sql"
    if schema_file.exists():
        sql_script = schema_file.read_text(encoding="utf-8")
        for statement in sql_script.split(";"):
            stmt = statement.strip()
            if stmt and not stmt.startswith("--"):
                try:
                    cur.execute(stmt)
                except Exception:
                    pass

    # Asegurar columna fecha_ultimo_cambio en tabla usuarios (requerida por centinelad.py en login y cambio de contraseña)
    try:
        cur.execute("ALTER TABLE usuarios ADD COLUMN fecha_ultimo_cambio TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL;")
    except Exception:
        pass

    # 3. Categorías de incidentes
    cur.execute("""
        INSERT IGNORE INTO categorias_incidentes (id_categoria, nombre_categoria, descripcion) VALUES
        (1, 'Phishing e Ingenieria Social', 'Ataques de suplantacion de identidad mediante correos o mensajeria'),
        (2, 'Malware y Ransomware', 'Infeccion por codigo malicioso o cifrado de archivos no autorizado'),
        (3, 'Intrusion y Acceso No Autorizado', 'Violacion de controles de acceso o escalamiento de privilegios'),
        (4, 'Denegacion de Servicio (DoS)', 'Saturacion maliciosa de ancho de banda o recursos del servidor'),
        (5, 'Fuga de Informacion', 'Exfiltracion de datos sensibles o violacion de confidencialidad');
    """)

    # 4. Estados de incidentes
    cur.execute("""
        INSERT IGNORE INTO estados_incidentes (id_estado, nombre_estado, descripcion) VALUES
        (1, 'Abierto', 'Incidente reportado pendiente de evaluacion'),
        (2, 'En Analisis', 'Investigacion forense y recoleccion de evidencias en progreso'),
        (3, 'En Contencion', 'Aplicacion de medidas para aislar y mitigar el impacto'),
        (4, 'Resuelto / Cerrado', 'Amenaza neutralizada y servicios restaurados con exito');
    """)

    # 5. Roles del sistema
    cur.execute("""
        INSERT IGNORE INTO roles (id_rol, nombre_rol, descripcion) VALUES
        (1, 'Administrador', 'Acceso total al sistema y auditoría'),
        (2, 'Analista Forense', 'Gestión de evidencias y custodia'),
        (3, 'Reportador', 'Registro y consulta de incidentes');
    """)

    # 6. Usuarios base
    cur.execute("""
        INSERT IGNORE INTO usuarios (id_usuario, nombre_completo, email, password_hash, id_rol, activo) VALUES
        (1, 'Alexis Ibarra', 'aibarra@centinela.local', '$2y$12$simulado_aibarra', 1, 1),
        (2, 'Marvin Camacho', 'mcamacho@centinela.local', '$2y$12$simulado_mcamacho', 2, 1),
        (3, 'Danna Gomez', 'dgomez@centinela.local', '$2y$12$simulado_dgomez', 3, 1),
        (4, 'Ivan Roblero', 'iroblero@centinela.local', '$2y$12$simulado_iroblero', 3, 0);
    """)

    # 7. Actualizar hashes bcrypt reales con 12 rondas
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

    # 8. Incidentes de muestra
    cur.execute("""
        INSERT IGNORE INTO incidentes (id_incidente, codigo_ticket, titulo, descripcion, severidad, id_categoria, id_estado, id_usuario_reportador, id_analista_asignado) VALUES
        (1, 'TCK-2026-001', 'Campaña de Phishing masivo a personal directivo', 'Recepcion de correos fraudulentos suplantando entidad bancaria con enlaces maliciosos.', 'Alta', 1, 2, 3, 2),
        (2, 'TCK-2026-002', 'Alerta de Ransomware en servidor de bases de datos', 'Deteccion de archivos .locked y actividad sospechosa del proceso lockbit_payload.elf.', 'Critica', 2, 3, 1, 2),
        (3, 'TCK-2026-003', 'Multiples intentos fallidos de autenticacion SSH', 'Deteccion de ataque de fuerza bruta desde red externa sobre el puerto 22.', 'Media', 3, 1, 3, 2);
    """)

    # 9. Triggers requeridos por el sistema
    # Trigger 1: Inmutabilidad UPDATE en bitácora
    cur.execute("DROP TRIGGER IF EXISTS trg_bitacora_inmutable_update;")
    cur.execute("""
    CREATE TRIGGER trg_bitacora_inmutable_update
    BEFORE UPDATE ON bitacora_auditoria
    FOR EACH ROW
    BEGIN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'ALTERACION PROHIBIDA: La bitacora transaccional es inmutable.';
    END;
    """)

    # Trigger 2: Inmutabilidad DELETE en bitácora
    cur.execute("DROP TRIGGER IF EXISTS trg_bitacora_inmutable_delete;")
    cur.execute("""
    CREATE TRIGGER trg_bitacora_inmutable_delete
    BEFORE DELETE ON bitacora_auditoria
    FOR EACH ROW
    BEGIN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'ALTERACION PROHIBIDA: La bitacora transaccional es inmutable.';
    END;
    """)

    # Trigger 3: After Insert Incidentes
    cur.execute("DROP TRIGGER IF EXISTS trg_incidentes_after_insert;")
    cur.execute("""
    CREATE TRIGGER trg_incidentes_after_insert
    AFTER INSERT ON incidentes
    FOR EACH ROW
    BEGIN
        INSERT INTO bitacora_auditoria (usuario_accion, operacion, tabla_afectada, datos_nuevos, mensaje_critico)
        VALUES (
            USER(),
            'INSERT',
            'incidentes',
            JSON_OBJECT('id_incidente', NEW.id_incidente, 'codigo_ticket', NEW.codigo_ticket, 'titulo', NEW.titulo, 'severidad', NEW.severidad),
            CONCAT('NUEVO INCIDENTE REGISTRADO: ', NEW.codigo_ticket)
        );
        IF NEW.severidad = 'Critica' THEN
            INSERT INTO notificaciones_telegram (id_incidente, mensaje, estado_envio)
            VALUES (
                NEW.id_incidente,
                CONCAT('INCIDENTE CRITICO DETECTADO [', NEW.codigo_ticket, ']: ', NEW.titulo),
                'Pendiente'
            );
        END IF;
    END;
    """)

    # Trigger 4: After Update Incidentes
    cur.execute("DROP TRIGGER IF EXISTS trg_incidentes_after_update;")
    cur.execute("""
    CREATE TRIGGER trg_incidentes_after_update
    AFTER UPDATE ON incidentes
    FOR EACH ROW
    BEGIN
        INSERT INTO bitacora_auditoria (usuario_accion, operacion, tabla_afectada, datos_antiguos, datos_nuevos, mensaje_critico)
        VALUES (
            USER(),
            'UPDATE',
            'incidentes',
            JSON_OBJECT('id_estado', OLD.id_estado, 'severidad', OLD.severidad),
            JSON_OBJECT('id_estado', NEW.id_estado, 'severidad', NEW.severidad),
            CONCAT('ACTUALIZACION DE INCIDENTE: ', NEW.codigo_ticket)
        );
        INSERT INTO historico_incidentes (id_incidente, codigo_ticket, titulo, descripcion, severidad, id_estado, id_analista_asignado, usuario_modificador)
        VALUES (NEW.id_incidente, NEW.codigo_ticket, NEW.titulo, NEW.descripcion, NEW.severidad, NEW.id_estado, NEW.id_analista_asignado, USER());
    END;
    """)

    # Trigger 5: After Delete Incidentes
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
            JSON_OBJECT('id_incidente', OLD.id_incidente, 'codigo_ticket', OLD.codigo_ticket, 'titulo', OLD.titulo, 'severidad', OLD.severidad),
            'REGISTRO DE INCIDENTE ELIMINADO'
        );
    END;
    """)

    # Trigger 6: Before Insert Incidentes (Validación de analista inactivo)
    cur.execute("DROP TRIGGER IF EXISTS trg_incidentes_before_insert;")
    cur.execute("""
    CREATE TRIGGER trg_incidentes_before_insert
    BEFORE INSERT ON incidentes
    FOR EACH ROW
    BEGIN
        DECLARE analista_activo INT DEFAULT 1;
        IF NEW.id_analista_asignado IS NOT NULL THEN
            SELECT activo INTO analista_activo FROM usuarios WHERE id_usuario = NEW.id_analista_asignado LIMIT 1;
            IF analista_activo = 0 THEN
                SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'ASIGNACION PROHIBIDA: El analista seleccionado se encuentra inactivo.';
            END IF;
        END IF;
    END;
    """)

    # Trigger 7: Before Update Incidentes (Validación de analista inactivo)
    cur.execute("DROP TRIGGER IF EXISTS trg_incidentes_before_update;")
    cur.execute("""
    CREATE TRIGGER trg_incidentes_before_update
    BEFORE UPDATE ON incidentes
    FOR EACH ROW
    BEGIN
        DECLARE analista_activo INT DEFAULT 1;
        IF NEW.id_analista_asignado IS NOT NULL THEN
            SELECT activo INTO analista_activo FROM usuarios WHERE id_usuario = NEW.id_analista_asignado LIMIT 1;
            IF analista_activo = 0 THEN
                SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'ASIGNACION PROHIBIDA: El analista seleccionado se encuentra inactivo.';
            END IF;
        END IF;
    END;
    """)

    # 10. Configurar roles y permisos en MySQL
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

    # 11. Cuentas operativas por rol con compatibilidad universal (MySQL 8.0 y 8.4)
    db_users = [
        ("usr_admin_ciber", "Admin2026#CiberCentinelaSecure", "rol_admin"),
        ("usr_analista_ciber", "Analyst2026#ForenseSecureKey", "rol_analista"),
        ("usr_reportador_ciber", "Reporter2026#ReportSafePass", "rol_reportador"),
    ]

    for username, pwd, role in db_users:
        for host in ["%", "localhost", "127.0.0.1"]:
            try:
                cur.execute(f"CREATE USER IF NOT EXISTS '{username}'@'{host}' IDENTIFIED BY '{pwd}';")
            except Exception:
                pass
            try:
                cur.execute(f"ALTER USER '{username}'@'{host}' IDENTIFIED BY '{pwd}';")
            except Exception:
                pass
            try:
                cur.execute(f"GRANT '{role}' TO '{username}'@'{host}';")
                cur.execute(f"SET DEFAULT ROLE '{role}' TO '{username}'@'{host}';")
            except Exception:
                pass

    cur.execute("FLUSH PRIVILEGES;")

    # 12. Crear archivo físico forense de muestra y registrarlo en evidencias_forenses
    forensics_dir = BASE_DIR / "srv" / "forensics" / "cases" / "TCK-2026-002"
    forensics_dir.mkdir(parents=True, exist_ok=True)
    sample_artifact = forensics_dir / "memdump_srv_db_prod.raw"
    sample_content = (
        b"CIBERCENTINELA_FORENSIC_MEMORY_DUMP_HEADER_v1.0\n"
        b"CASE_ID: TCK-2026-002\n"
        b"HOST: SRV-DB-PROD-01 (Ubuntu 22.04 LTS)\n"
        b"ARTIFACT: Volatile RAM Dump - LockBit Ransomware Indicator (.locked)\n"
        b"PROCESS_TREE: mysqld (PID 1142) <- lockbit_payload.elf (PID 9941)\n"
        b"NETWORK_IOC: 185.220.101.44:443 (TOR_EXIT_NODE)\n"
        b"CHAIN_OF_CUSTODY: SEALED BY ANALYST MARVIN CAMACHO (ID 2)\n"
    )
    if not sample_artifact.exists():
        sample_artifact.write_bytes(sample_content)

    artifact_bytes = sample_artifact.read_bytes()
    artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
    cur.execute("""
        INSERT IGNORE INTO evidencias_forenses
        (id_evidencia, id_incidente, nombre_archivo, ruta_almacenamiento, hash_sha256, tamano_bytes, id_usuario_carga)
        VALUES (1, 2, 'memdump_srv_db_prod.raw', '/srv/forensics/cases/TCK-2026-002/memdump_srv_db_prod.raw', %s, %s, 2);
    """, (artifact_sha256, len(artifact_bytes)))

    # 13. Asegurar alerta inicial en notificaciones_telegram y bitácora si están vacías
    cur.execute("SELECT COUNT(*) FROM notificaciones_telegram;")
    if cur.fetchone()[0] == 0:
        cur.execute("""
            INSERT INTO notificaciones_telegram (id_incidente, mensaje, estado_envio)
            VALUES (2, 'INCIDENTE CRITICO DETECTADO [TCK-2026-002]: Alerta de Ransomware en servidor de bases de datos', 'Pendiente');
        """)

    cur.execute("SELECT COUNT(*) FROM bitacora_auditoria;")
    if cur.fetchone()[0] == 0:
        cur.execute("""
            INSERT INTO bitacora_auditoria (usuario_accion, operacion, tabla_afectada, datos_nuevos, mensaje_critico)
            VALUES ('usr_admin_ciber@localhost', 'INSERT', 'incidentes', '{"id_incidente": 2, "codigo_ticket": "TCK-2026-002", "severidad": "Critica"}', 'NUEVO INCIDENTE CRITICO REGISTRADO: TCK-2026-002');
        """)

    conn.commit()
    cur.close()
    conn.close()
    print("[+] Configuracion de cibercentinela_db completada al 100% con exito.")

if __name__ == "__main__":
    setup_mysql_database()
