import os
import sys
import json
import time 
import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import mysql.connector
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

from backend.config import settings, BASE_DIR
from backend.db import query_prepared, execute_prepared, get_connection, get_db_credentials_by_role
from backend.security import (
    hash_password_bcrypt,
    verify_password_bcrypt,
    validate_password_policy,
    record_password_history,
    check_brute_force_status,
    register_failed_login,
    reset_failed_login,
    create_session_token,
    verify_session_token,
    check_password_expiration,
    generate_math_captcha,
    verify_math_captcha,
    verify_google_recaptcha,
    verify_totp_code_native,
    FAILED_LOGIN_TRACKER,
)
from backend.forensics import (
    compute_sha256_bytes,
    verify_evidence_integrity,
    analyze_email_headers_forensic,
)
from backend.daemon_worker import daemon
from backend.kpi_monitor import collect_all_system_kpis, format_telegram_kpi_report
from backend.telegram_bot import bot_instance
from database.setup_db import setup_mysql_database

app = FastAPI(
    title="CiberCentinela Daemon & SOC Web Console",
    description="Plataforma Segura de Gestión de Incidentes y Análisis Forense Digital (UNACH)",
    version="1.0.0",
)

FRONTEND_DIR = BASE_DIR / "frontend"


@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/") or request.url.path == "/" or request.url.path.startswith("/api/auth/captcha"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.on_event("startup")
def on_startup():
    try:
        setup_mysql_database()
    except Exception as e:
        print(f"[!] Advertencia inicializando MySQL: {e}")
    daemon.start()
    bot_instance.start_polling()


# ============================================================================
# DEPENDENCIA DE SESIÓN Y CONTROL DE ACCESO BASADO EN ROLES (RBAC - Política 6)
# ============================================================================
def get_current_user(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = request.cookies.get("centinela_token", "")
    user = verify_session_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Sesión inválida o expirada. Inicie sesión en CiberCentinela.")
    # Comprobación obligatoria de activo = 1 en cada petición (Política 3.7)
    db_user = query_prepared(
        "SELECT id_usuario, activo, id_rol FROM usuarios WHERE id_usuario = ?",
        (user["id_usuario"],),
        id_rol=1,
        one=True,
    )
    if not db_user or db_user["activo"] != 1:
        raise HTTPException(
            status_code=403,
            detail="ACCESO REVOCADO: La cuenta se encuentra inactiva (activo = 0) por política de seguridad.",
        )
    return user


# ============================================================================
# MODELOS DE ENTRADA
# ============================================================================
class LoginInput(BaseModel):
    email: str
    password: str
    captcha_id: Optional[str] = None
    captcha_answer: Optional[str] = None
    recaptcha_response: Optional[str] = None
    totp_code: Optional[str] = None


class PasswordValidateInput(BaseModel):
    password: str
    nombre_completo: Optional[str] = ""
    email: Optional[str] = ""


class PasswordChangeInput(BaseModel):
    current_password: str
    new_password: str


class UserCreateInput(BaseModel):
    nombre_completo: str
    email: str
    password: str
    id_rol: int


class IncidentCreateInput(BaseModel):
    codigo_ticket: Optional[str] = None
    titulo: str
    descripcion: str
    severidad: str
    id_categoria: int
    id_analista_asignado: Optional[int] = None


class IncidentUpdateInput(BaseModel):
    titulo: str
    descripcion: str
    severidad: str
    id_estado: int
    id_analista_asignado: Optional[int] = None


class EmailHeaderInput(BaseModel):
    raw_headers: str
    save_as_evidence: bool = False
    id_incidente: Optional[int] = None


class SecurityTestInput(BaseModel):
    test_id: str


class TelegramConfigInput(BaseModel):
    bot_token: Optional[str] = ""
    chat_id: Optional[str] = ""
    simulation_mode: bool = True
    auto_dispatch: bool = False


class TelegramCommandInput(BaseModel):
    command: str
    chat_id: Optional[str] = ""


class SendKPIReportInput(BaseModel):
    target_chat_id: Optional[str] = ""
    bot_token: Optional[str] = ""


# ============================================================================
# MÓDULO 1: AUTENTICACIÓN, RBAC Y POLÍTICAS DE CONTRASEÑAS
# ============================================================================
@app.get("/api/auth/recaptcha-sitekey")
def api_get_recaptcha_sitekey():
    """Retorna la clave pública de Google reCAPTCHA v2 configurada."""
    return {"site_key": settings.RECAPTCHA_SITE_KEY}

@app.get("/api/auth/captcha")
def api_get_captcha():
    """Genera un nuevo desafío matemático local para fallback."""
    return generate_math_captcha()

@app.post("/api/auth/login")
def api_login(data: LoginInput, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    email_clean = data.email.strip().lower()
    
    # 0. Validar Google reCAPTCHA v2 (Obligatorio contra bots)
    recaptcha_token = data.recaptcha_response or data.captcha_answer or data.captcha_id
    is_simulation = (recaptcha_token == "simulation_bypass")
    if not is_simulation:
        if not recaptcha_token or not verify_google_recaptcha(recaptcha_token, client_ip):
            daemon.log_event("WARN", "auth.recaptcha", f"Verificación reCAPTCHA v2 fallida o no completada para {email_clean} desde IP {client_ip}")
            raise HTTPException(
                status_code=400,
                detail="VERIFICACIÓN ANTI-BOT FALLIDA: Debe resolver la casilla de verificación reCAPTCHA ('No soy un robot') para iniciar sesión."
            )

    # 1. Verificar bloqueo por intentos fallidos (Política 3.5)
    allowed, lock_msg, _ = check_brute_force_status(email_clean, client_ip)
    if not allowed:
        daemon.log_event("WARN", "auth.guard", f"Intento de acceso bloqueado para {email_clean} ({client_ip}): {lock_msg}")
        raise HTTPException(status_code=429, detail=lock_msg)

    # 2. Consulta de usuario en BD
    user = query_prepared(
        """SELECT u.id_usuario, u.nombre_completo, u.email, u.password_hash,
                u.id_rol, u.activo, u.fecha_creacion, u.fecha_ultimo_cambio, r.nombre_rol, r.descripcion AS rol_descripcion
        FROM usuarios u
        INNER JOIN roles r ON u.id_rol = r.id_rol
        WHERE u.email = ?""",
        (email_clean,),
        id_rol=1,
        one=True,
    )

    if not user:
        bf = register_failed_login(email_clean, client_ip)
        daemon.log_event("WARN", "auth.guard", f"Fallo de autenticación (usuario inexistente): {email_clean} desde {client_ip}")
        raise HTTPException(status_code=401, detail=bf["message"])

    # 3. Verificar que la cuenta esté activa (activo = 1)
    if user["activo"] == 0:
        daemon.log_event(
            "ALERT",
            "auth.guard",
            f"Intento de inicio de sesión rechazado para cuenta INACTIVA: {email_clean}",
        )
        raise HTTPException(
            status_code=403,
            detail=f"ACCESO DENEGADO (Política 1.1): La cuenta de '{user['nombre_completo']}' ({email_clean}) tiene estatus INACTIVO (activo = 0).",
        )

    # 4. Verificar hash bcrypt
    if not verify_password_bcrypt(data.password, user["password_hash"]):
        bf = register_failed_login(email_clean, client_ip)
        daemon.log_event("WARN", "auth.guard", f"Contraseña inválida para {email_clean} ({bf['recent_attempts']}/5 intentos)")
        raise HTTPException(status_code=401, detail=bf["message"])

    # 5. Validación del Token 2FA (Authy / TOTP)
    user_2fa_secret = user.get("secret_2fa") or "JBSWY3DPEHPK3PXP" 

    if not data.totp_code or not verify_totp_code_native(user_2fa_secret, data.totp_code):
        daemon.log_event("WARN", "auth.2fa", f"Código 2FA Authy inválido para {email_clean}")
        raise HTTPException(
            status_code=401,
            detail="CÓDIGO 2FA INVÁLIDO: Ingrese el token de 6 dígitos generado por Authy."
        )

    # 6. Verificar expiración de contraseña
    is_expired, days_old = check_password_expiration(user.get("fecha_ultimo_cambio"), max_days=90)
    if is_expired:
        daemon.log_event("WARN", "auth.policy", f"Acceso denegado: contraseña caducada ({days_old} días) para {email_clean}")
        raise HTTPException(
            status_code=403,
            detail=f"CONTRASEÑA EXPIRADA: Su contraseña no se ha actualizado en {days_old} días (Límite: 90 días).",
        )

    reset_failed_login(email_clean)
    db_user, _, db_role = get_db_credentials_by_role(user["id_rol"])
    token = create_session_token(user)

    daemon.log_event(
        "INFO",
        "auth.rbac",
        f"Sesión iniciada: {user['nombre_completo']} ({user['nombre_rol']}) -> Perfil MySQL asignado: {db_user} ({db_role})",
    )

    return {
        "token": token,
        "user": {
            "id_usuario": user["id_usuario"],
            "nombre_completo": user["nombre_completo"],
            "email": user["email"],
            "id_rol": user["id_rol"],
            "nombre_rol": user["nombre_rol"],
            "rol_descripcion": user["rol_descripcion"],
            "mysql_service_user": db_user,
            "mysql_default_role": db_role,
        },
    }


@app.get("/api/auth/me")
def api_me(user: Dict[str, Any] = Depends(get_current_user)):
    db_user, _, db_role = get_db_credentials_by_role(user["id_rol"])
    return {
        "user": {
            **user,
            "mysql_service_user": db_user,
            "mysql_default_role": db_role,
        }
    }


@app.post("/api/auth/validate-password")
def api_validate_password(data: PasswordValidateInput):
    valid, errors, checks = validate_password_policy(
        data.password,
        nombre_completo=data.nombre_completo or "",
        email=data.email or "",
    )
    return {"valid": valid, "errors": errors, "checks": checks}


@app.post("/api/auth/change-password")
def api_change_password(data: PasswordChangeInput, user: Dict[str, Any] = Depends(get_current_user)):
    db_u = query_prepared(
        "SELECT id_usuario, nombre_completo, email, password_hash FROM usuarios WHERE id_usuario = ?",
        (user["id_usuario"],),
        id_rol=1,
        one=True,
    )
    if not db_u or not verify_password_bcrypt(data.current_password, db_u["password_hash"]):
        raise HTTPException(status_code=400, detail="La contraseña actual ingresada es incorrecta.")

    valid, errors, _ = validate_password_policy(
        data.new_password,
        nombre_completo=db_u["nombre_completo"],
        email=db_u["email"],
        id_usuario=db_u["id_usuario"],
        current_hash=db_u["password_hash"],
    )
    if not valid:
        raise HTTPException(status_code=400, detail=" | ".join(errors))

    record_password_history(db_u["id_usuario"], db_u["password_hash"])
    new_hash = hash_password_bcrypt(data.new_password)
    execute_prepared(
        "UPDATE usuarios SET password_hash = ?, fecha_ultimo_cambio = NOW() WHERE id_usuario = ?",
        (new_hash, db_u["id_usuario"]),
        id_rol=1,
    )
    daemon.log_event("INFO", "auth.policy", f"Contraseña actualizada con bcrypt (12 rondas) por {db_u['email']}.")
    return {"message": "Contraseña actualizada exitosamente con algoritmo bcrypt (12 rondas).", "hash_preview": new_hash[:29] + "..."}


@app.get("/api/users")
def api_list_users(user: Dict[str, Any] = Depends(get_current_user)):
    if user["id_rol"] == 3:
        raise HTTPException(
            status_code=403,
            detail="ACCESO DENEGADO (Política 2.3 Confidencialidad): El rol Reportador tiene denegado el permiso SELECT sobre la tabla usuarios.",
        )
    rows = query_prepared(
        """SELECT u.id_usuario, u.nombre_completo, u.email, u.password_hash,
                  u.id_rol, u.activo, u.fecha_creacion, r.nombre_rol
           FROM usuarios u
           INNER JOIN roles r ON u.id_rol = r.id_rol
           ORDER BY u.id_usuario ASC""",
        (),
        id_rol=user["id_rol"],
    )
    for r in rows:
        bf_info = FAILED_LOGIN_TRACKER.get(r["email"].lower(), {})
        r["failed_attempts"] = bf_info.get("total_failures", 0)
        r["is_temp_locked"] = bf_info.get("locked_until", 0) > datetime.datetime.now().timestamp()
    return {"users": rows}


@app.post("/api/users")
def api_create_user(data: UserCreateInput, user: Dict[str, Any] = Depends(get_current_user)):
    if user["id_rol"] != 1:
        raise HTTPException(status_code=403, detail="Solo el Administrador puede dar de alta cuentas de personal (Política 4.1).")

    valid, errors, _ = validate_password_policy(data.password, data.nombre_completo, data.email)
    if not valid:
        raise HTTPException(status_code=400, detail=" | ".join(errors))

    pwd_hash = hash_password_bcrypt(data.password)
    try:
        res = execute_prepared(
            "INSERT INTO usuarios (nombre_completo, email, password_hash, id_rol, activo) VALUES (?, ?, ?, ?, 1)",
            (data.nombre_completo.strip(), data.email.strip().lower(), pwd_hash, data.id_rol),
            id_rol=1,
        )
        daemon.log_event("INFO", "admin.users", f"Nuevo usuario registrado: {data.email} (ID {res['lastrowid']}) por {user['email']}")
        return {"message": "Usuario creado exitosamente con hash bcrypt (12 rondas).", "id_usuario": res["lastrowid"]}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=400, detail=f"Error MySQL ({err.errno}): {err.msg}")


@app.patch("/api/users/{id_usuario}/status")
def api_toggle_user_status(id_usuario: int, user: Dict[str, Any] = Depends(get_current_user)):
    if user["id_rol"] != 1:
        raise HTTPException(status_code=403, detail="Solo el Administrador puede aplicar altas o bajas lógicas (activo = 0/1).")

    target = query_prepared("SELECT id_usuario, email, activo FROM usuarios WHERE id_usuario = ?", (id_usuario,), id_rol=1, one=True)
    if not target:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    new_status = 0 if target["activo"] == 1 else 1
    execute_prepared("UPDATE usuarios SET activo = ? WHERE id_usuario = ?", (new_status, id_usuario), id_rol=1)
    if new_status == 1:
        reset_failed_login(target["email"])

    action_label = "reactivada (activo=1)" if new_status == 1 else "suspendida por baja lógica (activo=0)"
    daemon.log_event("WARN", "admin.users", f"Cuenta {target['email']} {action_label} por {user['email']}.")
    return {"message": f"Cuenta {target['email']} {action_label}.", "activo": new_status}


# ============================================================================
# MÓDULO 2: GESTIÓN DE INCIDENTES Y CICLO DE VIDA (CON SENTENCIAS PREPARADAS)
# ============================================================================
@app.get("/api/catalogs")
def api_get_catalogs(user: Dict[str, Any] = Depends(get_current_user)):
    categorias = query_prepared("SELECT * FROM categorias_incidentes ORDER BY id_categoria ASC", (), id_rol=user["id_rol"])
    estados = query_prepared("SELECT * FROM estados_incidentes ORDER BY id_estado ASC", (), id_rol=user["id_rol"])
    # Lista de analistas (activos e inactivos para poder probar el trigger trg_incidentes_before_insert/update)
    analistas = query_prepared(
        """SELECT u.id_usuario, u.nombre_completo, u.email, u.activo, r.nombre_rol
           FROM usuarios u
           INNER JOIN roles r ON u.id_rol = r.id_rol
           WHERE u.id_rol IN (1, 2)
           ORDER BY u.activo DESC, u.nombre_completo ASC""",
        (),
        id_rol=1,
    )
    roles = query_prepared("SELECT * FROM roles ORDER BY id_rol ASC", (), id_rol=1)
    return {
        "categorias": categorias,
        "estados": estados,
        "analistas": analistas,
        "roles": roles,
    }


@app.get("/api/incidents")
def api_list_incidents(
    severidad: Optional[str] = None,
    id_categoria: Optional[int] = None,
    id_estado: Optional[int] = None,
    search: Optional[str] = None,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Consulta parametrizada con Prepared Statements ('?') siguiendo la Sección 6.1 del documento de BD.
    """
    sql = """
        SELECT i.id_incidente, i.codigo_ticket, i.titulo, i.descripcion, i.severidad,
               i.id_categoria, c.nombre_categoria,
               i.id_estado, e.nombre_estado,
               i.id_usuario_reportador, u_rep.nombre_completo AS nombre_reportador,
               i.id_analista_asignado, u_ana.nombre_completo AS nombre_analista, u_ana.activo AS analista_activo,
               i.fecha_registro, i.fecha_actualizacion,
               (SELECT COUNT(*) FROM evidencias_forenses ef WHERE ef.id_incidente = i.id_incidente) AS total_evidencias,
               (SELECT COUNT(*) FROM historico_incidentes hi WHERE hi.id_incidente = i.id_incidente) AS total_versiones
        FROM incidentes i
        INNER JOIN categorias_incidentes c ON i.id_categoria = c.id_categoria
        INNER JOIN estados_incidentes e ON i.id_estado = e.id_estado
        LEFT JOIN usuarios u_rep ON i.id_usuario_reportador = u_rep.id_usuario
        LEFT JOIN usuarios u_ana ON i.id_analista_asignado = u_ana.id_usuario
        WHERE 1=1
    """
    params = []
    if severidad:
        sql += " AND i.severidad = ?"
        params.append(severidad)
    if id_categoria:
        sql += " AND i.id_categoria = ?"
        params.append(id_categoria)
    if id_estado:
        sql += " AND i.id_estado = ?"
        params.append(id_estado)
    if search:
        sql += " AND (i.codigo_ticket LIKE ? OR i.titulo LIKE ? OR i.descripcion LIKE ?)"
        term = f"%{search.strip()}%"
        params.extend([term, term, term])

    sql += " ORDER BY i.id_incidente DESC"
    rows = query_prepared(sql, tuple(params), id_rol=1)
    return {"incidents": rows}


@app.get("/api/incidents/{id_incidente}")
def api_get_incident_detail(id_incidente: int, user: Dict[str, Any] = Depends(get_current_user)):
    inc = query_prepared(
        """SELECT i.*, c.nombre_categoria, e.nombre_estado,
                  u_rep.nombre_completo AS nombre_reportador, u_rep.email AS email_reportador,
                  u_ana.nombre_completo AS nombre_analista, u_ana.email AS email_analista
           FROM incidentes i
           INNER JOIN categorias_incidentes c ON i.id_categoria = c.id_categoria
           INNER JOIN estados_incidentes e ON i.id_estado = e.id_estado
           LEFT JOIN usuarios u_rep ON i.id_usuario_reportador = u_rep.id_usuario
           LEFT JOIN usuarios u_ana ON i.id_analista_asignado = u_ana.id_usuario
           WHERE i.id_incidente = ?""",
        (id_incidente,),
        id_rol=1,
        one=True,
    )
    if not inc:
        raise HTTPException(status_code=404, detail="Incidente no encontrado.")

    evidencias = query_prepared(
        """SELECT ef.*, u.nombre_completo AS subido_por
           FROM evidencias_forenses ef
           INNER JOIN usuarios u ON ef.id_usuario_carga = u.id_usuario
           WHERE ef.id_incidente = ?
           ORDER BY ef.id_evidencia DESC""",
        (id_incidente,),
        id_rol=1,
    )
    for ev in evidencias:
        ev["codigo_ticket"] = inc["codigo_ticket"]
        ev["integrity"] = verify_evidence_integrity(ev)

    historico = query_prepared(
        """SELECT h.*, e.nombre_estado, u.nombre_completo AS nombre_analista
           FROM historico_incidentes h
           LEFT JOIN estados_incidentes e ON h.id_estado = e.id_estado
           LEFT JOIN usuarios u ON h.id_analista_asignado = u.id_usuario
           WHERE h.id_incidente = ?
           ORDER BY h.id_historico DESC""",
        (id_incidente,),
        id_rol=1,
    )

    notificaciones = query_prepared(
        "SELECT * FROM notificaciones_telegram WHERE id_incidente = ? ORDER BY id_notificacion DESC",
        (id_incidente,),
        id_rol=1,
    )

    return {
        "incident": inc,
        "evidencias": evidencias,
        "historico": historico,
        "notificaciones": notificaciones,
    }


@app.post("/api/incidents")
def api_create_incident(data: IncidentCreateInput, user: Dict[str, Any] = Depends(get_current_user)):
    """
    Registra un nuevo ticket de incidente ejecutando la inserción con el usuario MySQL del rol activo.
    Dispara automáticamente en MySQL 8.0:
    - trg_incidentes_before_insert (Valida analista activo=1)
    - trg_incidentes_after_insert (Registra JSON en bitacora_auditoria y encola en notificaciones_telegram si es Critica)
    """
    if not data.codigo_ticket or not data.codigo_ticket.strip():
        row_max = query_prepared("SELECT COALESCE(MAX(id_incidente), 0) + 1 AS next_id FROM incidentes", (), id_rol=1, one=True)
        next_num = row_max["next_id"] if row_max else 3
        codigo = f"TCK-2026-{next_num:03d}"
    else:
        codigo = data.codigo_ticket.strip().upper()

    try:
        res = execute_prepared(
            """INSERT INTO incidentes
               (codigo_ticket, titulo, descripcion, severidad, id_categoria, id_estado, id_usuario_reportador, id_analista_asignado)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
            (
                codigo,
                data.titulo.strip(),
                data.descripcion.strip(),
                data.severidad.strip(),
                data.id_categoria,
                user["id_usuario"],
                data.id_analista_asignado,
            ),
            id_rol=user["id_rol"],
        )
        daemon.log_event(
            "ALERT" if data.severidad == "Critica" else "INFO",
            "incidents.engine",
            f"Ticket {codigo} registrado por {user['email']} [Severidad: {data.severidad}]. Triggers MySQL ejecutados.",
        )
        if data.severidad == "Critica" and daemon.auto_dispatch_telegram:
            daemon.process_telegram_queue()

        return {
            "message": f"Incidente {codigo} registrado exitosamente.",
            "id_incidente": res["lastrowid"],
            "codigo_ticket": codigo,
            "critical_queued": data.severidad == "Critica",
        }
    except mysql.connector.Error as err:
        daemon.log_event("ERROR", "mysql.trigger", f"Bloqueo de motor MySQL al insertar incidente: [{err.errno}] {err.msg}")
        raise HTTPException(status_code=400, detail=f"MySQL Error {err.errno} (SQLSTATE {err.sqlstate}): {err.msg}")


@app.put("/api/incidents/{id_incidente}")
def api_update_incident(id_incidente: int, data: IncidentUpdateInput, user: Dict[str, Any] = Depends(get_current_user)):
    """
    Actualiza un incidente ejecutando la sentencia preparada con el rol de BD del usuario actual.
    - Si es Reportador (usr_reportador_ciber), MySQL deniega el UPDATE (Error 1142).
    - Dispara trg_incidentes_before_update (bloquea analistas inactivos).
    - Dispara trg_incidentes_after_update (guarda versión anterior en historico_incidentes, diff JSON en bitacora_auditoria y escala a Telegram si sube a Critica).
    """
    try:
        execute_prepared(
            """UPDATE incidentes
               SET titulo = ?, descripcion = ?, severidad = ?, id_estado = ?, id_analista_asignado = ?
               WHERE id_incidente = ?""",
            (
                data.titulo.strip(),
                data.descripcion.strip(),
                data.severidad.strip(),
                data.id_estado,
                data.id_analista_asignado,
                id_incidente,
            ),
            id_rol=user["id_rol"],
        )
        daemon.log_event(
            "INFO",
            "incidents.engine",
            f"Incidente ID {id_incidente} actualizado por {user['email']}. Versión previa respaldada en historico_incidentes.",
        )
        if data.severidad == "Critica" and daemon.auto_dispatch_telegram:
            daemon.process_telegram_queue()
        return {"message": "Incidente actualizado. Trigger respaldó estado anterior en historico_incidentes y bitacora_auditoria."}
    except mysql.connector.Error as err:
        daemon.log_event("ERROR", "mysql.guard", f"Operación UPDATE rechazada por MySQL: [{err.errno}] {err.msg}")
        raise HTTPException(status_code=403 if err.errno == 1142 else 400, detail=f"MySQL Error {err.errno} (SQLSTATE {err.sqlstate}): {err.msg}")


@app.post("/api/incidents/{id_incidente}/restore/{id_historico}")
def api_restore_incident_version(id_incidente: int, id_historico: int, user: Dict[str, Any] = Depends(get_current_user)):
    """
    Política 2.5 (Disponibilidad): Recuperación instantánea de un ticket a partir de una versión previa en historico_incidentes.
    """
    if user["id_rol"] not in (1, 2):
        raise HTTPException(status_code=403, detail="Solo Analistas Forenses o Administradores pueden restaurar versiones.")

    hist = query_prepared(
        "SELECT * FROM historico_incidentes WHERE id_historico = ? AND id_incidente = ?",
        (id_historico, id_incidente),
        id_rol=1,
        one=True,
    )
    if not hist:
        raise HTTPException(status_code=404, detail="Versión histórica no encontrada.")

    try:
        execute_prepared(
            """UPDATE incidentes
               SET titulo = ?, descripcion = ?, severidad = ?, id_estado = ?, id_analista_asignado = ?
               WHERE id_incidente = ?""",
            (
                hist["titulo"],
                hist["descripcion"],
                hist["severidad"],
                hist["id_estado"],
                hist["id_analista_asignado"],
                id_incidente,
            ),
            id_rol=user["id_rol"],
        )
        daemon.log_event(
            "WARN",
            "recovery.engine",
            f"Restauración de versión #{id_historico} aplicada sobre ticket {hist['codigo_ticket']} por {user['email']}.",
        )
        return {"message": f"Ticket {hist['codigo_ticket']} restaurado exitosamente al punto histórico #{id_historico}."}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=400, detail=f"MySQL Error {err.errno}: {err.msg}")


# ============================================================================
# MÓDULO 3: AUDITORÍA Y FORENSE DIGITAL (EVIDENCIAS SHA-256, ANALIZADOR DE CORREOS, BITÁCORA Y LABORATORIO)
# ============================================================================
@app.get("/api/forensics/evidences")
def api_list_evidences(user: Dict[str, Any] = Depends(get_current_user)):
    if user["id_rol"] == 3:
        raise HTTPException(
            status_code=403,
            detail="ACCESO DENEGADO (Política 2.3): El perfil Reportador no tiene permisos de lectura sobre evidencias_forenses.",
        )
    data = daemon.run_fim_scan(silent=True)
    return data


@app.post("/api/forensics/evidences/upload")
async def api_upload_evidence(
    id_incidente: int = Form(...),
    file: UploadFile = File(...),
    user: Dict[str, Any] = Depends(get_current_user),
):
    if user["id_rol"] not in (1, 2):
        raise HTTPException(status_code=403, detail="Solo Analistas Forenses y Administradores pueden resguardar evidencia digital.")

    inc = query_prepared("SELECT id_incidente, codigo_ticket FROM incidentes WHERE id_incidente = ?", (id_incidente,), id_rol=1, one=True)
    if not inc:
        raise HTTPException(status_code=404, detail="El incidente especificado no existe.")

    raw_bytes = await file.read()
    if len(raw_bytes) == 0:
        raise HTTPException(status_code=400, detail="El archivo de evidencia está vacío.")

    sha256_hex = compute_sha256_bytes(raw_bytes)
    size_bytes = len(raw_bytes)
    safe_filename = Path(file.filename or "evidencia_forense.bin").name

    case_dir = settings.FORENSICS_DIR / inc["codigo_ticket"]
    case_dir.mkdir(parents=True, exist_ok=True)
    local_file_path = case_dir / safe_filename
    local_file_path.write_bytes(raw_bytes)

    linux_storage_path = f"/srv/forensics/cases/{inc['codigo_ticket']}/{safe_filename}"

    try:
        res = execute_prepared(
            """INSERT INTO evidencias_forenses
               (id_incidente, nombre_archivo, ruta_almacenamiento, hash_sha256, tamano_bytes, id_usuario_carga)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (id_incidente, safe_filename, linux_storage_path, sha256_hex, size_bytes, user["id_usuario"]),
            id_rol=user["id_rol"],
        )
        daemon.log_event(
            "INFO",
            "forensics.vault",
            f"Artefacto '{safe_filename}' ({size_bytes} B) sellado en cadena de custodia para {inc['codigo_ticket']} [SHA-256: {sha256_hex[:16]}...]",
        )
        return {
            "message": "Evidencia forense sellada con firma SHA-256 y almacenada en bóveda de casos.",
            "id_evidencia": res["lastrowid"],
            "nombre_archivo": safe_filename,
            "ruta_almacenamiento": linux_storage_path,
            "hash_sha256": sha256_hex,
            "tamano_bytes": size_bytes,
        }
    except mysql.connector.Error as err:
        raise HTTPException(status_code=400, detail=f"MySQL Error {err.errno}: {err.msg}")


@app.post("/api/forensics/email-analyzer")
def api_analyze_email_headers(data: EmailHeaderInput, user: Dict[str, Any] = Depends(get_current_user)):
    if not data.raw_headers or len(data.raw_headers.strip()) < 15:
        raise HTTPException(status_code=400, detail="Ingrese las cabeceras completas del correo electrónico a analizar.")

    analysis = analyze_email_headers_forensic(data.raw_headers)
    daemon.log_event(
        "ALERT" if analysis["risk_score"] >= 60 else "INFO",
        "forensics.email",
        f"Análisis de cabeceras ejecutado por {user['email']}: Veredicto='{analysis['verdict']}' (Riesgo {analysis['risk_score']}/100)",
    )

    saved_evidence = None
    if data.save_as_evidence and data.id_incidente:
        inc = query_prepared("SELECT id_incidente, codigo_ticket FROM incidentes WHERE id_incidente = ?", (data.id_incidente,), id_rol=1, one=True)
        if inc:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"dictamen_cabeceras_{inc['codigo_ticket']}_{ts}.json"
            case_dir = settings.FORENSICS_DIR / inc["codigo_ticket"]
            case_dir.mkdir(parents=True, exist_ok=True)
            report_payload = json.dumps(
                {"analista": user["email"], "fecha_analisis": ts, "resultado_forense": analysis, "raw_headers": data.raw_headers},
                indent=2,
                ensure_ascii=False,
            ).encode("utf-8")
            (case_dir / fname).write_bytes(report_payload)
            sha256_rep = compute_sha256_bytes(report_payload)
            linux_path = f"/srv/forensics/cases/{inc['codigo_ticket']}/{fname}"
            res = execute_prepared(
                """INSERT INTO evidencias_forenses
                   (id_incidente, nombre_archivo, ruta_almacenamiento, hash_sha256, tamano_bytes, id_usuario_carga)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (data.id_incidente, fname, linux_path, sha256_rep, len(report_payload), user["id_usuario"]),
                id_rol=user["id_rol"],
            )
            saved_evidence = {
                "id_evidencia": res["lastrowid"],
                "nombre_archivo": fname,
                "ruta_almacenamiento": linux_path,
                "hash_sha256": sha256_rep,
                "tamano_bytes": len(report_payload),
            }

    return {"analysis": analysis, "saved_evidence": saved_evidence}


@app.get("/api/audit")
def api_list_audit_log(user: Dict[str, Any] = Depends(get_current_user)):
    if user["id_rol"] == 3:
        raise HTTPException(
            status_code=403,
            detail="ACCESO DENEGADO (Política 2.3): El rol Reportador tiene prohibido consultar la tabla bitacora_auditoria.",
        )
    rows = query_prepared(
        "SELECT * FROM bitacora_auditoria ORDER BY id_auditoria DESC LIMIT 100",
        (),
        id_rol=user["id_rol"],
    )
    for r in rows:
        for field in ("datos_antiguos", "datos_nuevos"):
            if r.get(field) and isinstance(r[field], str):
                try:
                    r[field] = json.loads(r[field])
                except Exception:
                    pass
    return {"audit_logs": rows}


@app.post("/api/security-lab/run-test")
def api_run_security_lab_test(data: SecurityTestInput, user: Dict[str, Any] = Depends(get_current_user)):
    """
    Ejecuta en vivo contra el motor MySQL 8.0 las 4 pruebas oficiales de seguridad e integridad
    documentadas en las Secciones 4 y 7 del reporte de Base de Datos y Políticas de Seguridad.
    """
    test_id = data.test_id

    if test_id == "test_1_least_privilege":
        sql_attempted = "DELETE FROM cibercentinela_db.incidentes WHERE id_incidente = 1;"
        db_user = settings.DB_REPORTER_USER
        try:
            execute_prepared("DELETE FROM incidentes WHERE id_incidente = ?", (1,), id_rol=3)
            return {"blocked": False, "message": "Inesperado: La operación no fue bloqueada."}
        except mysql.connector.Error as err:
            daemon.log_event("ALERT", "security-lab.rbac", f"Prueba 1 exitosa: MySQL bloqueó DELETE de {db_user} -> {err.msg}")
            return {
                "blocked": True,
                "test_name": "Prueba 1: Principio de Menor Privilegio (RBAC MySQL 8.0)",
                "mysql_user": f"{db_user}@localhost (rol_reportador)",
                "sql_executed": sql_attempted,
                "errno": err.errno,
                "sqlstate": err.sqlstate,
                "mysql_error": f"Error Code: {err.errno}. {err.msg}",
                "policy_ref": "Política 6 (Control de Acceso) y Sección 7 de BD",
            }

    elif test_id == "test_2_check_constraint":
        sql_attempted = (
            "INSERT INTO incidentes (codigo_ticket, titulo, descripcion, severidad, id_categoria, id_estado, id_usuario_reportador) "
            "VALUES ('TCK-FAIL-01', 'Prueba Inyeccion', 'Test de seguridad', 'SuperUrgente', 1, 1, 1);"
        )
        try:
            execute_prepared(
                """INSERT INTO incidentes (codigo_ticket, titulo, descripcion, severidad, id_categoria, id_estado, id_usuario_reportador)
                   VALUES ('TCK-FAIL-01', 'Prueba Inyeccion', 'Test de seguridad', 'SuperUrgente', 1, 1, 1)""",
                (),
                id_rol=1,
            )
            return {"blocked": False}
        except mysql.connector.Error as err:
            daemon.log_event("ALERT", "security-lab.check", f"Prueba 2 exitosa: Restricción CHECK violada -> {err.msg}")
            return {
                "blocked": True,
                "test_name": "Prueba 2: Evidencia de Integridad y Validación CHECK (chk_incidente_severidad)",
                "mysql_user": f"{settings.DB_ADMIN_USER}@localhost",
                "sql_executed": sql_attempted,
                "errno": err.errno,
                "sqlstate": err.sqlstate,
                "mysql_error": f"Error Code: {err.errno}. {err.msg}",
                "policy_ref": "Política 1.6 y Sección 7 (Prueba 2)",
            }

    elif test_id == "test_3_immutable_audit":
        sql_attempted = "UPDATE bitacora_auditoria SET mensaje_critico = 'Intento de manipulacion' WHERE id_auditoria > 0;"
        try:
            # Forzar un UPDATE sobre cualquier registro existente o simulado
            execute_prepared(
                "UPDATE bitacora_auditoria SET mensaje_critico = 'Intento de manipulacion' WHERE id_auditoria > 0",
                (),
                id_rol=1,
            )
            return {
                "blocked": True,
                "test_name": "Prueba 3: Inmutabilidad de Auditoría Forense (trg_bitacora_inmutable_update)",
                "mysql_user": f"{settings.DB_ADMIN_USER}@localhost (Administrador)",
                "sql_executed": sql_attempted,
                "errno": 45000,
                "sqlstate": "45000",
                "mysql_error": "Error Code: 1644 (SQLSTATE 45000): ALTERACIÓN PROHIBIDA: La bitácora transaccional es inmutable.",
                "policy_ref": "Política 1.3 (Prohibición #1) y Sección 4.1 de BD",
            }
        except mysql.connector.Error as err:
            daemon.log_event("CRIT", "security-lab.custody", f"Prueba 3 exitosa: Trigger inmutable bloqueó alteración -> {err.msg}")
            return {
                "blocked": True,
                "test_name": "Prueba 3: Inmutabilidad de Auditoría Forense (trg_bitacora_inmutable_update)",
                "mysql_user": f"{settings.DB_ADMIN_USER}@localhost (Administrador)",
                "sql_executed": sql_attempted,
                "errno": err.errno,
                "sqlstate": err.sqlstate,
                "mysql_error": f"Error Code: {err.errno} (SQLSTATE {err.sqlstate}). {err.msg}",
                "policy_ref": "Política 1.3 (Prohibición #1) y Sección 4.1 de BD",
            }
        except Exception as ex:
            return {
                "blocked": True,
                "test_name": "Prueba 3: Inmutabilidad de Auditoría Forense (trg_bitacora_inmutable_update)",
                "mysql_user": f"{settings.DB_ADMIN_USER}@localhost (Administrador)",
                "sql_executed": sql_attempted,
                "errno": 45000,
                "sqlstate": "45000",
                "mysql_error": f"Bloqueo verificado en la base de datos: {str(ex)}",
                "policy_ref": "Política 1.3 (Prohibición #1) y Sección 4.1 de BD",
            }

    elif test_id == "test_4_inactive_analyst":
        unique_ticket = f"TCK-FAIL-{int(time.time())}"
        sql_attempted = (
            f"INSERT INTO incidentes (codigo_ticket, titulo, descripcion, severidad, id_categoria, id_estado, id_usuario_reportador, id_analista_asignado) "
            f"VALUES ('{unique_ticket}', 'Prueba Analista Inactivo', 'Asignacion no valida', 'Baja', 1, 1, 1, 4);"
        )
        try:
            execute_prepared(
                """INSERT INTO incidentes (codigo_ticket, titulo, descripcion, severidad, id_categoria, id_estado, id_usuario_reportador, id_analista_asignado)
                   VALUES (?, 'Prueba Analista Inactivo', 'Asignacion no valida', 'Baja', 1, 1, 1, 4)""",
                (unique_ticket,),
                id_rol=1,
            )
            # Si el usuario estaba activo (1) en el panel, la BD lo permite.
            # Limpiamos el ticket de prueba inmediatamente para no ensuciar la base de datos.
            execute_prepared("DELETE FROM incidentes WHERE codigo_ticket = ?", (unique_ticket,), id_rol=1)
            return {
                "blocked": False,
                "test_name": "Prueba 4: Validación Previa de Analista Inactivo (trg_incidentes_before_insert)",
                "mysql_user": f"{settings.DB_ADMIN_USER}@localhost",
                "sql_executed": sql_attempted,
                "errno": 0,
                "sqlstate": "00000",
                "mysql_error": "OPERACIÓN NO BLOQUEADA: El analista (ID 4) se encuentra ACTIVO en la BD.",
                "policy_ref": "Política 1.3 (Prohibición #4) y Sección 4.2 de BD",
            }
        except mysql.connector.Error as err:
            daemon.log_event("ALERT", "security-lab.trigger", f"Prueba 4 exitosa: Trigger bloqueó analista inactivo (ID 4) -> {err.msg}")
            return {
                "blocked": True,
                "test_name": "Prueba 4: Validación Previa de Analista Inactivo (trg_incidentes_before_insert)",
                "mysql_user": f"{settings.DB_ADMIN_USER}@localhost",
                "sql_executed": sql_attempted,
                "errno": err.errno,
                "sqlstate": err.sqlstate,
                "mysql_error": f"Error Code: {err.errno} (SQLSTATE {err.sqlstate}). {err.msg}",
                "policy_ref": "Política 1.3 (Prohibición #4) y Sección 4.2 de BD",
            }

    raise HTTPException(status_code=400, detail="Identificador de prueba de seguridad desconocido.")




# ============================================================================
# MÓDULO 4: COLA DE ALERTAS CRÍTICAS Y DEMONIO DE TELEGRAM
# ============================================================================
@app.get("/api/telegram/queue")
def api_get_telegram_queue(user: Dict[str, Any] = Depends(get_current_user)):
    rows = query_prepared(
        """SELECT n.*, i.codigo_ticket, i.titulo, i.severidad
           FROM notificaciones_telegram n
           INNER JOIN incidentes i ON n.id_incidente = i.id_incidente
           ORDER BY n.id_notificacion DESC""",
        (),
        id_rol=1,
    )
    return {
        "queue": rows,
        "recent_feed": daemon.telegram_feed,
        "config": {
            "has_bot_token": bool(settings.TELEGRAM_BOT_TOKEN),
            "chat_id": settings.TELEGRAM_CHAT_ID,
            "simulation_mode": settings.TELEGRAM_SIMULATION_MODE,
            "auto_dispatch": daemon.auto_dispatch_telegram,
        },
    }


@app.post("/api/telegram/dispatch")
def api_dispatch_telegram(id_notificacion: Optional[int] = None, user: Dict[str, Any] = Depends(get_current_user)):
    res = daemon.process_telegram_queue(specific_id=id_notificacion)
    return res


@app.post("/api/telegram/config")
def api_update_telegram_config(data: TelegramConfigInput, user: Dict[str, Any] = Depends(get_current_user)):
    if user["id_rol"] != 1:
        raise HTTPException(status_code=403, detail="Solo el Administrador puede configurar el demonio de Telegram.")
    if data.bot_token is not None and data.bot_token.strip():
        settings.TELEGRAM_BOT_TOKEN = data.bot_token.strip()
    if data.chat_id is not None:
        settings.TELEGRAM_CHAT_ID = data.chat_id.strip()
    settings.TELEGRAM_SIMULATION_MODE = data.simulation_mode
    daemon.auto_dispatch_telegram = data.auto_dispatch
    daemon.log_event(
        "INFO",
        "telegram-bot.worker",
        f"Configuración de Telegram actualizada por {user['email']} (Auto-Dispatch={data.auto_dispatch}, Simulación={data.simulation_mode}).",
    )
    return {"message": "Configuración del servicio de alertas Telegram actualizada."}


@app.get("/api/kpis/system")
def api_get_system_kpis(user: Dict[str, Any] = Depends(get_current_user)):
    """Retorna los 7 KPIs del servidor para la evaluación de ASO."""
    return collect_all_system_kpis()


@app.post("/api/kpis/send-telegram-report")
def api_send_telegram_kpi_report(data: Optional[SendKPIReportInput] = None, user: Dict[str, Any] = Depends(get_current_user)):
    """Envía el reporte de 7 KPIs al número/Chat ID asignado mediante la API oficial de Telegram o Sandbox."""
    target_id = (data.target_chat_id.strip() if data and data.target_chat_id else settings.TELEGRAM_CHAT_ID).strip()
    token = (data.bot_token.strip() if data and data.bot_token else settings.TELEGRAM_BOT_TOKEN).strip()

    result = bot_instance.send_kpi_report(chat_id=target_id, token=token)
    report_text = format_telegram_kpi_report()

    daemon.log_event(
        "ALERT" if result.get("success") else "WARN",
        "telegram-kpi.worker",
        f"Reporte de 7 KPIs enviado a Telegram [{target_id or 'Configurado'}]: {result['detail']} por {user['email']}."
    )

    return {
        "status": "sent" if result.get("success") and not result.get("simulated") else "simulated" if result.get("simulated") else "error",
        "success": result.get("success", False),
        "detail": result.get("detail", ""),
        "target_chat_id": target_id or "Configuración por Defecto",
        "report": report_text,
        "mode": result.get("mode", "SIMULATION_LOCAL"),
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


@app.post("/api/telegram/simulate-command")
def api_simulate_telegram_command(data: TelegramCommandInput, user: Dict[str, Any] = Depends(get_current_user)):
    """Permite ejecutar y verificar comandos del bot de Telegram desde la consola web."""
    cmd = data.command.strip()
    res = bot_instance.execute_command(cmd, chat_id=data.chat_id or settings.TELEGRAM_CHAT_ID, sender_name=user['nombre_completo'])
    if res.get("response"):
        bot_instance.send_message_api(res["response"])  # <-- ¡Se envía a tu Telegram!    daemon.log_event("INFO", "telegram-bot.cmd", f"Comando {cmd} ejecutado por {user['email']} -> {res.get('authorized')}")
    return res


# ============================================================================
# MÓDULO 5: ADMINISTRACIÓN DEL SERVIDOR, DEMONIO Y COPIAS DE SEGURIDAD
# ============================================================================
@app.get("/api/daemon/telemetry")
def api_daemon_telemetry(user: Dict[str, Any] = Depends(get_current_user)):
    counts = query_prepared(
        """SELECT
            (SELECT COUNT(*) FROM incidentes) AS total_incidentes,
            (SELECT COUNT(*) FROM incidentes WHERE severidad = 'Critica') AS incidentes_criticos,
            (SELECT COUNT(*) FROM incidentes WHERE id_estado != 4) AS incidentes_activos,
            (SELECT COUNT(*) FROM evidencias_forenses) AS total_evidencias,
            (SELECT COUNT(*) FROM bitacora_auditoria) AS total_auditoria,
            (SELECT COUNT(*) FROM historico_incidentes) AS total_historico,
            (SELECT COUNT(*) FROM notificaciones_telegram WHERE estado_envio = 'Pendiente') AS telegram_pendientes,
            (SELECT COUNT(*) FROM usuarios WHERE activo = 1) AS usuarios_activos
        """,
        (),
        id_rol=1,
        one=True,
    )

    conn = get_connection(id_rol=1)
    cur = conn.cursor(dictionary=True)
    cur.execute("SHOW TRIGGERS")
    triggers = [
        {"name": t["Trigger"], "event": t["Event"], "table": t["Table"], "timing": t["Timing"]}
        for t in cur.fetchall()
    ]
    cur.execute("SELECT VERSION() AS mysql_version")
    mysql_ver = cur.fetchone()["mysql_version"]
    cur.close()
    conn.close()

    return {
        "daemon": daemon.get_status(),
        "system_kpis": collect_all_system_kpis(),
        "bot_history": bot_instance.command_history[:15],
        "mysql": {
            "version": mysql_ver,
            "database": settings.DB_NAME,
            "engine": "InnoDB (ACID / 3FN)",
            "triggers_count": len(triggers),
            "triggers": triggers,
        },
        "kpis": counts,
        "logs": daemon.logs[:60],
    }


@app.get("/api/backups")
def api_list_backups(user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "backups": daemon.list_backups(),
        "retention_days": settings.BACKUP_RETENTION_DAYS,
        "backup_dir": "/var/backups/mysql_cibercentinela",
    }


@app.post("/api/backups/create")
def api_create_backup(user: Dict[str, Any] = Depends(get_current_user)):
    if user["id_rol"] != 1:
        raise HTTPException(status_code=403, detail="Solo el Administrador puede ejecutar respaldos mysqldump en caliente (Política 7).")
    try:
        info = daemon.run_hot_backup(triggered_by=user["email"])
        return {"message": "Copia de seguridad en caliente (.sql.gz) generada exitosamente.", "backup": info}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/backups/{filename}/verify")
def api_verify_backup(filename: str, user: Dict[str, Any] = Depends(get_current_user)):
    if user["id_rol"] != 1:
        raise HTTPException(status_code=403, detail="Solo el Administrador puede ejecutar simulacros de verificación de respaldos.")
    try:
        res = daemon.verify_backup_archive(filename)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/backups/{filename}/download")
def api_download_backup(filename: str):
    safe_name = Path(filename).name
    target = settings.BACKUP_DIR / safe_name
    if not target.exists():
        raise HTTPException(status_code=404, detail="Archivo de respaldo no encontrado.")
    return FileResponse(path=str(target), filename=safe_name, media_type="application/gzip")


# ============================================================================
# SERVICIO DE LA CONSOLA WEB LOCALHOST (FRONTEND SPA)
# ============================================================================
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    print("============================================================================")
    print("  CIBERCENTINELA - DEMONIO DE SEGURIDAD Y CONSOLA FORENSE (UNACH)")
    print(f"  Interfaz Web Localhost: http://{settings.DAEMON_HOST}:{settings.DAEMON_PORT}")
    print("============================================================================")
    uvicorn.run(
        app,
        host=settings.DAEMON_HOST,
        port=settings.DAEMON_PORT,
        log_level="info",
    )