import re
import time
import datetime
import json
import hmac
import base64
import hashlib
import bcrypt
import struct
from typing import Dict, List, Optional, Tuple, Any
from backend.config import settings
from backend.db import query_prepared, execute_prepared


# Estado en memoria del demonio para control de fuerza bruta e historial de contraseñas
# Estructura: { key (email o IP): {"attempts": [timestamps], "locked_until": timestamp, "total_failures": int} }
FAILED_LOGIN_TRACKER: Dict[str, Dict[str, Any]] = {}
PASSWORD_HISTORY_STORE: Dict[int, List[str]] = {}


def hash_password_bcrypt(plain_password: str) -> str:
    """
    Genera un hash bcrypt con factor de costo de 12 rondas y salting aleatorio integrado,
    formateado con el prefijo estándar $2y$12$ especificado en la Política 3.
    """
    raw = plain_password.encode("utf-8")
    hashed = bcrypt.hashpw(raw, bcrypt.gensalt(rounds=12)).decode("utf-8")
    return "$2y$" + hashed[4:]


def verify_password_bcrypt(plain_password: str, stored_hash: str) -> bool:
    """
    Verifica una contraseña contra un hash bcrypt ($2y$12$ o $2b$12$).
    """
    if not stored_hash:
        return False
    normalized_hash = stored_hash
    if stored_hash.startswith("$2y$"):
        normalized_hash = "$2b$" + stored_hash[4:]
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), normalized_hash.encode("utf-8"))
    except Exception:
        return False


def validate_password_policy(
    password: str,
    nombre_completo: str = "",
    email: str = "",
    id_usuario: Optional[int] = None,
    current_hash: Optional[str] = None,
) -> Tuple[bool, List[str], Dict[str, bool]]:
    """
    Valida el cumplimiento estricto de la Política 3 (Política de Contraseñas):
    - Longitud mínima de 12 caracteres
    - Al menos una letra mayúscula, una minúscula, un dígito numérico y un símbolo (#, $, @, !, %, etc.)
    - No contener el nombre del usuario ni el identificador del correo institucional
    - No reutilizar ninguna de las últimas 5 contraseñas del historial
    """
    errors = []
    checks = {
        "min_length_12": len(password) >= 12,
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r"[#$@!%&*?_~\-\.^]", password)),
        "no_personal_info": True,
        "not_in_history": True,
    }

    if not checks["min_length_12"]:
        errors.append("La contraseña debe tener al menos 12 caracteres (Política 3.1).")
    if not checks["has_uppercase"]:
        errors.append("Debe incluir al menos una letra mayúscula.")
    if not checks["has_lowercase"]:
        errors.append("Debe incluir al menos una letra minúscula.")
    if not checks["has_digit"]:
        errors.append("Debe incluir al menos un dígito numérico.")
    if not checks["has_special"]:
        errors.append("Debe incluir al menos un símbolo especial (#, $, @, !, %).")

    pwd_lower = password.lower()
    if email and "@" in email:
        email_prefix = email.split("@")[0].lower()
        if len(email_prefix) >= 3 and email_prefix in pwd_lower:
            checks["no_personal_info"] = False
            errors.append(f"No puede contener el identificador del correo ('{email_prefix}').")

    if nombre_completo:
        for token in nombre_completo.lower().split():
            if len(token) >= 3 and token in pwd_lower:
                checks["no_personal_info"] = False
                errors.append(f"No puede contener partes del nombre del usuario ('{token}').")
                break

    # Verificar historial de últimas 5 contraseñas
    history_hashes = []
    if current_hash:
        history_hashes.append(current_hash)
    if id_usuario and id_usuario in PASSWORD_HISTORY_STORE:
        history_hashes.extend(PASSWORD_HISTORY_STORE[id_usuario])

    for old_hash in history_hashes[:5]:
        if verify_password_bcrypt(password, old_hash):
            checks["not_in_history"] = False
            errors.append("Prohibido reutilizar cualquiera de las últimas 5 contraseñas registradas (Política 3.4).")
            break

    return len(errors) == 0, errors, checks


def record_password_history(id_usuario: int, old_hash: str):
    if id_usuario not in PASSWORD_HISTORY_STORE:
        PASSWORD_HISTORY_STORE[id_usuario] = []
    PASSWORD_HISTORY_STORE[id_usuario].insert(0, old_hash)
    PASSWORD_HISTORY_STORE[id_usuario] = PASSWORD_HISTORY_STORE[id_usuario][:5]


def check_brute_force_status(email: str, client_ip: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Política 3.5: Bloqueo por intentos fallidos.
    - 5 intentos fallidos en < 10 min -> bloqueo temporal por 30 minutos para cuenta e IP.
    - 10 intentos fallidos -> deshabilitación preventiva en BD (activo = 0).
    """
    now = time.time()
    key = email.lower().strip()
    entry = FAILED_LOGIN_TRACKER.get(key, {"attempts": [], "locked_until": 0, "total_failures": 0, "ip": client_ip})

    # Limpiar intentos con antigüedad mayor a 10 minutos (600s)
    entry["attempts"] = [t for t in entry["attempts"] if now - t < 600]

    if entry.get("locked_until", 0) > now:
        remaining_min = int((entry["locked_until"] - now) // 60) + 1
        return (
            False,
            f"BLOQUEO TEMPORAL ACTIVO (Política 3.5): Cuenta e IP ({client_ip}) bloqueadas por {remaining_min} min tras 5 intentos fallidos.",
            entry,
        )

    return True, None, entry


def register_failed_login(email: str, client_ip: str) -> Dict[str, Any]:
    now = time.time()
    key = email.lower().strip()
    entry = FAILED_LOGIN_TRACKER.setdefault(
        key, {"attempts": [], "locked_until": 0, "total_failures": 0, "ip": client_ip}
    )
    entry["attempts"] = [t for t in entry["attempts"] if now - t < 600]
    entry["attempts"].append(now)
    entry["total_failures"] += 1
    entry["ip"] = client_ip

    recent_count = len(entry["attempts"])
    total_count = entry["total_failures"]

    # 10 intentos fallidos -> baja lógica preventiva en base de datos (activo = 0)
    if total_count >= 10:
        try:
            execute_prepared(
                "UPDATE usuarios SET activo = 0 WHERE email = ?",
                (key,),
                id_rol=1,
            )
            execute_prepared(
                """INSERT INTO bitacora_auditoria (usuario_accion, operacion, tabla_afectada, datos_nuevos, mensaje_critico)
                   VALUES (?, 'UPDATE', 'usuarios', ?, ?)""",
                (
                    f"centinelad@{client_ip}",
                    json.dumps({"email": key, "activo": 0, "motivo": "10_intentos_fallidos_fuerza_bruta"}),
                    f"ALERTA FUERZA BRUTA: Cuenta {key} deshabilitada preventivamente (activo=0) tras 10 intentos fallidos desde IP {client_ip}.",
                ),
                id_rol=1,
            )
        except Exception:
            pass
        return {
            "status": "disabled_db",
            "recent_attempts": recent_count,
            "total_failures": total_count,
            "message": "CUENTA DESHABILITADA EN BD (activo = 0): Se alcanzaron 10 intentos fallidos. Se notificó al Administrador por posible ataque de fuerza bruta.",
        }

    # 5 intentos fallidos en < 10 minutos -> bloqueo temporal de 30 minutos (1800s)
    if recent_count >= 5:
        entry["locked_until"] = now + 1800
        return {
            "status": "temp_locked",
            "recent_attempts": recent_count,
            "total_failures": total_count,
            "message": f"BLOQUEO TEMPORAL (30 MIN): Se detectaron {recent_count} intentos fallidos en menos de 10 minutos desde {client_ip}.",
        }

    return {
        "status": "failed",
        "recent_attempts": recent_count,
        "total_failures": total_count,
        "message": f"Credenciales inválidas. Intentos fallidos recientes: {recent_count}/5 (Deshabilitación total a los 10: {total_count}/10).",
    }


def reset_failed_login(email: str):
    key = email.lower().strip()
    if key in FAILED_LOGIN_TRACKER:
        del FAILED_LOGIN_TRACKER[key]


def create_session_token(user_data: Dict[str, Any]) -> str:
    payload = {
        "id_usuario": user_data["id_usuario"],
        "nombre_completo": user_data["nombre_completo"],
        "email": user_data["email"],
        "id_rol": user_data["id_rol"],
        "nombre_rol": user_data["nombre_rol"],
        "exp": int(time.time()) + 86400,
    }
    raw_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(raw_json).decode("utf-8")
    sig = hmac.new(
        settings.SESSION_SECRET_KEY.encode("utf-8"),
        b64_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{b64_payload}.{sig}"


def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    if not token or "." not in token:
        return None
    try:
        b64_payload, sig = token.split(".", 1)
        expected_sig = hmac.new(
            settings.SESSION_SECRET_KEY.encode("utf-8"),
            b64_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(b64_payload.encode("utf-8")).decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def check_password_expiration(fecha_ultimo_cambio: Optional[Any], max_days: int = 90) -> Tuple[bool, int]:
    """
    Verifica si la contraseña del usuario ha superado el límite de días permitido (Política de Expiración).
    Retorna (is_expired, days_old).
    """
    if not fecha_ultimo_cambio:
        return False, 0
    
    dt_cambio = fecha_ultimo_cambio
    if isinstance(fecha_ultimo_cambio, str):
        try:
            dt_cambio = datetime.datetime.strptime(fecha_ultimo_cambio, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return False, 0

    if isinstance(dt_cambio, datetime.date) and not isinstance(dt_cambio, datetime.datetime):
        dt_cambio = datetime.datetime.combine(dt_cambio, datetime.time.min)

    now = datetime.datetime.now()
    days_old = (now - dt_cambio).days
    return days_old >= max_days, days_old

# Almacén en memoria para tokens de CAPTCHA
CAPTCHA_STORE: Dict[str, Dict[str, Any]] = {}

def generate_math_captcha() -> Dict[str, Any]:
    """
    Genera un desafío matemático aleatorio para protección contra bots.
    Retorna un captcha_id y la ecuación visual.
    """
    import random
    num1 = random.randint(1, 15)
    num2 = random.randint(1, 15)
    answer = num1 + num2
    
    captcha_id = hashlib.sha256(f"{time.time()}_{num1}_{num2}".encode()).hexdigest()[:12]
    
    # Guardar solución con tiempo de expiración de 5 minutos (300s)
    CAPTCHA_STORE[captcha_id] = {
        "answer": str(answer),
        "expires_at": time.time() + 300
    }
    
    # Limpiar captchas viejos
    now = time.time()
    expired_keys = [k for k, v in CAPTCHA_STORE.items() if v["expires_at"] < now]
    for k in expired_keys:
        del CAPTCHA_STORE[k]
        
    return {
        "captcha_id": captcha_id,
        "question": f"¿Cuánto es {num1} + {num2}?"
    }

def verify_math_captcha(captcha_id: str, user_answer: str) -> bool:
    """
    Verifica la respuesta del CAPTCHA matemático.
    """
    if not captcha_id or captcha_id not in CAPTCHA_STORE:
        return False
        
    data = CAPTCHA_STORE.pop(captcha_id) # Consumir el captcha (un solo uso)
    
    if time.time() > data["expires_at"]:
        return False
        
    return user_answer.strip() == data["answer"]

def verify_google_recaptcha(recaptcha_response: str, client_ip: Optional[str] = None) -> bool:
    """
    Verifica el token de Google reCAPTCHA v2 contra los servidores de Google.
    Permite bypass para pruebas internas de simulación y fuerza bruta ('simulation_bypass').
    """
    if not recaptcha_response:
        return False
        
    if recaptcha_response == "simulation_bypass":
        return True
        
    import requests
    verify_url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {
        "secret": settings.RECAPTCHA_SECRET_KEY,
        "response": recaptcha_response,
    }
    if client_ip and client_ip not in ("127.0.0.1", "localhost", "::1"):
        payload["remoteip"] = client_ip
        
    try:
        resp = requests.post(verify_url, data=payload, timeout=6)
        if resp.status_code == 200:
            result = resp.json()
            return result.get("success", False)
        return False
    except Exception as e:
        print(f"[!] Error contactando con Google reCAPTCHA: {e}")
        return False

def verify_totp_code_native(secret: str, code: str) -> bool:
    """
    Verifica un código TOTP de 6 dígitos (Authy / Google Authenticator) 
    cumpliendo con el RFC 6238 sin librerías externas.
    """
    if not secret or not code:
        return False
    try:
        secret_clean = secret.upper().replace(" ", "")
        padding = "=" * ((8 - len(secret_clean) % 8) % 8)
        key = base64.b32decode(secret_clean + padding)
        
        now = int(time.time() // 30)
        
        # Ventana de tolerancia ±30 segundos
        for offset in (-1, 0, 1):
            counter = struct.pack(">Q", now + offset)
            hm = hmac.new(key, counter, hashlib.sha1).digest()
            offset_idx = hm[-1] & 0x0F
            code_num = (struct.unpack(">I", hm[offset_idx:offset_idx+4])[0] & 0x7FFFFFFF) % 1000000
            
            if f"{code_num:06d}" == code.strip():
                return True
    except Exception:
        pass
    return False