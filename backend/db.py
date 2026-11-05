import datetime
import json
import mysql.connector
from typing import Any, Dict, List, Optional, Tuple
from backend.config import settings


def get_db_credentials_by_role(id_rol: Optional[int] = 1) -> Tuple[str, str, str]:
    """
    Retorna el usuario y contraseña de MySQL 8.0 correspondiente al rol operativo,
    aplicando el Principio de Menor Privilegio directamente en el motor de BD.
    """
    if id_rol == 1:
        return settings.DB_ADMIN_USER, settings.DB_ADMIN_PASS, "rol_admin"
    elif id_rol == 2:
        return settings.DB_ANALYST_USER, settings.DB_ANALYST_PASS, "rol_analista"
    elif id_rol == 3:
        return settings.DB_REPORTER_USER, settings.DB_REPORTER_PASS, "rol_reportador"
    return settings.DB_ADMIN_USER, settings.DB_ADMIN_PASS, "rol_admin"


def get_connection(id_rol: Optional[int] = 1):
    user, password, _ = get_db_credentials_by_role(id_rol)
    return mysql.connector.connect(
        host=settings.DB_HOST,
        port=settings.DB_PORT,
        user=user,
        password=password,
        database=settings.DB_NAME,
        charset="utf8mb4",
    )


def _serialize_val(val: Any) -> Any:
    if isinstance(val, (datetime.datetime, datetime.date)):
        return val.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(val, (bytes, bytearray)):
        try:
            return val.decode("utf-8")
        except Exception:
            return str(val)
    return val


def query_prepared(
    sql: str,
    params: Tuple[Any, ...] = (),
    id_rol: int = 1,
    one: bool = False,
) -> Any:
    """
    Ejecuta una consulta SELECT utilizando sentencias preparadas nativas (prepared=True)
    con marcadores '?' para mitigar al 100% ataques de SQL Injection (Política 2 y 6.1).
    """
    conn = get_connection(id_rol=id_rol)
    cursor = conn.cursor(prepared=True)
    try:
        cursor.execute(sql, params)
        col_names = [desc[0] for desc in cursor.description] if cursor.description else []
        if one:
            row = cursor.fetchone()
            if not row:
                return None
            return {col_names[i]: _serialize_val(row[i]) for i in range(len(col_names))}
        rows = cursor.fetchall()
        result = []
        for r in rows:
            result.append({col_names[i]: _serialize_val(r[i]) for i in range(len(col_names))})
        return result
    finally:
        cursor.close()
        conn.close()


def execute_prepared(
    sql: str,
    params: Tuple[Any, ...] = (),
    id_rol: int = 1,
) -> Dict[str, Any]:
    """
    Ejecuta una operación DML (INSERT, UPDATE, DELETE) con sentencia preparada (prepared=True)
    y retorna lastrowid y rowcount.
    """
    conn = get_connection(id_rol=id_rol)
    cursor = conn.cursor(prepared=True)
    try:
        cursor.execute(sql, params)
        conn.commit()
        return {
            "lastrowid": cursor.lastrowid,
            "rowcount": cursor.rowcount,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()
