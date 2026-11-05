# REPORTE TÉCNICO Y DE ARQUITECTURA DE SEGURIDAD
## Sistema CiberCentinela: Implementación de Mecanismos de Contención y Control de Acceso Seguro
**Institución:** Universidad Autónoma de Chiapas (UNACH)  
**Asignatura:** Seguridad en Sistemas / Respuesta a Incidentes de Seguridad  
**Actividad:** Desarrollo de Mecanismos de Contención en un Sistema Seguro (Primer Avance)  
**Fecha de Emisión:** Octubre 2026  

---

## RESUMEN EJECUTIVO DEL PROYECTO

El presente documento expone la arquitectura técnica, las políticas de seguridad y la implementación funcional del sistema **CiberCentinela**, una plataforma integral de gestión de incidentes y respuesta defensiva (SOC) desarrollada bajo estándares de **Seguridad por Diseño** (*Security by Design*) y el principio de **Defensa en Profundidad** (*Defense in Depth*).

El sistema cuenta con un demonio de seguridad en segundo plano (`centinelad`), una base de datos relacional MySQL 8.0 robustecida con triggers transaccionales y roles de menor privilegio, un backend en Python/FastAPI con sentencias preparadas y una consola web SPA (*Single Page Application*) que opera localmente con mecanismos activos de detección, prevención y contención de amenazas.

---

## 1. CONTROL DE ACCESO Y AUTENTICACIÓN

### 1.1 Login Seguro con Validación de Credenciales
El acceso al sistema se realiza a través de un esquema multifactorial y validación estricta de identidad:
- **Identificador Institucional:** El sistema exige credenciales basadas en correos institucionales formalizados bajo el dominio `@centinela.local` (validado mediante expresiones regulares y restricción `CHECK` a nivel de base de datos: `chk_usuario_email`).
- **Verificación Criptográfica de Contraseñas:** Se utiliza el algoritmo **bcrypt** con factor de coste de **12 rondas** (`$2y$12$`), garantizando salting dinámico por usuario para mitigar ataques de tablas arcoíris (*rainbow tables*).
- **Validación de Estatus de Cuenta en Tiempo Real:** En cada intento de autenticación y en cada petición HTTP subsiguiente, el sistema consulta de forma sincronizada si el atributo `activo` es igual a `1`. Si la cuenta ha sido suspendida preventiva o administrativamente (`activo = 0`), el acceso se deniega inmediatamente arrojando un código de estado `HTTP 403 Forbidden`.
- **Protección contra Intentos Inválidos:** Si el correo no existe o la contraseña no coincide, el sistema incrementa el contador de intentos fallidos sin revelar si el usuario existe o no, mitigando técnicas de enumeración de cuentas.

### 1.2 Control de Acceso Basado en Roles (RBAC - Role-Based Access Control)
La solución implementa RBAC en dos capas independientes (Backend/API y Motor de Base de Datos MySQL 8.0), garantizando que incluso ante una hipotética vulneración de la capa lógica, el motor de base de datos impida operaciones no autorizadas:

| Rol en el Sistema | Perfil de Base de Datos MySQL | Alcance y Privilegios Asignados | Equivalente Académico |
| :--- | :--- | :--- | :--- |
| **Administrador** | `usr_admin_ciber` (`rol_admin`) | **Acceso total:** Altas y bajas lógicas de usuarios, gestión global de incidentes, configuración del demonio y bot de Telegram, consulta de auditoría completa e inmutable, y ejecución de respaldos en caliente (*mysqldump*). | **Administrador del Sistema** |
| **Analista Forense** | `usr_analista_ciber` (`rol_analista`) | **Acceso operativo:** Consulta general, asignación y cambio de estado de tickets, subida y sellado criptográfico de evidencias forenses (SHA-256), análisis de cabeceras de correo. Restringido: no puede alterar usuarios ni bitácora. | **Profesor / Gestor** (acceso a materias/incidentes bajo su asignación) |
| **Reportador** | `usr_reportador_ciber` (`rol_reportador`) | **Acceso mínimo:** Exclusivamente puede consultar catálogos base y registrar nuevos incidentes. A nivel de MySQL tiene denegado el `SELECT` a la tabla `usuarios`, denegado el acceso a `bitacora_auditoria` y tiene prohibido ejecutar `UPDATE` o `DELETE` sobre cualquier tabla. | **Alumno / Usuario Final** (acceso limitado a su ámbito y registros propios) |

#### Evidencia de Código de la Implementación (centinelad.py / backend/db.py):
```python
# Conexión dinámica a MySQL según el rol del usuario autenticado
def get_db_credentials_by_role(id_rol: int):
    if id_rol == 1:
        return settings.DB_ADMIN_USER, settings.DB_ADMIN_PASS, "rol_admin"
    elif id_rol == 2:
        return settings.DB_ANALYST_USER, settings.DB_ANALYST_PASS, "rol_analista"
    else:
        return settings.DB_REPORTER_USER, settings.DB_REPORTER_PASS, "rol_reportador"
```

---

## 2. MECANISMOS DE CONTENCIÓN

Los mecanismos de contención corresponden a las salvaguardas activas diseñadas para reaccionar de forma autónoma o manual ante incidentes y comportamientos sospechosos, aislando el impacto:

### 2.1 Bloqueo Automático de Cuentas tras Múltiples Intentos Fallidos
Se diseñó un mecanismo de contención por umbrales escalonados gestionado por el módulo `FAILED_LOGIN_TRACKER`:
1. **Primer Umbral (Contención Temporal):** Al registrarse **5 intentos fallidos en una ventana menor a 10 minutos**, la cuenta y la dirección IP atacante quedan temporalmente bloqueadas por **30 minutos**. Cualquier petición dentro de este lapso devuelve `HTTP 429 Too Many Requests`.
2. **Segundo Umbral (Aislamiento Total):** Si el vector de ataque persiste y se alcanzan **10 intentos fallidos acumulados**, el sistema ejecuta una **baja lógica preventiva directa en la base de datos** (`UPDATE usuarios SET activo = 0`), obligando a un desbloqueo manual por parte de un Administrador y registrando la alerta crítica en la bitácora.

#### Evidencia de Código (backend/security.py):
```python
if total_count >= 10:
    execute_prepared("UPDATE usuarios SET activo = 0 WHERE email = ?", (key,), id_rol=1)
    execute_prepared(
        """INSERT INTO bitacora_auditoria (usuario_accion, operacion, tabla_afectada, datos_nuevos, mensaje_critico)
           VALUES (?, 'UPDATE', 'usuarios', ?, ?)""",
        (f"centinelad@{client_ip}", json.dumps({"email": key, "activo": 0}), "ALERTA FUERZA BRUTA: Cuenta deshabilitada.")
    )
    return {"status": "disabled_db", "message": "CUENTA DESHABILITADA EN BD (activo = 0)"}

if recent_count >= 5:
    entry["locked_until"] = now + 1800  # 30 minutos
    return {"status": "temp_locked", "message": "BLOQUEO TEMPORAL (30 MIN)"}
```

### 2.2 Restricción Temporal de Acceso a Módulos Afectados
- Cuando una cuenta es suspendida preventivamente (`activo = 0`), todos los módulos quedan inaccesibles de inmediato.
- Los módulos críticos (administración de usuarios, ejecución de pruebas de laboratorio de seguridad, rotación de respaldos y exportación de bitácoras) cuentan con validación por decorador y dependencia (`Depends(get_current_user)`), validando no solo el token de sesión sino consultando activamente el estado en BD.
- En caso de un compromiso de privilegios sobre el rol reportador, este queda confinado por permisos de MySQL, impidiendo cualquier intento de lectura en módulos de auditoría o administración.

### 2.3 Cierre o Invalidación de Sesiones Sospechosas
- **Cierre Forzado por Inactividad/Revocación:** Al modificarse el estatus de un usuario (`activo = 0`), las peticiones subsiguientes rechazan el token firmado sin importar que su fecha de expiración aún sea válida.
- **Función de Cierre de Sesión Seguro:** Al ejecutar `logoutSession()`, se purgan los tokens en almacenamiento local (`localStorage`) y en las cookies de sesión, finalizando el intervalo de sincronización de telemetría.
- **Tokens Criptográficos Stateless con Expiración:** Los tokens de sesión se generan firmados mediante **HMAC-SHA256** con un *payload* que incluye `id_usuario`, `id_rol`, `email` y tiempo de expiración Unix (`exp`), evitando la manipulación por parte del cliente.

### 2.4 Registro de Acciones en Bitácora (Auditoría Forense Inmutable)
Toda acción transaccional queda asentada en la tabla `bitacora_auditoria`:
- **Estructura del Registro:** Almacena `id_auditoria`, `usuario_accion`, `fecha_hora`, `operacion` (`INSERT`, `UPDATE`, `DELETE`), `tabla_afectada`, `datos_antiguos` (JSON), `datos_nuevos` (JSON) y `mensaje_critico`.
- **Automatización por Disparadores (Triggers MySQL):** Los disparadores `trg_incidentes_after_insert`, `trg_incidentes_after_update` y `trg_incidentes_after_delete` registran las diferencias de estado de forma independiente al código de la aplicación.
- **Garantía de Inmutabilidad:** Se implementó el disparador `trg_bitacora_inmutable_update`, el cual intercepta cualquier intento de modificación o borrado en la bitácora arrojando una excepción `SQLSTATE 45000: ALTERACIÓN PROHIBIDA: La bitácora transaccional es inmutable`.

### 2.5 Notificación al Responsable de Seguridad
- **Cola de Mensajería para Incidentes Críticos:** Ante el registro de un incidente catalogado con severidad **"Crítica"** o la detección de eventos de fuerza bruta, el motor encola automáticamente un mensaje estructurado en la tabla `notificaciones_telegram`.
- **Demonio de Despacho Automatizado:** El demonio `centinelad` monitorea la cola y efectúa el despacho mediante la API oficial de Telegram Bot al canal de mando del SOC, alertando en tiempo real al equipo de seguridad.

---

## 3. GESTIÓN DE CREDENCIALES

### 3.1 Contraseñas Seguras con Expiración
- **Expiración Periódica a 90 Días:** El sistema registra la columna `fecha_ultimo_cambio` en la tabla `usuarios`. Mediante la función `check_password_expiration(fecha_ultimo_cambio, max_days=90)`, si la contraseña supera los 90 días naturales, el inicio de sesión es bloqueado con código `HTTP 403`, obligando al operador a renovar su clave.

### 3.2 Políticas de Complejidad Estricta
La función `validate_password_policy` evalúa obligatoriamente las siguientes reglas criptográficas antes de admitir cualquier contraseña:
1. **Longitud mínima:** Al menos **12 caracteres** alfanuméricos.
2. **Diversidad de caracteres:** Debe contener simultáneamente al menos una letra mayúscula (`[A-Z]`), una letra minúscula (`[a-z]`), un dígito numérico (`[0-9]`) y un símbolo o carácter especial (`[#$@!%&*?_~\\-\\.\\^]`).
3. **No inclusión de datos personales:** Se rechaza la contraseña si contiene fragmentos del nombre del usuario o el prefijo de su correo institucional.
4. **Historial de Contraseñas:** Se almacena el historial de las últimas 5 contraseñas en `PASSWORD_HISTORY_STORE`. Queda estrictamente prohibida la reutilización de cualquiera de estas 5 contraseñas anteriores.

### 3.3 Cifrado y Hashing Seguro
- Se prohíbe el uso de algoritmos obsoletos o vulnerables a colisiones como MD5 o SHA-1 para el resguardo de credenciales.
- Se implementa **bcrypt** con salting pseudoaleatorio de 128 bits integrado y factor de trabajo de **12 rondas** (`$2y$12$`), el cual introduce lentitud calculada para hacer impracticable el ataque por fuerza bruta fuera de línea mediante hardware de alta paralelización (GPU/FPGA).

### 3.4 Verificación en Dos Pasos (2FA / TOTP)
- **Estándar RFC 6238 (Time-based One-Time Password):** Se implementó de manera nativa mediante `verify_totp_code_native`, utilizando HMAC-SHA1 con ventanas de tiempo de 30 segundos y tolerancia de desfase de ±30 segundos.
- **Compatibilidad Universal:** Es compatible con aplicaciones estándar de la industria como **Authy**, **Google Authenticator** o **Microsoft Authenticator**, solicitando un token numérico de 6 dígitos al momento de autenticarse.

---

## 4. PROTECCIÓN CONTRA ATAQUES

### 4.1 Implementación de CAPTCHA y Google reCAPTCHA
Para mitigar el ataque de agentes automatizados, bots de diccionario y scrapers:
- **Google reCAPTCHA v2 ("No soy un robot"):** Integrado en el flujo principal del login. La respuesta del widget es enviada al backend y validada contra los servidores seguros de Google (`https://www.google.com/recaptcha/api/siteverify`) utilizando la clave secreta del sistema y la dirección IP del cliente.
- **CAPTCHA Matemático Local de Respaldo:** En caso de fallas de conectividad externa con Google, el demonio dispone del generador `generate_math_captcha()` que produce desafíos aritméticos con tokens de un solo uso (*single-use*) y tiempo de caducidad de 5 minutos en memoria.

### 4.2 Protección contra Ataques de Fuerza Bruta
- **Monitoreo en Memoria por Par (Usuario, IP):** La estructura `FAILED_LOGIN_TRACKER` almacena timestamps exactos de cada intento fallido.
- **Purga Dinámica:** Los intentos con más de 10 minutos de antigüedad se descartan de la ventana de análisis.
- **Contención Automática Gradual:** Bloqueo temporal preventivo (30 minutos) a los 5 intentos e inhabilitación definitiva en base de datos (`activo = 0`) a los 10 intentos.
- **Herramienta de Simulación para Demostración:** El panel incluye un disparador de pruebas rápidas (`simulateBruteForceAttempt()`) para demostrar ante evaluadores la respuesta inmediata del sistema y el registro del evento en tiempo real.

---

## 5. SEGURIDAD EN SERVICIOS Y SESIONES

### 5.1 Uso de APIs Seguras y Estándares de Autenticación
- **Arquitectura REST con Bearer Token:** Todas las rutas del API bajo `/api/*` (exceptuando login y entrega del catálogo público) exigen el encabezado HTTP:
  ```http
  Authorization: Bearer <token_criptografico>
  ```
- **Firma Criptográfica HMAC-SHA256:** Cada token contiene un cuerpo codificado en Base64 URL-safe y una firma digital calculada con la clave privada `SESSION_SECRET_KEY`. Cualquier alteración del payload invalida la firma (`hmac.compare_digest`) impidiendo ataques de escalamiento de privilegios por manipulación de tokens.
- **Cabeceras de Seguridad HTTP:** Middleware HTTP implementado para inyectar cabeceras que previenen el almacenamiento de datos sensibles en memorias intermedias:
  ```http
  Cache-Control: no-cache, no-store, must-revalidate
  Pragma: no-cache
  Expires: 0
  ```

### 5.2 Gestión Segura de Sesiones
- **Principio de Verificación Continua:** Aunque el token sea matemáticamente válido, la dependencia `get_current_user` valida en cada llamada la presencia del usuario en la base de datos y que su estatus continúe en `activo = 1`. Si un administrador revoca una cuenta, la sesión queda inmediatamente invalidada en la siguiente petición.
- **Cierre de Sesión Robusto:** El método `logoutSession()` invalida las credenciales en el cliente, limpia intervalos de sondeo y retorna la interfaz al formulario de autenticación inicial.

### 5.3 Protección contra Inyección SQL (SQL Injection - SQLi)
- **100% Sentencias Preparadas (Prepared Statements):** Ninguna consulta a la base de datos se realiza mediante concatenación ni interpolación de cadenas de texto (`f-strings` o `%s` directo sin parámetros). Todas las operaciones utilizan la interfaz parametrizada `query_prepared` y `execute_prepared` con marcadores `?`, delegando la separación entre código SQL y datos al analizador nativo del motor MySQL.
- **Defensa en Profundidad con Restricciones CHECK:** La base de datos aplica restricciones directas para impedir datos anómalos:
  - `chk_usuario_email`: Valida estructura formal de correo electrónico.
  - `chk_incidente_severidad`: Restringe severidad estrictamente a `'Baja'`, `'Media'`, `'Alta'`, `'Critica'`.
  - `chk_evidencia_sha256`: Obliga a que el hash registrado sea exactamente de 64 caracteres hexadecimales.
- **Principio de Menor Privilegio en Base de Datos:** Los roles de MySQL (`rol_reportador`, `rol_analista`) tienen revocados los permisos destructivos (`DROP`, `ALTER`, `TRUNCATE`) y solo pueden interactuar con los objetos autorizados para su función.

---

## 6. GUÍA DE EVIDENCIAS Y CAPTURAS DEL SISTEMA PARA LA ENTREGA

Para la conformación del documento final en PDF que se presentará al profesor, se deben anexar las capturas de pantalla obtenidas directamente del sistema en ejecución (`http://127.0.0.1:8090`):

| # | Sección de la Tarea | Vista / Pantalla a Capturar | Qué Debe Observarse en la Captura |
| :---: | :--- | :--- | :--- |
| **1** | Control de acceso y login seguro | Formulario de Login Principal | Campos de correo, contraseña, widget de Google reCAPTCHA v2 y casilla de verificación de Token 2FA Authy. |
| **2** | Mecanismo de contención (Fuerza Bruta) | Alerta roja en pantalla de Login | Mensaje de bloqueo tras presionar *"Probar Intento Fallido (Política 3.5)"* evidenciando el conteo de intentos fallidos. |
| **3** | Control de roles (RBAC) | Barra superior del panel SOC | Usuario autenticado con rol asignado (`Administrador`, `Analista Forense` o `Reportador`) y el usuario MySQL asociado (`usr_admin_ciber`, etc.). |
| **4** | Restricción de módulos | Pestaña *"Usuarios"* con Rol Reportador | Mensaje de denegación de acceso `HTTP 403 Forbidden` demostrando la prohibición de lectura para perfiles no autorizados. |
| **5** | Bitácora de auditoría inmutable | Pestaña *"Bitácora"* (Auditoría Forense) | Registros de operaciones `INSERT`/`UPDATE` con detalle en formato JSON del estado anterior y nuevo. |
| **6** | Notificación al responsable | Pestaña *"Alertas Telegram"* | Cola de notificaciones generadas para incidentes de severidad Crítica con fecha y estado de envío. |
| **7** | Laboratorio de Seguridad en Vivo | Sección *"Laboratorio de Pruebas"* en Bitácora | Ejecución exitosa de la *"Prueba 1: Principio de Menor Privilegio"* o *"Prueba 3: Inmutabilidad de Auditoría"* mostrando el error nativo arrojado por MySQL. |
| **8** | Cadena de Custodia / Evidencias | Pestaña *"Evidencias Forenses"* | Archivos resguardados en bóveda con cálculo y verificación del hash SHA-256. |

---

## 7. CONCLUSIONES TÉCNICAS

El sistema **CiberCentinela** cumple a cabalidad con los requerimientos establecidos para la entrega de Mecanismos de Contención:
1. **Prevención:** Lograda mediante políticas rigurosas de complejidad de contraseñas, hashing bcrypt, autenticación de dos factores (2FA), validación anti-bot (reCAPTCHA) y sentencias preparadas contra SQLi.
2. **Detección:** Evidenciada por el rastreador de intentos fallidos en tiempo real, el analizador de cabeceras de correo con dictamen SPF/DKIM/DMARC y la telemetría continua del demonio `centinelad`.
3. **Contención:** Implementada a través del bloqueo temporal de cuentas e IPs atacantes, la baja lógica automática en base de datos (`activo = 0`), la invalidación inmediata de sesiones sospechosas y el despacho de alertas críticas hacia el responsable de seguridad mediante Telegram.
4. **Integridad y No Repudio:** Respaldada por disparadores transaccionales de auditoría inmutable, sellado pericial de evidencias bajo algoritmo SHA-256 y respaldos en caliente automáticos con retención de 7 días.
