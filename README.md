# CiberCentinela - Daemon & Plataforma SOC Forense

Sistema seguro de gestión de incidentes de ciberseguridad, análisis forense digital y control de acceso basado en roles (RBAC) con persistencia en MySQL 8.0+.

---

## 🛡️ Características Principales

- **Control de Acceso Basado en Roles (RBAC):** Cuentas nativas por rol (`usr_admin_ciber`, `usr_analista_ciber`, `usr_reportador_ciber`) aplicando el Principio de Menor Privilegio.
- **Políticas de Contraseñas Criptográficas:** Hashes bcrypt con factor de coste 12 ($2y$12$).
- **Protección Anti-Bot y Fuerza Bruta:** Integración con Google reCAPTCHA v2 e inhabilitación tras intentos fallidos consecutivos.
- **Autenticación en Dos Pasos (2FA/TOTP):** Compatible con Authy y Google Authenticator (RFC 6238).
- **Análisis Forense Digital:** Verificación de integridad SHA-256 e inspección de cabeceras de correo para detección de phishing (SPF, DKIM, DMARC).
- **Triggers y Auditoría Inmutable:** Registro de auditoría estricto a nivel de base de datos MySQL 8.0.
- **Demonio en Segundo Plano (`centinelad`):** Monitoreo FIM, respaldos en caliente automáticos y alertas por Telegram.

---

## 🚀 Requisitos Previos

1. **Python 3.10+**
2. **MySQL Server 8.0+**
3. Cuenta en Google reCAPTCHA v2 (Checkbox)

---

## ⚙️ Instalación y Configuración

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/Jaime-Ibarr4/CiberCentinela.git
   cd CiberCentinela
   ```

2. **Crear y activar un entorno virtual (recomendado):**
   ```bash
   python -m venv venv
   # En Windows:
   venv\Scripts\activate
   # En Linux/macOS:
   source venv/bin/activate
   ```

3. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configurar variables de entorno:**
   Copia el archivo `.env.example` a `.env` y edita los valores correspondientes:
   ```bash
   cp .env.example .env
   ```

5. **Inicializar Base de Datos y Demonio:**
   Puedes iniciar ejecutando:
   ```bash
   python centinelad.py
   ```
   O usando el script por lotes:
   ```cmd
   iniciar_centinela.bat
   ```

6. **Acceder a la Consola:**
   Abre tu navegador en: [http://127.0.0.1:8090](http://127.0.0.1:8090)
