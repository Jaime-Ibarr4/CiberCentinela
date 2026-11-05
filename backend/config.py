import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"
load_dotenv(dotenv_path=ENV_PATH)

class Settings:
    DAEMON_HOST: str = os.getenv("DAEMON_HOST", "127.0.0.1")
    DAEMON_PORT: int = int(os.getenv("DAEMON_PORT", "8090"))
    DAEMON_INTERVAL_SEC: int = int(os.getenv("DAEMON_INTERVAL_SEC", "15"))

    DB_HOST: str = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
    DB_NAME: str = os.getenv("DB_NAME", "cibercentinela_db")

    DB_ADMIN_USER: str = os.getenv("DB_ADMIN_USER", "usr_admin_ciber")
    DB_ADMIN_PASS: str = os.getenv("DB_ADMIN_PASS", "Admin2026#CiberCentinelaSecure")

    DB_ANALYST_USER: str = os.getenv("DB_ANALYST_USER", "usr_analista_ciber")
    DB_ANALYST_PASS: str = os.getenv("DB_ANALYST_PASS", "Analyst2026#ForenseSecureKey")

    DB_REPORTER_USER: str = os.getenv("DB_REPORTER_USER", "usr_reportador_ciber")
    DB_REPORTER_PASS: str = os.getenv("DB_REPORTER_PASS", "Reporter2026#ReportSafePass")

    DB_BACKUP_USER: str = os.getenv("DB_BACKUP_USER", "root")
    DB_BACKUP_PASS: str = os.getenv("DB_BACKUP_PASS", "roblero14")
    MYSQLDUMP_BIN: str = os.getenv(
        "MYSQLDUMP_BIN",
        r"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqldump.exe",
    )

    FORENSICS_DIR: Path = BASE_DIR / "srv" / "forensics" / "cases"
    BACKUP_DIR: Path = BASE_DIR / "var" / "backups" / "mysql_cibercentinela"
    BACKUP_RETENTION_DAYS: int = int(os.getenv("BACKUP_RETENTION_DAYS", "7"))

    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "")
    TELEGRAM_SIMULATION_MODE: bool = os.getenv("TELEGRAM_SIMULATION_MODE", "true").lower() == "true"

    SESSION_SECRET_KEY: str = os.getenv("SESSION_SECRET_KEY", "CiberCentinela_UNACH_2026_Secret")

    RECAPTCHA_SITE_KEY: str = os.getenv("RECAPTCHA_SITE_KEY", "6LfseAcuAAAAAEiL7seb1wxEyZ_52ZpdqXl8H327")
    RECAPTCHA_SECRET_KEY: str = os.getenv("RECAPTCHA_SECRET_KEY", "6LfseAcuAAAAAMeWWVDZUR6J47ckPl28s84F1l7Q")

settings = Settings()
settings.FORENSICS_DIR.mkdir(parents=True, exist_ok=True)
settings.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
