-- ============================================================================
-- CIBERCENTINELA: SCRIPT INTEGRAL DE BASE DE DATOS, ROLES Y TRIGGERS (MySQL 8.0+)
-- Universidad Autónoma de Chiapas (UNACH) - Respuesta a Incidentes de Seguridad
-- ============================================================================

CREATE DATABASE IF NOT EXISTS cibercentinela_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE cibercentinela_db;

-- 1. TABLA: roles
CREATE TABLE IF NOT EXISTS roles (
    id_rol INT AUTO_INCREMENT PRIMARY KEY,
    nombre_rol VARCHAR(50) NOT NULL UNIQUE,
    descripcion TEXT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
) ENGINE=InnoDB;

-- 2. TABLA: usuarios
CREATE TABLE IF NOT EXISTS usuarios (
    id_usuario INT AUTO_INCREMENT PRIMARY KEY,
    nombre_completo VARCHAR(150) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    id_rol INT NOT NULL,
    activo TINYINT(1) DEFAULT 1 NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_usuarios_roles FOREIGN KEY (id_rol)
        REFERENCES roles(id_rol) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT chk_usuario_email CHECK (email LIKE '%_@__%.__%')
) ENGINE=InnoDB;

-- 3. TABLA: categorias_incidentes
CREATE TABLE IF NOT EXISTS categorias_incidentes (
    id_categoria INT AUTO_INCREMENT PRIMARY KEY,
    nombre_categoria VARCHAR(100) NOT NULL UNIQUE,
    descripcion TEXT NULL
) ENGINE=InnoDB;

-- 4. TABLA: estados_incidentes
CREATE TABLE IF NOT EXISTS estados_incidentes (
    id_estado INT AUTO_INCREMENT PRIMARY KEY,
    nombre_estado VARCHAR(50) NOT NULL UNIQUE,
    descripcion TEXT NULL
) ENGINE=InnoDB;

-- 5. TABLA: incidentes
CREATE TABLE IF NOT EXISTS incidentes (
    id_incidente INT AUTO_INCREMENT PRIMARY KEY,
    codigo_ticket VARCHAR(25) NOT NULL UNIQUE,
    titulo VARCHAR(200) NOT NULL,
    descripcion TEXT NOT NULL,
    severidad VARCHAR(20) NOT NULL,
    id_categoria INT NOT NULL,
    id_estado INT NOT NULL,
    id_usuario_reportador INT NOT NULL,
    id_analista_asignado INT NULL,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_incidentes_categoria FOREIGN KEY (id_categoria)
        REFERENCES categorias_incidentes(id_categoria) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_incidentes_estado FOREIGN KEY (id_estado)
        REFERENCES estados_incidentes(id_estado) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_incidentes_reportador FOREIGN KEY (id_usuario_reportador)
        REFERENCES usuarios(id_usuario) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT fk_incidentes_analista FOREIGN KEY (id_analista_asignado)
        REFERENCES usuarios(id_usuario) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT chk_incidente_severidad CHECK (severidad IN ('Baja', 'Media', 'Alta', 'Critica'))
) ENGINE=InnoDB;

-- 6. TABLA: evidencias_forenses
CREATE TABLE IF NOT EXISTS evidencias_forenses (
    id_evidencia INT AUTO_INCREMENT PRIMARY KEY,
    id_incidente INT NOT NULL,
    nombre_archivo VARCHAR(255) NOT NULL,
    ruta_almacenamiento VARCHAR(512) NOT NULL,
    hash_sha256 CHAR(64) NOT NULL,
    tamano_bytes BIGINT NOT NULL,
    fecha_subida TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    id_usuario_carga INT NOT NULL,
    CONSTRAINT fk_evidencias_incidente FOREIGN KEY (id_incidente)
        REFERENCES incidentes(id_incidente) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_evidencias_usuario FOREIGN KEY (id_usuario_carga)
        REFERENCES usuarios(id_usuario) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT chk_evidencia_sha256 CHECK (LENGTH(hash_sha256) = 64)
) ENGINE=InnoDB;

-- 7. TABLA: bitacora_auditoria (Auditoría Forense Inmutable)
CREATE TABLE IF NOT EXISTS bitacora_auditoria (
    id_auditoria BIGINT AUTO_INCREMENT PRIMARY KEY,
    usuario_accion VARCHAR(100) NOT NULL,
    fecha_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    operacion VARCHAR(10) NOT NULL,
    tabla_afectada VARCHAR(100) NOT NULL,
    datos_antiguos JSON NULL,
    datos_nuevos JSON NULL,
    mensaje_critico TEXT NULL,
    CONSTRAINT chk_auditoria_operacion CHECK (operacion IN ('INSERT', 'UPDATE', 'DELETE'))
) ENGINE=InnoDB;

-- 8. TABLA: historico_incidentes (Versionado para recuperación de datos)
CREATE TABLE IF NOT EXISTS historico_incidentes (
    id_historico BIGINT AUTO_INCREMENT PRIMARY KEY,
    id_incidente INT NOT NULL,
    codigo_ticket VARCHAR(25) NOT NULL,
    titulo VARCHAR(200) NOT NULL,
    descripcion TEXT NOT NULL,
    severidad VARCHAR(20) NOT NULL,
    id_estado INT NOT NULL,
    id_analista_asignado INT NULL,
    fecha_modificacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    usuario_modificador VARCHAR(100) NOT NULL
) ENGINE=InnoDB;

-- 9. TABLA: notificaciones_telegram (Cola de Alertas Críticas)
CREATE TABLE IF NOT EXISTS notificaciones_telegram (
    id_notificacion BIGINT AUTO_INCREMENT PRIMARY KEY,
    id_incidente INT NOT NULL,
    mensaje TEXT NOT NULL,
    estado_envio VARCHAR(20) DEFAULT 'Pendiente' NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    fecha_envio TIMESTAMP NULL,
    CONSTRAINT fk_notif_incidente FOREIGN KEY (id_incidente)
        REFERENCES incidentes(id_incidente) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT chk_notif_estado CHECK (estado_envio IN ('Pendiente', 'Enviado', 'Error'))
) ENGINE=InnoDB;
