-- Script para actualizar los usuarios de CiberCentinela al plugin nativo caching_sha2_password de MySQL 8.4
-- No modifica contrasenas, permisos ni la logica del proyecto.

ALTER USER 'usr_admin_ciber'@'%' IDENTIFIED WITH caching_sha2_password BY 'Admin2026#CiberCentinelaSecure';
ALTER USER 'usr_admin_ciber'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'Admin2026#CiberCentinelaSecure';
ALTER USER 'usr_admin_ciber'@'127.0.0.1' IDENTIFIED WITH caching_sha2_password BY 'Admin2026#CiberCentinelaSecure';

ALTER USER 'usr_analista_ciber'@'%' IDENTIFIED WITH caching_sha2_password BY 'Analyst2026#ForenseSecureKey';
ALTER USER 'usr_analista_ciber'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'Analyst2026#ForenseSecureKey';
ALTER USER 'usr_analista_ciber'@'127.0.0.1' IDENTIFIED WITH caching_sha2_password BY 'Analyst2026#ForenseSecureKey';

ALTER USER 'usr_reportador_ciber'@'%' IDENTIFIED WITH caching_sha2_password BY 'Reporter2026#ReportSafePass';
ALTER USER 'usr_reportador_ciber'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'Reporter2026#ReportSafePass';
ALTER USER 'usr_reportador_ciber'@'127.0.0.1' IDENTIFIED WITH caching_sha2_password BY 'Reporter2026#ReportSafePass';

FLUSH PRIVILEGES;
