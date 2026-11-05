@echo off
echo [*] Buscando procesos del demonio CiberCentinela en puerto 8090...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8090" ^| findstr "LISTENING"') do (
    echo [+] Deteniendo demonio centinelad (PID %%a)...
    taskkill /F /PID %%a >nul 2>&1
)
echo [+] Servicio CiberCentinela detenido.
pause
