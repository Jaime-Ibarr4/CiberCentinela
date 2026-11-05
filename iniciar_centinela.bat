@echo off
title CiberCentinela Daemon Launcher (centinelad)
cd /d "%~dp0"

echo ============================================================================
echo   CIBERCENTINELA - SERVICIO DE SEGURIDAD EN SEGUNDO PLANO (centinelad)
echo   Universidad Autonoma de Chiapas (UNACH)
echo ============================================================================
echo [*] Iniciando demonio CiberCentinela en segundo plano (127.0.0.1:8090)...

start "centinelad-daemon" /B python centinelad.py > centinelad.log 2>&1
timeout /t 2 /nobreak >nul

echo [+] Demonio centinelad en ejecucion en segundo plano.
echo [+] Abriendo interfaz web en http://localhost:8090 ...
start http://localhost:8090
echo.
echo Para detener el servicio en segundo plano, ejecute detener_centinela.bat
pause
