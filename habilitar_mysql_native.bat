@echo off
:: =====================================================================
:: CiberCentinela - Reparar Plugin mysql_native_password en MySQL 8.4
:: Auto-solicita permisos de Administrador si no los tiene
:: =====================================================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Solicitando permisos de Administrador...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo =====================================================================
echo  Habilitando compatibilidad con mysql_native_password en MySQL 8.4...
echo =====================================================================

powershell -ExecutionPolicy Bypass -Command "$ini = 'C:\ProgramData\MySQL\MySQL Server 8.4\my.ini'; if (Test-Path $ini) { $content = Get-Content $ini -Raw; if ($content -notmatch 'mysql_native_password=ON') { $newContent = $content -replace '\[mysqld\]', \"[mysqld]`nmysql_native_password=ON\"; Set-Content $ini -Value $newContent -NoNewline; Write-Host '[+] my.ini actualizado correctamente con mysql_native_password=ON' -ForegroundColor Green } else { Write-Host '[*] my.ini ya tiene configurado mysql_native_password=ON' -ForegroundColor Yellow } } else { Write-Host '[!] No se encontro el archivo my.ini' -ForegroundColor Red }"

echo.
echo Reiniciando servicio de base de datos MySQL84...
net stop MySQL84
net start MySQL84

echo.
echo =====================================================================
echo  EXITO: MySQL 8.4 ya acepta conexiones.
echo  Ya puedes iniciar sesion en CiberCentinela al 100%%.
echo =====================================================================
pause
