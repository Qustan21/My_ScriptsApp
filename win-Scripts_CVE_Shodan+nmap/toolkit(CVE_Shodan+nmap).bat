@echo off
setlocal
:: Запускаем PowerShell в новом окне
start powershell.exe -NoExit -ExecutionPolicy Bypass -File "run.ps1"

echo.
echo ==============================================
echo [OK] PowerShell запущен в отдельном окне.
echo Это окно закроется автоматически через 5 сек.
echo ==============================================
timeout /t 5 >nul
exit