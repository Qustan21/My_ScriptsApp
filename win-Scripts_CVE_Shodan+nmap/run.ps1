# Установка кодировки UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(65001)
[Console]::InputEncoding = [System.Text.Encoding]::GetEncoding(65001)

if (!(Test-Path "venv")) {
    python -m venv venv
    & ".\venv\Scripts\Activate.ps1"
    pip install -r requirements.txt --quiet
} else {
    & ".\venv\Scripts\Activate.ps1"
}

Clear-Host
# Запуск основного кода
python main.py

# Блок завершения с правильной кодировкой
Write-Host "`n"
Write-Host "========================================" -ForegroundColor Gray
Write-Host "Сессия завершена. Все отчеты сохранены." -ForegroundColor Gray
Read-Host "Нажмите Enter для выхода"