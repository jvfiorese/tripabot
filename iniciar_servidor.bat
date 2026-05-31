@echo off
chcp 65001 > nul
echo.
echo ======================================
echo   TripaBot License Server
echo ======================================
echo.
cd /d "%~dp0"

REM Inicia o servidor
echo Iniciando servidor...
echo Acesse: http://localhost:5000
echo Painel admin: http://localhost:5000/admin
echo.
echo Pressione CTRL+C para parar.
echo.

python server.py
pause
