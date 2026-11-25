@echo off
title EVM Swiss Army Knife Bot
cd /d "%~dp0"

echo ===================================================
echo     EVM Swiss Army Knife - Telegram Bot Runner
echo ===================================================
echo.

:: Check if Python is installed and available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in your PATH!
    echo Please install Python 3.11+ or ensure it is added to your environment variables.
    echo.
    pause
    exit /b 1
)

:: Check if .env file exists
if not exist ".env" (
    echo [WARNING] .env file not found!
    echo Creating .env from .env.example...
    if exist ".env.example" (
        copy .env.example .env
        echo .env created! Please edit it with your BOT_TOKEN before running.
    ) else (
        echo [ERROR] Neither .env nor .env.example was found!
    )
    echo.
    pause
    exit /b 1
)

echo Starting EVM Swiss Army Knife Bot...
echo Press Ctrl+C in this window anytime to stop the bot.
echo ---------------------------------------------------
echo.

python bot.py

echo.
echo ---------------------------------------------------
echo Bot process exited.
pause
