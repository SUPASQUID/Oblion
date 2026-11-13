@echo off
rem Oblion - lance l'interface graphique (oblion.exe) en administrateur.
rem - deja administrateur (cas de WinPE) : lancement direct ;
rem - sinon : relance de ce fichier en administrateur (UAC) via PowerShell ;
rem - PowerShell absent : lancement direct.
setlocal
cd /d "%~dp0"

fltmc >nul 2>&1 && goto :run
net session >nul 2>&1 && goto :run

rem Deja relance une fois : ne pas boucler sur la demande UAC.
if /i "%~1"=="--eleve" goto :run

where powershell >nul 2>&1 || goto :run
set "OBLION_BAT=%~f0"
set "OBLION_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:OBLION_BAT -ArgumentList '--eleve' -WorkingDirectory $env:OBLION_DIR -Verb RunAs" >nul 2>&1
if errorlevel 1 (
    echo.
    echo Oblion a besoin des droits administrateur pour acceder aux disques.
    echo La demande a ete refusee ou n'a pas pu etre affichee.
    echo Clic droit sur Lancer.bat puis "Executer en tant qu'administrateur".
    echo.
    pause
    exit /b 1
)
exit /b 0

:run
if not exist "%~dp0oblion.exe" (
    echo oblion.exe introuvable dans "%~dp0".
    pause
    exit /b 1
)
start "" /d "%~dp0." "%~dp0oblion.exe"
exit /b 0
