@echo off
rem Oblion - ouvre une console administrateur dans le dossier d'Oblion.
rem - deja administrateur (cas de WinPE) : console directe ;
rem - sinon : relance de ce fichier en administrateur (UAC) via PowerShell ;
rem - PowerShell absent : console directe (sans droits administrateur).
setlocal
cd /d "%~dp0"

fltmc >nul 2>&1 && goto :console
net session >nul 2>&1 && goto :console

rem Deja relance une fois : ne pas boucler sur la demande UAC.
if /i "%~1"=="--eleve" goto :console

where powershell >nul 2>&1 || goto :console
set "OBLION_BAT=%~f0"
set "OBLION_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:OBLION_BAT -ArgumentList '--eleve' -WorkingDirectory $env:OBLION_DIR -Verb RunAs" >nul 2>&1
if errorlevel 1 (
    echo.
    echo Oblion a besoin des droits administrateur pour acceder aux disques.
    echo La demande a ete refusee : ouverture de la console SANS droits administrateur.
    echo.
    goto :console
)
exit /b 0

:console
title Oblion - console
echo ==========================================================================
echo  Oblion - console (dossier : %~dp0)
echo  OUTIL DESTRUCTIF : verifiez deux fois le disque choisi.
echo ==========================================================================
echo.
echo  oblion-cli --list                         liste des disques
echo  oblion-cli --info N                       details du disque N (lecture seule)
echo  oblion-cli --erase N --confirm XXXX --dry-run
echo                                            simulation : n'ecrit rien
echo  oblion-cli --erase N --confirm XXXX       effacement + certificat PDF
echo  oblion-cli --history                      historique des effacements
echo  oblion-cli --help                         toutes les options
echo.
echo  N = numero du disque dans --list, XXXX = 4 derniers caracteres du n de serie.
echo  Certificats : data\certificates
echo.
cmd /k
