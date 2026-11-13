@echo off
rem Richtet den OSINT-Ermittlungsarbeitsplatz unter Windows ein.
rem Startet setup.ps1, ohne die Ausfuehrungsrichtlinie von PowerShell dauerhaft zu aendern.
rem
rem   setup.cmd                 alles einrichten
rem   setup.cmd --hilfe         alle Optionen
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
exit /b %ERRORLEVEL%
