# Richtet den OSINT-Ermittlungsarbeitsplatz unter Windows ein. Ohne Rückfragen, beliebig oft wiederholbar.
#
#   .\setup.cmd                              alles einrichten (startet dieses Skript)
#   .\setup.cmd --nur-pruefen                nur zeigen, was vorhanden ist und was fehlt
#   .\setup.cmd --ermittlungsmodell mythos   Ermittlungsphase auf Claude Mythos 5.2 stellen
#   .\setup.cmd --hilfe                      alle Optionen
#
# Dieses Skript sorgt nur für ein brauchbares Python (3.10 oder neuer, bei Bedarf über winget) und übergibt
# dann an tools\einrichten.py. Dort steht alles Weitere, für Linux, macOS und Windows gemeinsam.
#
# Direkter Aufruf ohne setup.cmd:   powershell -ExecutionPolicy Bypass -File .\setup.ps1
# Läuft mit Windows PowerShell 5.1 und PowerShell 7. Administratorrechte sind nicht nötig.
# Diese Datei ist als UTF-8 mit BOM gespeichert, damit Windows PowerShell 5.1 die Umlaute richtig liest.

$ErrorActionPreference = 'Continue'
Set-Location -LiteralPath $PSScriptRoot
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$env:PYTHONUTF8 = '1'

$Argumente = @($args)
$Darf = $true       # darf dieses Skript Python nachinstallieren?
foreach ($schalter in @('--nur-pruefen', '--nichts-installieren', '--hilfe', '--help', '-h')) {
    if ($Argumente -contains $schalter) { $Darf = $false }
}
$Mindestversion = [version]'3.10.0'
$Log = Join-Path ([System.IO.Path]::GetTempPath()) 'osint-setup\python.log'

function Get-PythonVersion([string]$Pfad) {
    # Gibt die Version zurück oder nichts. Der Platzhalter aus dem Microsoft Store liefert keine Version und zählt nicht.
    if (-not $Pfad) { return $null }
    try {
        $ausgabe = & $Pfad -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null
        if ($LASTEXITCODE -eq 0 -and "$ausgabe" -match '^\d+\.\d+\.\d+$') { return [version]"$ausgabe" }
    } catch { }
    return $null
}

function Find-Python {
    # Reihenfolge: das python aus dem PATH (das benutzt ihr auch sonst), dann der Python-Starter py.
    $kandidaten = @()
    foreach ($name in @('python.exe', 'python3.exe')) {
        foreach ($befehl in @(Get-Command $name -All -ErrorAction SilentlyContinue)) {
            if ($befehl.Path) { $kandidaten += $befehl.Path }
        }
    }
    $starter = Get-Command 'py.exe' -ErrorAction SilentlyContinue
    if ($starter) {
        try {
            $exe = & $starter.Path -3 -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $exe) { $kandidaten += "$exe".Trim() }
        } catch { }
    }
    # Frisch installiert steht Python noch nicht im PATH dieses Fensters: an den üblichen Orten nachsehen.
    $muster = @()
    if ($env:LOCALAPPDATA) { $muster += (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python3*\python.exe') }
    if ($env:ProgramFiles) { $muster += (Join-Path $env:ProgramFiles 'Python3*\python.exe') }
    foreach ($m in $muster) {
        foreach ($datei in @(Get-Item -Path $m -ErrorAction SilentlyContinue)) { $kandidaten += $datei.FullName }
    }
    foreach ($kandidat in $kandidaten) {
        $version = Get-PythonVersion $kandidat
        if ($version -and ($version -ge $Mindestversion)) { return $kandidat }
    }
    return $null
}

function Update-Pfad {
    # Übernimmt neue Einträge aus dem PATH des Systems und des Kontos in dieses Fenster.
    $teile = @($env:Path -split ';' | Where-Object { $_ })
    foreach ($ziel in @('Machine', 'User')) {
        foreach ($teil in @("$([Environment]::GetEnvironmentVariable('Path', $ziel))" -split ';')) {
            if ($teil -and ($teile -notcontains $teil)) { $teile += $teil }
        }
    }
    $env:Path = $teile -join ';'
}

function Install-Python {
    $winget = Get-Command 'winget.exe' -ErrorAction SilentlyContinue
    if (-not $winget) { return $null }
    Write-Host '  + Python 3.10 oder neuer fehlt. Python 3.12 wird über winget für euer Benutzerkonto installiert ...'
    New-Item -ItemType Directory -Force -Path (Split-Path $Log) | Out-Null
    $basis = @('install', '--id', 'Python.Python.3.12', '-e', '--source', 'winget', '--silent',
               '--accept-package-agreements', '--accept-source-agreements')
    # Ältere winget-Versionen kennen nicht jeden Schalter: vom genauesten Aufruf zum einfachsten.
    foreach ($versuch in @('--scope user --disable-interactivity', '--scope user', '')) {
        $zusatz = @()
        if ($versuch) { $zusatz = $versuch.Split(' ') }
        & $winget.Path @basis @zusatz 2>&1 | Out-File -FilePath $Log -Append -Encoding utf8
        Update-Pfad
        $gefunden = Find-Python
        if ($gefunden) { return $gefunden }
    }
    return $null
}

$python = Find-Python
if ((-not $python) -and $Darf) { $python = Install-Python }

if (-not $python) {
    Write-Host ''
    Write-Host 'FEHLER: Python 3.10 oder neuer wird gebraucht und wurde nicht gefunden.' -ForegroundColor Red
    Write-Host '        Installieren:   winget install --id Python.Python.3.12 -e'
    Write-Host '        oder von https://www.python.org/downloads/windows/  (dort "Add python.exe to PATH" ankreuzen).'
    Write-Host '        Danach ein neues Terminal öffnen und .\setup.cmd erneut starten.'
    if (Test-Path -LiteralPath $Log) { Write-Host "        Meldungen von winget: $Log" }
    if (Get-Command 'wsl.exe' -ErrorAction SilentlyContinue) {
        Write-Host '        Alternative mit WSL: das Repository in WSL klonen und dort ./setup.sh starten.'
    }
    exit 1
}

& $python (Join-Path $PSScriptRoot 'tools\einrichten.py') @Argumente
exit $LASTEXITCODE
