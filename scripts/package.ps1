<#
.SYNOPSIS
    Construit le paquet portable d'Oblion : dist/Oblion-vX.Y.Z/, son zip et le .sha256.

.DESCRIPTION
    1. cargo build --release (sauf -SkipBuild) ;
    2. dossier dist/Oblion-vX.Y.Z/ : les deux exe, Lancer.bat, Lancer-console.bat,
       LISEZMOI.txt, data/ (modèles vides de packaging/), LICENSE, THIRD-PARTY-LICENSES.txt ;
    3. dist/Oblion-vX.Y.Z.zip (dossier Oblion-vX.Y.Z/ à la racine) ;
    4. dist/Oblion-vX.Y.Z.zip.sha256 au format sha256sum (« hash  nom »).
    La version vient de Cargo.toml. Aucune donnée personnelle : les modèles de data/ viennent
    de packaging/, jamais du data/ de travail ; le script vérifie qu'aucun certificat,
    historique ou journal n'est présent.
    Compatible PowerShell 5.1 et 7 (poste local et runner GitHub windows-latest).

.PARAMETER SkipBuild
    Ne recompile pas : utilise les exe release déjà présents.
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$root = Split-Path -Parent $PSScriptRoot
$target = 'x86_64-pc-windows-msvc'
$pkgSrc = Join-Path $root 'packaging'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$utf8Bom = New-Object System.Text.UTF8Encoding($true)

# --- Version (section [package] de Cargo.toml) -------------------------------------------
$cargoToml = [System.IO.File]::ReadAllText((Join-Path $root 'Cargo.toml'), $utf8)
$m = [regex]::Match($cargoToml, '(?ms)^\[package\].*?^version\s*=\s*"([^"]+)"')
if (-not $m.Success) { throw 'version introuvable dans Cargo.toml' }
$version = $m.Groups[1].Value
$name = "Oblion-v$version"
Write-Host "Paquet $name"

# --- Compilation ---------------------------------------------------------------------------
if (-not $SkipBuild) {
    Push-Location $root
    try {
        & cargo build --release --target $target
        if ($LASTEXITCODE -ne 0) { throw "cargo build --release a échoué ($LASTEXITCODE)" }
    }
    finally {
        Pop-Location
    }
}
$bin = Join-Path $root "target\$target\release"
$exes = @('oblion.exe', 'oblion-cli.exe')
foreach ($e in $exes) {
    if (-not (Test-Path -LiteralPath (Join-Path $bin $e))) { throw "$e introuvable dans $bin (compiler d'abord)" }
}

# --- Dossier du paquet ---------------------------------------------------------------------
$dist = Join-Path $root 'dist'
$pkg = Join-Path $dist $name
$zip = Join-Path $dist "$name.zip"
$sha = "$zip.sha256"
if (-not (Test-Path -LiteralPath $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }
foreach ($p in @($pkg, $zip, $sha)) {
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
}
New-Item -ItemType Directory -Path $pkg | Out-Null

foreach ($e in $exes) { Copy-Item -LiteralPath (Join-Path $bin $e) -Destination $pkg }
Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination $pkg

# Copie d'un modèle texte : fins de ligne CRLF, {VERSION} remplacé, BOM au choix.
function Copy-Text([string]$from, [string]$to, [bool]$bom) {
    $t = [System.IO.File]::ReadAllText((Join-Path $pkgSrc $from), $utf8)
    $t = $t.TrimStart([char]0xFEFF).Replace("`r`n", "`n").Replace("`n", "`r`n").Replace('{VERSION}', $version)
    $dest = Join-Path $pkg $to
    $dir = Split-Path -Parent $dest
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $enc = if ($bom) { $utf8Bom } else { $utf8 }
    [System.IO.File]::WriteAllText($dest, $t, $enc)
}

# Fichiers .bat : ASCII, SANS BOM (un BOM casserait la première ligne pour cmd.exe).
Copy-Text 'Lancer.bat' 'Lancer.bat' $false
Copy-Text 'Lancer-console.bat' 'Lancer-console.bat' $false
# Textes à lire dans le Bloc-notes : UTF-8 avec BOM.
Copy-Text 'LISEZMOI.txt' 'LISEZMOI.txt' $true
Copy-Text 'data\assets\LISEZMOI.txt' 'data\assets\LISEZMOI.txt' $true
# TOML : UTF-8 sans BOM (lu par l'outil).
Copy-Text 'data\config.toml' 'data\config.toml' $false
Copy-Text 'data\clients.toml' 'data\clients.toml' $false
foreach ($d in @('certificates', 'history', 'logs')) {
    $dir = Join-Path $pkg "data\$d"
    New-Item -ItemType Directory -Path $dir | Out-Null
    # Fichier vide : garde le dossier dans le zip.
    [System.IO.File]::WriteAllText((Join-Path $dir '.keep'), '', $utf8)
}

& (Join-Path $PSScriptRoot 'third-party-licenses.ps1') -OutFile (Join-Path $pkg 'THIRD-PARTY-LICENSES.txt')

# --- Contrôles : rien de personnel, rien d'inattendu ---------------------------------------
foreach ($d in @('certificates', 'history', 'logs')) {
    $extra = @(Get-ChildItem -LiteralPath (Join-Path $pkg "data\$d") -Force | Where-Object { $_.Name -ne '.keep' })
    if ($extra.Count -gt 0) { throw "data\$d n'est pas vide : $($extra.Name -join ', ')" }
}
$bad = @(Get-ChildItem -LiteralPath $pkg -Recurse -File -Force | Where-Object { $_.Extension -in @('.pdf', '.json', '.csv', '.log', '.pdb') })
if ($bad.Count -gt 0) { throw "fichiers inattendus dans le paquet : $($bad.Name -join ', ')" }
$cfg = [System.IO.File]::ReadAllText((Join-Path $pkg 'data\config.toml'), $utf8)
if ($cfg -match '(?m)^\s*(name|address|contact_name|phone)\s*=\s*"[^"]+"') { throw 'data\config.toml du paquet n''est pas vide' }

# --- Zip (entrées « Oblion-vX.Y.Z/... » avec des « / », dossiers compris) ------------------
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$fs = [System.IO.File]::Open($zip, [System.IO.FileMode]::CreateNew)
try {
    $archive = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $prefix = $pkg.TrimEnd('\') + '\'
        [void]$archive.CreateEntry("$name/")
        $items = Get-ChildItem -LiteralPath $pkg -Recurse -Force | Sort-Object FullName
        foreach ($it in $items) {
            $rel = $it.FullName.Substring($prefix.Length).Replace('\', '/')
            if ($it.PSIsContainer) {
                [void]$archive.CreateEntry("$name/$rel/")
            }
            else {
                [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $archive, $it.FullName, "$name/$rel", [System.IO.Compression.CompressionLevel]::Optimal)
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}
finally {
    $fs.Dispose()
}

# --- Empreinte SHA256 (format sha256sum : « <hash>  <nom> » + LF) ---------------------------
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText($sha, "$hash  $name.zip`n", $utf8)

$size = (Get-Item -LiteralPath $zip).Length
Write-Host ("{0}.zip : {1:N0} octets" -f $name, $size)
Write-Host "SHA256 : $hash"
