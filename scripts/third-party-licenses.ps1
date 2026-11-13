<#
.SYNOPSIS
    Génère THIRD-PARTY-LICENSES.txt : licences des crates réellement liées dans les
    exécutables release d'Oblion (cible x86_64-pc-windows-msvc).

.DESCRIPTION
    - Liste des crates : `cargo tree -e normal,no-proc-macro --target x86_64-pc-windows-msvc`
      (dépendances normales uniquement : ni build-dependencies, ni dev-dependencies, ni macros
      procédurales et leurs dépendances, qui ne sont exécutées qu'à la compilation).
    - Textes : fichiers LICENSE* / LICENCE* / COPYING* / COPYRIGHT* / NOTICE* / UNLICENSE*
      de chaque crate dans le registre local de cargo (~/.cargo/registry/src).
    - Crate sans fichier de licence : identifiant SPDX + texte standard de scripts/licenses/.
    - Les textes identiques (ex. Apache-2.0) ne sont écrits qu'une fois, puis référencés.
    Aucun outil externe : seulement cargo et PowerShell (5.1 ou 7).
    Fichier produit : UTF-8 avec BOM, fins de ligne CRLF (Bloc-notes).

.PARAMETER OutFile
    Chemin du fichier produit (défaut : dist/THIRD-PARTY-LICENSES.txt).
#>
[CmdletBinding()]
param(
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$root = Split-Path -Parent $PSScriptRoot
if (-not $OutFile) { $OutFile = Join-Path $root 'dist\THIRD-PARTY-LICENSES.txt' }
$target = 'x86_64-pc-windows-msvc'
$stdDir = Join-Path $PSScriptRoot 'licenses'

# Sorties de cargo lues en UTF-8 (PowerShell 5 utilise sinon la page de code OEM).
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

Push-Location $root
try {
    # Sources présentes dans le registre local (sans effet si déjà téléchargées).
    & cargo fetch --target $target
    if ($LASTEXITCODE -ne 0) { throw "cargo fetch a échoué ($LASTEXITCODE)" }
    $tree = & cargo tree -e 'normal,no-proc-macro' --target $target --prefix none -f '{p}|{l}|{r}'
    if ($LASTEXITCODE -ne 0) { throw "cargo tree a échoué ($LASTEXITCODE)" }
}
finally {
    Pop-Location
}

# --- Liste des crates (nom, version, licence, dépôt) -----------------------------------
$crates = @{}
foreach ($line in $tree) {
    $parts = $line.Split('|')
    if ($parts.Count -lt 2) { continue }
    $id = $parts[0].Replace(' (*)', '').Trim()
    # Crate racine (« oblion v0.1.0 (D:\...) ») et éventuelles macros : ignorées.
    if ($id -match '\(' -or $id -eq '') { continue }
    $nv = $id.Split(' ')
    if ($nv.Count -ne 2 -or -not $nv[1].StartsWith('v')) { continue }
    $key = "$($nv[0]) $($nv[1])"
    if (-not $crates.ContainsKey($key)) {
        $crates[$key] = [pscustomobject]@{
            Name       = $nv[0]
            Version    = $nv[1].Substring(1)
            License    = $parts[1].Trim()
            Repository = if ($parts.Count -ge 3) { $parts[2].Trim() } else { '' }
        }
    }
}
$list = @($crates.Values | Sort-Object Name, Version)
if ($list.Count -eq 0) { throw 'aucune dépendance trouvée par cargo tree' }

# --- Registre local ---------------------------------------------------------------------
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
$regRoots = @(Get-ChildItem -Path (Join-Path $cargoHome 'registry\src') -Directory | ForEach-Object { $_.FullName })

function Find-CrateDir($c) {
    foreach ($r in $regRoots) {
        $d = Join-Path $r "$($c.Name)-$($c.Version)"
        if (Test-Path -LiteralPath $d) { return $d }
    }
    throw "sources de $($c.Name) $($c.Version) introuvables dans $cargoHome\registry\src"
}

function Read-Text([string]$path) {
    $t = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    $t = $t.TrimStart([char]0xFEFF).Replace("`r`n", "`n").Replace("`r", "`n")
    return $t.Trim("`n", ' ', "`t")
}

function Get-Authors([string]$dir) {
    $toml = Join-Path $dir 'Cargo.toml'
    if (-not (Test-Path -LiteralPath $toml)) { return '' }
    $m = [regex]::Match((Read-Text $toml), '(?ms)^authors\s*=\s*\[(.*?)\]')
    if (-not $m.Success) { return '' }
    $names = [regex]::Matches($m.Groups[1].Value, '"([^"]*)"') | ForEach-Object {
        ($_.Groups[1].Value -replace '\s*<[^>]*>', '').Trim()
    }
    return (@($names | Where-Object { $_ }) -join ', ')
}

function Get-CopyrightLines([string]$text) {
    $text.Split("`n") | ForEach-Object { $_.Trim() } | Where-Object {
        ($_ -cmatch '^(Copyright|©)') -and ($_ -notmatch '\[yyyy\]|<year>|\[year\]|<copyright holders>')
    }
}

# Identifiants SPDX d'une expression (« MIT OR Apache-2.0 », « Apache-2.0/MIT »...).
function Get-SpdxIds([string]$expr) {
    @($expr -split '[\s/()]+' | Where-Object { $_ -and $_ -notin @('OR', 'AND', 'WITH') })
}

# --- Textes dédupliqués -------------------------------------------------------------------
$texts = @{}   # clé normalisée -> n° du texte
$textOwner = @{}
$nextId = 1
function Add-Text([string]$text, [string]$owner) {
    $norm = ($text -replace '\s+', ' ').Trim()
    if ($script:texts.ContainsKey($norm)) {
        return @{ Id = $script:texts[$norm]; New = $false; Owner = $script:textOwner[$norm] }
    }
    $id = $script:nextId
    $script:nextId++
    $script:texts[$norm] = $id
    $script:textOwner[$norm] = $owner
    return @{ Id = $id; New = $true; Owner = $owner }
}

$licPattern = '^(licen[cs]e|copying|copyright|notice|unlicense)'
$sb = New-Object System.Text.StringBuilder
$nl = "`r`n"
function W([string]$s = '') { [void]$script:sb.Append($s.Replace("`n", $script:nl)).Append($script:nl) }

$version = ''
$m = [regex]::Match((Read-Text (Join-Path $root 'Cargo.toml')), '(?m)^version\s*=\s*"([^"]+)"')
if ($m.Success) { $version = $m.Groups[1].Value }

W "LICENCES DES COMPOSANTS TIERS - Oblion $version"
W ('=' * 78)
W ''
W 'Oblion est distribué sous licence MIT (fichier LICENSE). Ses exécutables'
W "(oblion.exe, oblion-cli.exe, cible $target) incluent les bibliothèques Rust"
W 'ci-dessous, chacune sous sa propre licence. Pour une crate sous plusieurs licences'
W 'au choix (« A OR B »), Oblion peut utiliser l''une ou l''autre ; les textes fournis'
W 'par la crate sont reproduits (sauf GPL, non retenue lorsqu''une autre licence est'
W 'proposée au choix).'
W ''
W 'Sont aussi liées : la bibliothèque standard de Rust (MIT OR Apache-2.0,'
W 'https://github.com/rust-lang/rust) et le runtime C de Microsoft Visual C++ (lié'
W 'statiquement, redistribuable selon les conditions de Visual Studio).'
W ''
W 'Liste générée automatiquement par scripts/third-party-licenses.ps1 à partir de'
W '`cargo tree` et des fichiers de licence du registre cargo.'
W ''
W "Crates : $($list.Count)"
W ''
$w = ($list | ForEach-Object { "$($_.Name) $($_.Version)".Length } | Measure-Object -Maximum).Maximum
foreach ($c in $list) {
    W ("  {0}  {1}" -f "$($c.Name) $($c.Version)".PadRight($w), $c.License)
}
W ''

$missing = @()
foreach ($c in $list) {
    $dir = Find-CrateDir $c
    W ('=' * 78)
    W "$($c.Name) $($c.Version)"
    W ('=' * 78)
    W "Licence (SPDX) : $($c.License)"
    if ($c.Repository) { W "Dépôt : $($c.Repository)" }
    $authors = Get-Authors $dir
    if ($authors) { W "Auteurs (Cargo.toml) : $authors" }

    $files = @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -match $licPattern } | Sort-Object Name)
    if ($c.License -match '\bOR\b|/') {
        $files = @($files | Where-Object { $_.Name -notmatch 'GPL' })
    }
    $bodies = @()
    foreach ($f in $files) {
        $bodies += [pscustomobject]@{ Label = "Fichier $($f.Name)"; Text = (Read-Text $f.FullName) }
    }
    if ($bodies.Count -eq 0) {
        $missing += "$($c.Name) $($c.Version)"
        foreach ($sid in (Get-SpdxIds $c.License)) {
            $std = Join-Path $stdDir "$sid.txt"
            if (-not (Test-Path -LiteralPath $std)) { throw "texte standard manquant : scripts/licenses/$sid.txt ($($c.Name))" }
            $bodies += [pscustomobject]@{ Label = "Aucun fichier de licence dans la crate : texte standard $sid"; Text = (Read-Text $std) }
        }
    }

    $copy = @($bodies | ForEach-Object { Get-CopyrightLines $_.Text } | Select-Object -Unique)
    if ($copy.Count -gt 0) {
        W 'Mentions de copyright :'
        foreach ($l in $copy) { W "  $l" }
    }
    elseif ($authors) {
        W "Mentions de copyright : aucune dans les fichiers ; titulaires d'après Cargo.toml : $authors"
    }
    foreach ($b in $bodies) {
        $r = Add-Text $b.Text "$($c.Name) $($c.Version)"
        W ''
        if ($r.New) {
            W "--- $($b.Label) [texte T$($r.Id)] ---"
            W ''
            W $b.Text
        }
        else {
            W "--- $($b.Label) : texte identique à T$($r.Id) (voir $($r.Owner)) ---"
        }
    }
    W ''
}

$dirOut = Split-Path -Parent $OutFile
if ($dirOut -and -not (Test-Path -LiteralPath $dirOut)) { New-Item -ItemType Directory -Path $dirOut | Out-Null }
[System.IO.File]::WriteAllText($OutFile, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

$spdx = @($list | ForEach-Object { Get-SpdxIds $_.License } | Sort-Object -Unique)
Write-Host "THIRD-PARTY-LICENSES.txt : $($list.Count) crates, $($nextId - 1) textes distincts -> $OutFile"
Write-Host "Licences citées : $($spdx -join ', ')"
if ($missing.Count -gt 0) { Write-Host "Sans fichier de licence (texte standard) : $($missing -join ', ')" }
