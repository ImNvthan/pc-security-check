<#
.SYNOPSIS
  Verification complete du PC en une seule commande :
   1. Mise a jour + analyse Microsoft Defender (rapide, complete en option)
   2. Audit Scan-PC (services, taches, demarrage, processus, reseau, navigateurs, VirusTotal)
   3. Autoruns (Microsoft Sysinternals) : tout ce qui demarre sans signature verifiee (telechargement optionnel)
   4. Synthese HTML + liste de controles manuels + analyse Defender hors ligne (optionnelle)
  Aucune suppression ni modification de votre systeme. Rien n'est telecharge sans votre accord.
#>
param([switch]$NoElevate, [switch]$SkipDefender, [switch]$SkipAutoruns, [switch]$NoOpen, [string]$VirusTotalKey)

$ErrorActionPreference = 'Continue'
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$IsAdmin = Test-Admin
if (-not $IsAdmin -and -not $NoElevate) {
    Write-Host "Relance en administrateur (obligatoire pour analyser et lire les journaux)..." -ForegroundColor Yellow
    try {
        $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
        if ($VirusTotalKey) { $a += @('-VirusTotalKey', $VirusTotalKey) }
        Start-Process powershell -Verb RunAs -ArgumentList $a
        exit
    } catch { Write-Host "Elevation refusee : verification partielle." -ForegroundColor Yellow }
}

function Ask($q) {
    if ($NoOpen) { return $false }
    (Read-Host "$q [o/N]") -match '^(o|oui|y|yes)$'
}
function E($s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
function Title($t) { Write-Host ""; Write-Host "=== $t ===" -ForegroundColor Green }

$outDir = Join-Path $PSScriptRoot 'Rapports'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$t0 = Get-Date

# ---------- 1. Defender ----------
$def = [ordered]@{ Ran = $false; Threats = @(); SigVersion = ''; SigAge = ''; Mode = 'ignoree' }
if (-not $SkipDefender -and (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
    Title '1/4  Microsoft Defender'
    if ($IsAdmin) {
        Write-Host 'Mise a jour des signatures...'
        try { Update-MpSignature -ErrorAction Stop } catch { Write-Host "  (mise a jour impossible : $($_.Exception.Message))" -ForegroundColor Yellow }
        $scanType = 'QuickScan'
        if (Ask "Faire l'analyse COMPLETE (1 a 2 h) au lieu de la rapide (quelques minutes) ?") { $scanType = 'FullScan' }
        Write-Host "Analyse $scanType en cours (patientez, ne fermez pas la fenetre)..." -ForegroundColor Cyan
        $ts = Get-Date
        try { Start-MpScan -ScanType $scanType -ErrorAction Stop; $def.Ran = $true; $def.Mode = $scanType } catch { Write-Host "  Analyse impossible : $($_.Exception.Message)" -ForegroundColor Yellow }
        $def.Threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $ts.AddMinutes(-1) })
        $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($st) { $def.SigVersion = $st.AntivirusSignatureVersion; $def.SigAge = $st.AntivirusSignatureAge }
        if ($def.Threats.Count) { Write-Host "  $($def.Threats.Count) menace(s) detectee(s) pendant l'analyse !" -ForegroundColor Red } else { Write-Host '  Aucune nouvelle menace detectee.' -ForegroundColor Green }
    } else { Write-Host 'Droits administrateur requis : etape ignoree.' -ForegroundColor Yellow }
} else { Write-Host 'Etape Defender ignoree.' -ForegroundColor DarkGray }

# ---------- 2. Scan-PC ----------
Title '2/4  Audit systeme (Scan-PC)'
$args2 = @{ NoElevate = $true; NoOpen = $true }
if ($VirusTotalKey) { $args2.VirusTotalKey = $VirusTotalKey }
& (Join-Path $PSScriptRoot 'Scan-PC.ps1') @args2
$scanReport = Get-ChildItem $outDir -Filter 'Rapport_*.html' | Sort-Object LastWriteTime | Select-Object -Last 1
$cnt = @{ High = 0; Warn = 0; Info = 0 }
if ($scanReport) {
    $raw = Get-Content -LiteralPath $scanReport.FullName -Raw -Encoding UTF8
    $cnt.High = ([regex]::Matches($raw, "<span class='b high'>")).Count
    $cnt.Warn = ([regex]::Matches($raw, "<span class='b warn'>")).Count
    $cnt.Info = ([regex]::Matches($raw, "<span class='b info'>")).Count
}

# ---------- 3. Autoruns ----------
$auto = @()
$autoNote = 'Etape ignoree.'
if (-not $SkipAutoruns) {
    Title '3/4  Autoruns (Sysinternals) : demarrages non verifies'
    $tools = Join-Path $PSScriptRoot 'Outils'
    $exe = Join-Path $tools 'autorunsc64.exe'
    if (-not (Test-Path $exe)) {
        if (Ask "Telecharger autorunsc64.exe depuis live.sysinternals.com (outil officiel Microsoft, ~1 Mo) ?") {
            New-Item -ItemType Directory -Force -Path $tools | Out-Null
            try {
                Invoke-WebRequest -Uri 'https://live.sysinternals.com/autorunsc64.exe' -OutFile $exe -UseBasicParsing -ErrorAction Stop
                $sg = Get-AuthenticodeSignature $exe
                if ($sg.Status -ne 'Valid' -or $sg.SignerCertificate.Subject -notmatch 'Microsoft') { Remove-Item $exe -Force; Write-Host '  Signature Microsoft invalide : fichier supprime.' -ForegroundColor Red }
            } catch { Write-Host "  Telechargement impossible : $($_.Exception.Message)" -ForegroundColor Yellow }
        }
    }
    if (Test-Path $exe) {
        Write-Host 'Analyse des points de demarrage...'
        $rows = & $exe -accepteula -nobanner -a '*' -c -h -s -m 2>$null | ConvertFrom-Csv
        $auto = @($rows | Where-Object { $_.'Image Path' -and $_.Signer -notmatch '^\(Verified\)' })
        $autoNote = "$(@($rows).Count) entree(s) non-Microsoft analysee(s), dont $($auto.Count) sans signature verifiee."
        Write-Host "  $autoNote"
    } else { $autoNote = 'Autoruns non disponible (non telecharge).' }
}

# ---------- 4. Synthese ----------
Title '4/4  Synthese'
$verdict = if ($def.Threats.Count -or $cnt.High) { 'Des elements suspects demandent votre attention' } elseif ($cnt.Warn -or $auto.Count) { 'Quelques points a verifier, rien d''alarmant a premiere vue' } else { 'Rien de suspect detecte' }
$vclass = if ($def.Threats.Count -or $cnt.High) { 'high' } elseif ($cnt.Warn -or $auto.Count) { 'warn' } else { 'ok' }

$thRows = foreach ($t in $def.Threats) { "<tr><td>$(E $t.InitialDetectionTime)</td><td class='d'>$(E ($t.Resources -join '; '))</td></tr>" }
$thHtml = if ($def.Threats.Count) { "<table><tr><th>Date</th><th>Fichier</th></tr>$($thRows -join '')</table>" } elseif ($def.Ran) { '<p>Aucune menace detectee par cette analyse.</p>' } else { '<p>Analyse non effectuee.</p>' }

$auRows = foreach ($r in $auto | Select-Object -First 200) {
    $sha = $r.'SHA-256'
    $lk = if ($sha) { "<a target='_blank' href='https://www.virustotal.com/gui/file/$sha'>VirusTotal</a>" } else { '' }
    "<tr><td>$(E $r.Category)</td><td><b>$(E $r.Entry)</b><div class='d'>$(E $r.'Entry Location')</div></td><td class='d'>$(E $r.'Image Path')</td><td>$(E $r.Company)<br>$(E $r.Signer)</td><td>$lk</td></tr>"
}
$auHtml = if ($auto.Count) { "<table><tr><th>Type</th><th>Entree</th><th>Fichier</th><th>Editeur / signature</th><th>Verifier</th></tr>$($auRows -join '')</table>" } else { '<p>Aucune entree non verifiee (ou etape non faite).</p>' }

$scanLink = if ($scanReport) { "<a href='$(E $scanReport.Name)'>Ouvrir le rapport detaille Scan-PC</a>" } else { '' }
$sfile = Join-Path $outDir ("Synthese_{0}_{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmm'))
$html = @"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Synthese de verification</title>
<style>
body{font:14px Segoe UI,Arial,sans-serif;margin:24px;background:#f5f6f8;color:#1b1f24;max-width:1200px}
h1{margin:0 0 4px}h2{margin-top:28px}.sub{color:#667}
.banner{padding:14px 18px;border-radius:8px;color:#fff;font-size:18px;margin:14px 0}.banner.high{background:#c62828}.banner.warn{background:#ef8f00}.banner.ok{background:#2e7d32}
.cards{display:flex;gap:12px;flex-wrap:wrap}.card{padding:12px 20px;border-radius:8px;color:#fff;font-size:13px}.card b{display:block;font-size:26px}
.high{background:#c62828}.warn{background:#ef8f00}.info{background:#546e7a}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden;margin:8px 0}
th,td{padding:7px 10px;text-align:left;border-bottom:1px solid #e5e7eb;vertical-align:top}th{background:#263238;color:#fff}
.d{font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:#455}
.box{background:#fff;padding:12px 18px;border-radius:8px}.box li{margin:6px 0}a{color:#1565c0}
</style></head><body>
<h1>Synthese de verification</h1>
<div class="sub">$(E $env:COMPUTERNAME) - $(Get-Date -Format 'dd/MM/yyyy HH:mm') - duree $([int]((Get-Date) - $t0).TotalMinutes) min - Administrateur : $IsAdmin</div>
<div class="banner $vclass">$verdict</div>

<h2>1. Microsoft Defender</h2>
<p>Mode : $(E $def.Mode) - signatures : $(E $def.SigVersion) (age $(E $def.SigAge) j)</p>
$thHtml

<h2>2. Audit systeme</h2>
<div class="cards"><div class="card high"><b>$($cnt.High)</b>Suspect</div><div class="card warn"><b>$($cnt.Warn)</b>A verifier</div><div class="card info"><b>$($cnt.Info)</b>Probablement normal</div></div>
<p>$scanLink - chaque point y est explique avec les actions conseillees et un lien VirusTotal.</p>

<h2>3. Demarrages non verifies (Autoruns)</h2>
<p>$(E $autoNote) Un element sans signature n'est pas forcement malveillant : cliquez VirusTotal pour trancher.</p>
$auHtml

<h2>4. A faire vous-meme pour une verification vraiment complete</h2>
<div class="box"><ol>
<li><b>Analyse Defender hors ligne</b> (trouve les rootkits caches) : Securite Windows &gt; Protection contre les virus &gt; Options d'analyse &gt; <i>Analyse Microsoft Defender hors ligne</i>.</li>
<li><b>Second avis :</b> installez <a target="_blank" href="https://www.malwarebytes.com/">Malwarebytes Free</a> et lancez une analyse.</li>
<li><b>Extensions du navigateur :</b> relisez la liste dans le rapport Scan-PC (categorie Navigateur) et supprimez ce que vous ne reconnaissez pas.</li>
<li><b>Mots de passe :</b> si un element suspect est confirme, changez vos mots de passe depuis un autre appareil et activez la double authentification.</li>
<li><b>Dernier recours :</b> si un malware est confirme et persistant, sauvegardez vos documents (pas les programmes) et reinstallez Windows.</li>
</ol></div>
<p class="sub">Aucun outil ne garantit a 100 % l'absence de malware : cette verification combine plusieurs methodes independantes pour reduire fortement le risque.</p>
</body></html>
"@
$html | Out-File -FilePath $sfile -Encoding utf8
Write-Host "Synthese : $sfile" -ForegroundColor Green
if (-not $NoOpen) { Start-Process $sfile }

# ---------- Analyse hors ligne (redemarre le PC) ----------
if ($IsAdmin -and -not $SkipDefender -and (Get-Command Start-MpWDOSScan -ErrorAction SilentlyContinue)) {
    Write-Host ""
    if (Ask "Lancer maintenant l'analyse Defender HORS LIGNE ? Le PC va REDEMARRER immediatement (enregistrez votre travail)") {
        Start-MpWDOSScan
    }
}
if (-not $NoOpen) { Read-Host "Appuyez sur Entree pour fermer" | Out-Null }
