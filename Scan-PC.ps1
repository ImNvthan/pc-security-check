<#
.SYNOPSIS
  Audit de securite en LECTURE SEULE : cherche les elements suspects sur le PC
  (services, taches planifiees, demarrage, processus, reseau, config, journaux).
  Ne modifie, ne supprime et n'envoie rien. Genere un rapport HTML.
#>
param([switch]$NoElevate, [switch]$NoOpen, [string]$VirusTotalKey)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$IsAdmin = Test-Admin
if (-not $IsAdmin -and -not $NoElevate) {
    Write-Host "Relance en administrateur (necessaire pour lire les journaux et tous les processus)..." -ForegroundColor Yellow
    try {
        Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
        exit
    } catch { Write-Host "Elevation refusee : scan partiel en utilisateur normal." -ForegroundColor Yellow }
}

$Findings = New-Object System.Collections.Generic.List[object]

# Base de conseils : premiere regle qui correspond au titre = explication + action
$Advice = @(
 @{ Rx='ligne de commande suspecte'; Why="Cette commande utilise des techniques courantes chez les malwares (code encode, telechargement, fenetre cachee). Certains installeurs legitimes le font aussi, mais c'est rare."; Do="Si vous n'avez pas configure cela vous-meme : desactivez l'element, puis scannez avec Defender (analyse complete) et Malwarebytes." },
 @{ Rx='MODIFIE'; Why="Le fichier a une signature numerique, mais il a ete altere apres coup : signe typique d'un fichier infecte ou corrompu."; Do="Reinstallez le logiciel depuis le site officiel et verifiez le fichier sur VirusTotal (lien dans le rapport)." },
 @{ Rx='signature non approuvee'; Why="Le fichier est signe, mais par un certificat que Windows ne reconnait pas (expire, revoque ou auto-signe)."; Do="Verifiez l'editeur et le hash sur VirusTotal. Courant pour de vieux logiciels ou des outils de bricolage." },
 @{ Rx='non signe, dans un dossier a risque'; Why="Programme anonyme lance depuis Temp/Telechargements/Public : c'est l'emplacement favori des malwares."; Do="Si vous ne reconnaissez pas le nom : verifiez sur VirusTotal, puis supprimez-le si doute." },
 @{ Rx='non signe'; Why="Aucune signature : impossible de savoir qui a cree le programme. Normal pour beaucoup de jeux, mods et petits outils, mais les malwares ne sont jamais signes non plus."; Do="Reconnaissez-vous ce logiciel ? Si oui, c'est bon. Sinon verifiez le hash sur VirusTotal (lien dans le rapport)." },
 @{ Rx='dossier a risque'; Why="Programme (signe) lance depuis un dossier temporaire : parfois un installeur en cours, parfois suspect."; Do="Verifiez que vous avez bien lance un installeur recemment." },
 @{ Rx='orpheline'; Why="Une entree pointe vers un fichier qui n'existe plus : reste d'un logiciel desinstalle. Sans danger en soi."; Do="Rien d'urgent. Peut etre nettoyee avec l'outil Autoruns (Microsoft Sysinternals)." },
 @{ Rx='chemin non protege'; Why="Service dont le chemin contient des espaces sans guillemets : faille d'escalade de privileges theorique (rarement exploitee)."; Do="Faible priorite. Mettre a jour le logiciel concerne." },
 @{ Rx='Usurpation'; Why="Un programme porte le nom d'un processus Windows vital mais ne se trouve pas dans System32 : technique classique de camouflage."; Do="Tres suspect : verifiez le chemin et le hash, scannez immediatement." },
 @{ Rx='controle a distance actif'; Why="Un outil de prise de controle a distance tourne. Legitime si vous l'avez installe, tres dangereux sinon (arnaques au faux support)."; Do="Si vous ne vous en servez pas, desinstallez-le." },
 @{ Rx='Defender DESACTIVE|temps reel desactivee'; Why="La protection antivirus est coupee : malware ou reglage manuel."; Do="Reactivez-la dans Securite Windows > Protection contre les virus." },
 @{ Rx='Exclusion Defender'; Why="Defender ignore cet element : les malwares ajoutent des exclusions pour ne pas etre detectes."; Do="Reconnaissez-vous cette exclusion ? Sinon retirez-la dans Securite Windows > Gerer les parametres > Exclusions." },
 @{ Rx='Menace detectee'; Why="Defender a deja detecte (et normalement bloque) ce fichier. Les cracks, keygens et installeurs d'origine douteuse sont souvent concernes."; Do="Verifiez dans Securite Windows > Historique de protection que la menace est bien supprimee. Ne relancez pas ce fichier." },
 @{ Rx='Pare-feu desactive'; Why="Le pare-feu est coupe pour ce profil reseau."; Do="Reactivez-le : Securite Windows > Pare-feu." },
 @{ Rx='UAC desactive'; Why="Plus aucune confirmation avant les actions administrateur : un malware s'installe sans alerte."; Do="Reactivez le controle de compte utilisateur." },
 @{ Rx='SMBv1'; Why="Protocole obsolete exploite par WannaCry."; Do="Desactivez-le : Fonctionnalites Windows > Support de partage de fichiers SMB 1.0." },
 @{ Rx='RDP|3389'; Why="Le Bureau a distance permet de controler ce PC depuis un autre. Exposee a Internet, c'est une des portes d'entree favorites des pirates (force brute)."; Do="Si vous ne l'utilisez pas : Parametres > Systeme > Bureau a distance > Desactive. Ne jamais l'ouvrir sur Internet sans VPN." },
 @{ Rx='hosts'; Why="Le fichier hosts force un nom de site vers une adresse IP precise. Les malwares s'en servent pour rediriger vers de faux sites."; Do="Si vous reconnaissez la ligne (ex. serveur d'ecole/entreprise), c'est bon. Sinon supprimez-la (Bloc-notes en administrateur)." },
 @{ Rx='Partage reseau'; Why="Ce dossier est accessible depuis le reseau local."; Do="Si vous ne partagez rien volontairement, supprimez le partage (clic droit > Proprietes > Partage)." },
 @{ Rx='sans mot de passe'; Why="Compte utilisable sans mot de passe : n'importe qui ayant acces au PC (ou au reseau) peut s'y connecter."; Do="Definissez un mot de passe ou un code PIN Windows Hello." },
 @{ Rx='Compte integre|Invite active'; Why="Compte special de Windows normalement desactive."; Do="Desactivez-le sauf besoin precis." },
 @{ Rx='Membre du groupe Administrateurs'; Why="Ce compte a tous les droits sur le PC."; Do="Verifiez que chaque nom est un compte que vous connaissez." },
 @{ Rx='DNS'; Why="Un DNS malveillant peut vous rediriger vers de faux sites (hameconnage)."; Do="Verifiez qu'il correspond a votre box/FAI ou a un DNS que vous avez choisi (Google, Cloudflare...)." },
 @{ Rx='Proxy'; Why="Tout votre trafic web passe par un intermediaire : parfois un malware espion."; Do="Si vous n'utilisez pas de proxy/VPN : Parametres > Reseau > Proxy > tout desactiver." },
 @{ Rx='Port en ecoute|Connexion sortante'; Why="Un programme attend ou etablit une connexion reseau inhabituelle (port rare ou programme dans un dossier a risque)."; Do="Identifiez le programme (chemin dans Detail) puis verifiez-le sur VirusTotal." },
 @{ Rx='EFFACE'; Why="Quelqu'un a vide le journal de securite : technique pour effacer ses traces."; Do="Si ce n'etait pas vous, considerez le PC comme potentiellement compromis." },
 @{ Rx='echecs de connexion'; Why="Beaucoup de mots de passe errones en peu de temps : tentative de devinette (force brute)."; Do="Verifiez que RDP/partages ne sont pas exposes a Internet ; changez vos mots de passe." },
 @{ Rx='Nouveau service installe'; Why="Un service a ete ajoute recemment. Normal apres l'installation d'un logiciel."; Do="Verifiez que vous reconnaissez le nom et la date." },
 @{ Rx='Compte utilisateur cree'; Why="Un compte a ete cree recemment."; Do="Si ce n'etait pas vous, supprimez-le et changez vos mots de passe." },
 @{ Rx='Winlogon|IFEO|AppInit|WMI'; Why="Mecanisme de demarrage furtif tres rarement utilise par des logiciels legitimes."; Do="Tres suspect si vous n'avez rien configure de tel : scannez et faites verifier." },
 @{ Rx='Extension navigateur'; Why="Une extension peut lire et modifier tout ce que vous faites sur les sites (mots de passe, cookies, pages bancaires). Les extensions malveillantes sont tres repandues."; Do="Gardez uniquement celles que vous avez installees vous-meme et que vous utilisez. Supprimez-en une dont vous ignorez l'origine (chrome://extensions ou edge://extensions)." },
 @{ Rx='Signe par'; Why="Programme signe par un editeur absent de ma liste de confiance. Signature valide = fichier non altere, mais il faut connaitre l'editeur."; Do="Reconnaissez-vous cet editeur ? Si oui c'est bon." },
 @{ Rx='non execute en administrateur'; Why="Sans droits administrateur, journaux et exclusions Defender sont illisibles."; Do="Relancez via Lancer-Scan.bat et acceptez l'elevation." }
)

$Trusted = 'Microsoft|Google|Mozilla|NVIDIA|Intel|Advanced Micro Devices|\bAMD\b|Realtek|Valve|Epic Games|Ubisoft|Riot Games|Adobe|Discord|Logitech|Corsair|Razer|ASUS|Dell|HP Inc|Hewlett|Lenovo|Apple|Oracle|Brave|Electronic Arts|Blizzard|Activision|Spotify|Zoom|Cloudflare|Malwarebytes|Opera|JetBrains|GitHub|Python Software|Anthropic|VideoLAN|OBS|Overwolf|Samsung|Qualcomm|SteelSeries|Wacom|Autodesk|Bambu|Prusa|Creality|Ultimaker|Dropbox|Slack|Notepad|Git|Node\.js|OpenJS|Docker|VMware|Citrix|Cisco|TeamViewer|AnyDesk|Mullvad|Proton|NordVPN|Nvidia|Realtek|Qualcomm|MediaTek|Broadcom|Killer|Rivet|Elgato|Blackmagic|Roblox|Rockstar|EasyAntiCheat|Apowersoft|Nefarius|Bitdefender|Kaspersky|ESET|Avast|AVG|Norton|McAfee'

$hashCache = @{}
function Add-Finding($Cat, $Sev, $Title, $Detail, $Why = '', $Do = '', $File = $null) {
    if (-not $Why) {
        foreach ($a in $Advice) { if ($Title -match $a.Rx) { $Why = $a.Why; if (-not $Do) { $Do = $a.Do }; break } }
    }
    $sha = ''; $signer = ''; $date = ''; $status = ''
    if ($File -and (Test-Path -LiteralPath $File -PathType Leaf)) {
        $sg = Get-SigInfo $File
        if ($sg) { $signer = $sg.Signer; $status = $sg.Status }
        $date = (Get-Item -LiteralPath $File).LastWriteTime.ToString('dd/MM/yyyy')
        if ($Sev -ne 'OK') {
            if (-not $hashCache.ContainsKey($File)) { $hashCache[$File] = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash }
            $sha = $hashCache[$File]
        }
    }
    $Findings.Add([pscustomobject]@{ Cat = $Cat; Sev = $Sev; Title = $Title; Detail = $Detail; Why = $Why; Do = $Do
        File = $File; Sha = $sha; Signer = $signer; SigStatus = $status; Date = $date; VT = '' })
}

# ---------- Outils ----------
$sigCache = @{}
function Get-SigInfo($p) {
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null }
    if ($sigCache.ContainsKey($p)) { return $sigCache[$p] }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        $signer = ''
        if ($s.SignerCertificate) { $signer = ($s.SignerCertificate.Subject -replace '^.*?CN=([^,]+).*$', '$1') }
        $r = [pscustomobject]@{ Status = $s.Status.ToString(); Signer = $signer }
    } catch { $r = [pscustomobject]@{ Status = 'Error'; Signer = '' } }
    $sigCache[$p] = $r
    $r
}

function Get-ExePath($cmd) {
    if (-not $cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    if ($c -match '^"([^"]+)"') { return $matches[1] }
    if ($c -match '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|dll|scr))(\s|$)') { return $matches[1] }
    ($c -split '\s+')[0]
}

$RiskDir  = '\\(Temp|Downloads|Users\\Public|\$Recycle\.Bin|PerfLogs)\\|\\AppData\\Local\\Temp\\'
$UserDir  = '\\Users\\[^\\]+\\(AppData|Desktop|Documents)\\|\\ProgramData\\'
$SafeDir  = '^C:\\Windows\\|^C:\\Program Files( \(x86\))?\\'
$SusCmd   = '-enc(odedcommand)?\s|FromBase64String|DownloadString|DownloadFile|Invoke-Expression|\biex\b|-w(indowstyle)?\s+hidden|mshta|regsvr32.+(http|/i:)|rundll32.+(http|javascript)|certutil.+(-urlcache|-decode)|bitsadmin.+/transfer|cmd(\.exe)?\s+/c\s+(start|powershell)'

# Verifie un binaire lance par $Cat/$Name ; classe en OK / Info / Warn / High
function Test-Binary($Cat, $Name, $Cmd) {
    $path = Get-ExePath $Cmd
    if (-not $path) { return }
    if ($Cmd -match $SusCmd) {
        Add-Finding $Cat 'High' "$Name : ligne de commande suspecte" $Cmd '' '' $path
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        if ($path -match '\.(exe|bat|cmd|ps1|vbs|dll)$') {
            Add-Finding $Cat 'Info' "$Name : binaire introuvable (entree orpheline)" $path
        }
        return
    }
    $sig = Get-SigInfo $path
    $detail = "$path  [signature: $($sig.Status)$(if($sig.Signer){' - ' + $sig.Signer})]"
    switch -Regex ($sig.Status) {
        'HashMismatch' { Add-Finding $Cat 'High' "$Name : fichier signe mais MODIFIE" $detail '' '' $path; return }
        'NotTrusted|UnknownError' { Add-Finding $Cat 'Warn' "$Name : signature non approuvee" $detail '' '' $path; return }
        'NotSigned' {
            if ($path -match $RiskDir)       { Add-Finding $Cat 'High' "$Name : non signe, dans un dossier a risque" $detail '' '' $path }
            elseif ($path -match $UserDir)   { Add-Finding $Cat 'Warn' "$Name : non signe, dans un dossier utilisateur" $detail '' '' $path }
            elseif ($path -notmatch $SafeDir){ Add-Finding $Cat 'Warn' "$Name : non signe, emplacement inhabituel" $detail '' '' $path }
            else                             { Add-Finding $Cat 'Info' "$Name : non signe (Program Files/Windows)" $detail '' '' $path }
            return
        }
    }
    if ($path -match $RiskDir) { Add-Finding $Cat 'Warn' "$Name : execute depuis un dossier a risque" $detail '' '' $path; return }
    if ($sig.Status -eq 'Valid') {
        if ($sig.Signer -match $Trusted) { Add-Finding $Cat 'OK' "$Name : signe par $($sig.Signer)" $path '' '' $path }
        else { Add-Finding $Cat 'Info' "$Name : signe par $($sig.Signer) (editeur a verifier)" $detail '' '' $path }
    }
}

$step = 0; $total = 11
function Step($t) { $script:step++; Write-Host ("[{0}/{1}] {2}" -f $script:step, $total, $t) -ForegroundColor Cyan }

Write-Host ""
Write-Host "=== Scan-PC : audit de securite (lecture seule) ===" -ForegroundColor Green
Write-Host ("Machine : {0} | Utilisateur : {1} | Admin : {2}" -f $env:COMPUTERNAME, $env:USERNAME, $IsAdmin)
if (-not $IsAdmin) { Add-Finding 'Scan' 'Warn' 'Scan non execute en administrateur' 'Journaux d''evenements et certains processus inaccessibles : resultats partiels.' }

# ---------- 1. Services ----------
Step 'Services'
$svcs = Get-CimInstance Win32_Service
foreach ($s in $svcs) {
    $cmd = $s.PathName
    if (-not $cmd) { continue }
    if ($cmd -notmatch '^"' -and $cmd -match '^[A-Za-z]:\\.* .*\.exe' -and $cmd -notmatch '^[A-Za-z]:\\(Windows|Program Files( \(x86\))?)\\') {
        $first = ($cmd -split '\.exe')[0]
        if ($first -match ' ') { Add-Finding 'Services' 'Warn' "$($s.Name) : chemin non protege par des guillemets (risque d'escalade)" $cmd }
    }
    if ($cmd -match '^"?[A-Za-z]:\\Windows\\') {
        if ($cmd -match $SusCmd) { Add-Finding 'Services' 'High' "$($s.Name) : ligne de commande suspecte" $cmd }
        continue
    }
    Test-Binary 'Services' "$($s.Name) ($($s.DisplayName), $($s.StartMode)/$($s.State))" $cmd
}

# ---------- 2. Taches planifiees ----------
Step 'Taches planifiees'
foreach ($t in (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
    foreach ($a in $t.Actions) {
        if (-not $a.Execute) { continue }
        $cmd = ('"' + $a.Execute + '" ' + $a.Arguments).Trim()
        Test-Binary 'Taches' ("{0}{1}" -f $t.TaskPath, $t.TaskName) $cmd
    }
}

# ---------- 3. Persistance / demarrage ----------
Step 'Demarrage automatique et persistance'
$runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
           'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
           'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
           'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
foreach ($k in $runKeys) {
    $item = Get-ItemProperty -Path $k
    if (-not $item) { continue }
    foreach ($p in $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
        Test-Binary 'Demarrage' "$($p.Name) [$k]" ([string]$p.Value)
    }
}
$startDirs = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
foreach ($d in $startDirs) {
    foreach ($f in (Get-ChildItem -LiteralPath $d -File -Force | Where-Object { $_.Name -ne 'desktop.ini' })) {
        $target = $f.FullName
        if ($f.Extension -eq '.lnk') { try { $target = (New-Object -ComObject WScript.Shell).CreateShortcut($f.FullName).TargetPath } catch {} }
        Test-Binary 'Demarrage' "Dossier Demarrage : $($f.Name)" $target
    }
}
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl.Shell -and $wl.Shell -ne 'explorer.exe') { Add-Finding 'Demarrage' 'High' 'Winlogon Shell modifie' $wl.Shell }
if ($wl.Userinit -and $wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Add-Finding 'Demarrage' 'High' 'Winlogon Userinit modifie' $wl.Userinit }
$ifeo = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($i in $ifeo) {
    $dbg = (Get-ItemProperty $i.PSPath).Debugger
    if ($dbg) { Add-Finding 'Demarrage' 'High' "IFEO Debugger detourne : $($i.PSChildName)" $dbg }
}
$appInit = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows').AppInit_DLLs
if ($appInit) { Add-Finding 'Demarrage' 'High' 'AppInit_DLLs renseigne' $appInit }
$wmiCons = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
foreach ($w in ($wmiCons | Where-Object { $_.Name -ne 'SCM Event Log Consumer' })) { Add-Finding 'Demarrage' 'High' "Abonnement WMI permanent : $($w.Name)" ($w | Out-String).Trim() }

# ---------- 4. Processus ----------
Step 'Processus en cours'
$sysNames = 'svchost','lsass','csrss','winlogon','services','smss','wininit','explorer','taskhostw','spoolsv','dwm'
$procs = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath }
$seen = @{}
foreach ($p in $procs) {
    $path = $p.ExecutablePath
    $base = [IO.Path]::GetFileNameWithoutExtension($path).ToLower()
    if ($sysNames -contains $base -and $path -notmatch '^C:\\Windows\\(System32|SysWOW64)\\' -and $path -ne 'C:\Windows\explorer.exe') {
        Add-Finding 'Processus' 'High' "Usurpation possible d'un processus systeme : $base" "$path (PID $($p.ProcessId))"
        continue
    }
    if ($path -match '^C:\\Windows\\') { continue }
    if ($seen.ContainsKey($path)) { continue }
    $seen[$path] = $true
    Test-Binary 'Processus' "$($p.Name) (PID $($p.ProcessId))" ('"' + $path + '"')
    if ($p.CommandLine -match $SusCmd) { Add-Finding 'Processus' 'High' "$($p.Name) (PID $($p.ProcessId)) : ligne de commande suspecte" $p.CommandLine }
}
$remote = 'anydesk','teamviewer','rustdesk','vnc','ultravnc','tightvnc','logmein','screenconnect','splashtop','ammyy','radmin','meshagent'
foreach ($p in (Get-Process)) {
    foreach ($r in $remote) { if ($p.ProcessName -like "*$r*") { Add-Finding 'Processus' 'Warn' "Outil de controle a distance actif : $($p.ProcessName)" "PID $($p.Id) - verifiez que vous l'avez installe vous-meme." } }
}

# ---------- 5. Reseau ----------
Step 'Connexions reseau'
$procById = @{}; Get-Process | ForEach-Object { $procById[$_.Id] = $_ }
$badPorts = 4444,1337,31337,5555,6667,6666,12345,54321,9001,9050,3389
$listen = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' }
foreach ($c in $listen) {
    $pr = $procById[[int]$c.OwningProcess]
    $name = if ($pr) { $pr.ProcessName } else { '?' }
    $path = if ($pr) { $pr.Path } else { $null }
    $sev = 'Info'
    if ($badPorts -contains $c.LocalPort) { $sev = 'Warn' }
    if ($path -and $path -match $RiskDir) { $sev = 'High' }
    if ($sev -ne 'Info') { Add-Finding 'Reseau' $sev "Port en ecoute $($c.LocalPort) ($name)" "$($c.LocalAddress):$($c.LocalPort) -> $path" }
}
$est = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80|0\.0\.0\.0)' }
foreach ($c in $est) {
    $pr = $procById[[int]$c.OwningProcess]
    if (-not $pr -or -not $pr.Path) { continue }
    $bad = $badPorts -contains $c.RemotePort
    $risk = $pr.Path -match $RiskDir
    if ($bad -or $risk) {
        Add-Finding 'Reseau' $(if ($risk) { 'High' } else { 'Warn' }) "Connexion sortante : $($pr.ProcessName) -> $($c.RemoteAddress):$($c.RemotePort)" $pr.Path
    }
}
$dns = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique
$knownDns = '^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|1\.1\.1\.1|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.9|208\.67\.22[02]\.22[02]|127\.)'
foreach ($d in $dns) { if ($d -notmatch $knownDns) { Add-Finding 'Reseau' 'Warn' "Serveur DNS inhabituel : $d" 'Verifiez qu''il s''agit bien de celui de votre FAI/routeur (detournement DNS possible).' } }
$proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
if ($proxy.ProxyEnable -eq 1 -or $proxy.AutoConfigURL) { Add-Finding 'Reseau' 'Warn' 'Proxy systeme configure' "ProxyServer=$($proxy.ProxyServer) AutoConfigURL=$($proxy.AutoConfigURL)" }
$hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }
foreach ($h in $hosts) { Add-Finding 'Reseau' 'Warn' 'Entree personnalisee dans le fichier hosts' $h }
foreach ($sh in (Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' })) { Add-Finding 'Reseau' 'Warn' "Partage reseau expose : $($sh.Name)" $sh.Path }

# ---------- 6. Comptes ----------
Step 'Comptes et administrateurs'
foreach ($u in (Get-LocalUser)) {
    if ($u.Enabled -and $u.Name -in 'Administrator','Administrateur') { Add-Finding 'Comptes' 'Warn' "Compte integre $($u.Name) active" '' }
    if ($u.Enabled -and $u.Name -eq 'Guest') { Add-Finding 'Comptes' 'Warn' 'Compte Invite active' '' }
    if ($u.Enabled -and -not $u.PasswordRequired) { Add-Finding 'Comptes' 'Warn' "Compte sans mot de passe obligatoire : $($u.Name)" '' }
}
$adminGroup = (Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'").Name
foreach ($m in (Get-LocalGroupMember -Group $adminGroup)) { Add-Finding 'Comptes' 'Info' "Membre du groupe Administrateurs : $($m.Name)" "$($m.ObjectClass) / $($m.PrincipalSource)" }

# ---------- 7. Configuration de securite ----------
Step 'Configuration de securite'
$mp = Get-MpComputerStatus
if ($mp) {
    if (-not $mp.AntivirusEnabled)          { Add-Finding 'Securite' 'High' 'Antivirus Defender DESACTIVE' '' }
    if (-not $mp.RealTimeProtectionEnabled) { Add-Finding 'Securite' 'High' 'Protection en temps reel desactivee' '' }
    if ($mp.AntivirusSignatureAge -gt 7)    { Add-Finding 'Securite' 'Warn' "Signatures antivirus anciennes ($($mp.AntivirusSignatureAge) jours)" '' }
    $pref = Get-MpPreference
    foreach ($e in @($pref.ExclusionPath))      { if ($e -and $e -notmatch '^N/A') { Add-Finding 'Securite' 'Warn' 'Exclusion Defender (chemin)' $e } }
    foreach ($e in @($pref.ExclusionProcess))   { if ($e -and $e -notmatch '^N/A') { Add-Finding 'Securite' 'Warn' 'Exclusion Defender (processus)' $e } }
    foreach ($e in @($pref.ExclusionExtension)) { if ($e -and $e -notmatch '^N/A') { Add-Finding 'Securite' 'Warn' 'Exclusion Defender (extension)' $e } }
    foreach ($th in (Get-MpThreatDetection | Select-Object -First 10)) {
        Add-Finding 'Securite' 'Warn' "Menace detectee par Defender le $($th.InitialDetectionTime)" (($th.Resources -join '; '))
    }
} else { Add-Finding 'Securite' 'Info' 'Etat Defender illisible (autre antivirus ?)' '' }
foreach ($fw in (Get-NetFirewallProfile)) { if (-not $fw.Enabled) { Add-Finding 'Securite' 'High' "Pare-feu desactive (profil $($fw.Name))" '' } }
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0) { Add-Finding 'Securite' 'Warn' 'Bureau a distance (RDP) active' 'Inutile si vous ne l''utilisez pas.' }
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA -eq 0) { Add-Finding 'Securite' 'High' 'UAC desactive' '' }
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
if ($smb1 -and $smb1.State -eq 'Enabled') { Add-Finding 'Securite' 'Warn' 'SMBv1 active (protocole obsolete et dangereux)' '' }
foreach ($svcName in 'WinRM','RemoteRegistry','TermService','Telnet') {
    $sv = Get-Service $svcName
    if ($sv -and $sv.Status -eq 'Running') { Add-Finding 'Securite' 'Info' "Service d'acces distant en cours : $svcName" '' }
}

# ---------- 8. Journaux d'evenements ----------
Step "Journaux d'evenements (30 derniers jours)"
if ($IsAdmin) {
    $since = (Get-Date).AddDays(-30)
    foreach ($e in (Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$since} -MaxEvents 50)) {
        Add-Finding 'Journaux' 'Info' "Nouveau service installe le $($e.TimeCreated.ToString('dd/MM/yyyy HH:mm'))" ($e.Message -replace '\s+', ' ')
    }
    foreach ($e in (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=$since} -MaxEvents 20)) {
        Add-Finding 'Journaux' 'Warn' "Compte utilisateur cree le $($e.TimeCreated.ToString('dd/MM/yyyy HH:mm'))" ($e.Message -replace '\s+', ' ').Substring(0, [Math]::Min(250, ($e.Message -replace '\s+', ' ').Length))
    }
    foreach ($e in (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102; StartTime=$since} -MaxEvents 5)) {
        Add-Finding 'Journaux' 'High' "Journal de securite EFFACE le $($e.TimeCreated.ToString('dd/MM/yyyy HH:mm'))" 'Technique classique pour masquer des traces.'
    }
    $fail = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 2000
    if ($fail.Count -ge 20) { Add-Finding 'Journaux' 'Warn' "$($fail.Count) echecs de connexion en 48 h" 'Possible tentative de force brute (surtout si RDP/SMB expose).' }
} else { Add-Finding 'Journaux' 'Info' 'Journaux ignores (droits administrateur requis)' '' }

# ---------- 9. Pilotes non signes / recemment ajoutes ----------
Step 'Pilotes'
foreach ($d in (Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' -and $_.PathName })) {
    $p = Get-ExePath $d.PathName
    if ($p -match '^C:\\Windows\\') { continue }
    Test-Binary 'Pilotes' "$($d.Name)" $d.PathName
}

# ---------- Extensions de navigateur ----------
Step 'Extensions de navigateur'
$browsers = @{ 'Chrome' = "$env:LOCALAPPDATA\Google\Chrome\User Data"; 'Edge' = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"; 'Brave' = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
$goodExt = 'Claude|iCloud|Tampermonkey|Violentmonkey|uBlock|Bitwarden|AdBlock|1Password|Dark Reader|LastPass|Google Docs|Google Drive|Google Translate|Microsoft|Edge|Chrome|Grammarly|Adobe|Keeper|Proton|Malwarebytes|Kaspersky|Bitdefender|Avast|Norton|McAfee|ESET'
$broadHost = '<all_urls>', '*://*/*', 'http://*/*', 'https://*/*'
$riskPerm  = 'cookies', 'webRequestBlocking', 'nativeMessaging', 'debugger', 'proxy', 'management', 'history', 'clipboardRead'
foreach ($b in $browsers.Keys) {
    foreach ($prof in (Get-ChildItem -LiteralPath $browsers[$b] -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
        foreach ($ext in (Get-ChildItem -LiteralPath (Join-Path $prof.FullName 'Extensions') -Directory)) {
            $ver = Get-ChildItem -LiteralPath $ext.FullName -Directory | Sort-Object Name | Select-Object -Last 1
            $mf = if ($ver) { Join-Path $ver.FullName 'manifest.json' }
            if (-not $mf -or -not (Test-Path -LiteralPath $mf)) { continue }
            $m = Get-Content -LiteralPath $mf -Raw -Encoding UTF8 | ConvertFrom-Json
            if (-not $m) { continue }
            $name = [string]$m.name
            if ($name -match '^__MSG_(.+)__$') {
                $key = $matches[1]; $name = $ext.Name
                foreach ($loc in 'en', 'en_US', 'fr') {
                    $lf = Join-Path $ver.FullName "_locales\$loc\messages.json"
                    if (Test-Path -LiteralPath $lf) {
                        $msg = (Get-Content -LiteralPath $lf -Raw -Encoding UTF8 | ConvertFrom-Json).$key.message
                        if ($msg) { $name = $msg; break }
                    }
                }
            }
            $perms = @(); foreach ($x in @($m.permissions) + @($m.host_permissions) + @($m.optional_permissions)) { if ($x -is [string]) { $perms += $x } }
            foreach ($cs in @($m.content_scripts)) { foreach ($mt in @($cs.matches)) { $perms += $mt } }
            $perms = $perms | Sort-Object -Unique
            $broad = [bool]($perms | Where-Object { $broadHost -contains $_ })
            $risky = @($perms | Where-Object { $riskPerm -contains $_ })
            $sev = if ($broad -and $risky.Count -gt 0 -and $name -notmatch $goodExt) { 'Warn' } else { 'Info' }
            $sum = (@(if ($broad) { 'acces a TOUS les sites' }) + $risky) -join ', '
            Add-Finding 'Navigateur' $sev "Extension navigateur ($b) : $name" "ID $($ext.Name) v$($m.version) | profil $($prof.Name) | $(if ($sum) { $sum } else { 'permissions limitees' })"
        }
    }
}

# ---------- 10. VirusTotal (optionnel : envoie UNIQUEMENT des empreintes SHA256, jamais les fichiers) ----------
$vtKey = $VirusTotalKey
if (-not $vtKey) { $kf = Join-Path $PSScriptRoot 'vt_key.txt'; if (Test-Path $kf) { $vtKey = (Get-Content $kf -Raw).Trim() } }
if (-not $vtKey) { $vtKey = $env:VT_API_KEY }
$vtUsed = $false
if ($vtKey) {
    $vtUsed = $true
    $todo = $Findings | Where-Object { $_.Sev -ne 'OK' -and $_.Sha } | Group-Object Sha | Select-Object -First 40
    $i = 0
    foreach ($g in $todo) {
        $i++
        Write-Host ("  VirusTotal {0}/{1} ..." -f $i, @($todo).Count) -ForegroundColor DarkCyan
        $res = $null; $known = $true
        try {
            $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$($g.Name)" -Headers @{ 'x-apikey' = $vtKey } -TimeoutSec 20 -ErrorAction Stop
            $st = $r.data.attributes.last_analysis_stats
            $res = [pscustomobject]@{ Mal = [int]$st.malicious; Sus = [int]$st.suspicious; Total = [int]($st.malicious + $st.suspicious + $st.harmless + $st.undetected) }
        } catch {
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { $known = $false }
            else { Write-Host "  VirusTotal indisponible ou cle invalide, arret des verifications." -ForegroundColor Yellow; break }
        }
        foreach ($f in $g.Group) {
            if (-not $known) { $f.VT = "Fichier jamais analyse par VirusTotal (rare ou personnel)"; continue }
            $f.VT = "VirusTotal : $($res.Mal)/$($res.Total) moteurs le jugent malveillant"
            if ($res.Mal -ge 3) { $f.Sev = 'High'; $f.Why = "Plusieurs antivirus reconnus detectent ce fichier comme malveillant. " + $f.Why; $f.Do = "Arretez et supprimez ce programme, puis lancez une analyse complete." }
            elseif ($res.Mal -ge 1 -and $f.Sev -eq 'Info') { $f.Sev = 'Warn'; $f.VT += ' (1-2 detections : souvent un faux positif, a verifier)' }
            elseif ($res.Mal -eq 0 -and $res.Total -ge 50 -and $f.Sev -eq 'Warn') { $f.Sev = 'Info'; $f.VT += ' -> fichier propre, point rétrogradé' }
        }
        if ($i -lt @($todo).Count) { Start-Sleep -Seconds 16 }   # quota gratuit : 4 requetes/min
    }
}

# ---------- 11. Rapport ----------
Step 'Generation du rapport'
$order = @{ High = 0; Warn = 1; Info = 2; OK = 3 }
$label = @{ High = 'Suspect'; Warn = 'A verifier'; Info = 'Probablement normal'; OK = 'Reconnu' }
$sorted = $Findings | Sort-Object @{e={$order[$_.Sev]}}, Cat, Title
$nH = @($Findings | Where-Object Sev -eq 'High').Count
$nW = @($Findings | Where-Object Sev -eq 'Warn').Count
$nI = @($Findings | Where-Object Sev -eq 'Info').Count
$nO = @($Findings | Where-Object Sev -eq 'OK').Count

$outDir = Join-Path $PSScriptRoot 'Rapports'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$file = Join-Path $outDir ("Rapport_{0}_{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmm'))
function E($s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }

function Row($f) {
    $cls = $f.Sev.ToLower()
    $links = ''
    if ($f.Sha) { $links += "<a target='_blank' href='https://www.virustotal.com/gui/file/$($f.Sha)'>Verifier sur VirusTotal</a> " }
    $nm = if ($f.File) { Split-Path $f.File -Leaf } else { ($f.Title -split ' ')[0] }
    $q = [uri]::EscapeDataString("$nm c'est quoi legit ou virus")
    $links += "<a target='_blank' href='https://www.google.com/search?q=$q'>Chercher ce nom</a>"
    $meta = @()
    if ($f.Signer) { $meta += "Editeur : $(E $f.Signer)" } elseif ($f.File) { $meta += 'Editeur : aucun (non signe)' }
    if ($f.Date)   { $meta += "Modifie le $($f.Date)" }
    if ($f.Sha)    { $meta += "SHA256 : <span class='sha'>$($f.Sha)</span>" }
    if ($f.VT)     { $meta += "<b>$(E $f.VT)</b>" }
    $why = ''
    if ($f.Why) { $why += "<div><b>Pourquoi c'est signale :</b> $(E $f.Why)</div>" }
    if ($f.Do)  { $why += "<div><b>Que faire :</b> $(E $f.Do)</div>" }
    "<tr class='$cls'><td><span class='b $cls'>$($label[$f.Sev])</span></td><td>$(E $f.Cat)</td><td><b>$(E $f.Title)</b><div class='d'>$(E $f.Detail)</div></td><td>$why<div class='meta'>$($meta -join ' &middot; ')</div><div class='lk'>$links</div></td></tr>"
}
$main = foreach ($f in ($sorted | Where-Object Sev -ne 'OK')) { Row $f }
$okRows = foreach ($f in ($sorted | Where-Object Sev -eq 'OK')) { "<tr><td>$(E $f.Cat)</td><td>$(E $f.Title)</td><td class='d'>$(E $f.Detail)</td></tr>" }
$verdict = if ($nH -gt 0) { 'Elements suspects : a traiter en priorite' } elseif ($nW -gt 0) { 'Quelques points a verifier, rien d''alarmant a premiere vue' } else { 'Rien de suspect detecte' }
$vtNote = if ($vtUsed) { 'Les empreintes (SHA256) des fichiers douteux ont ete comparees a VirusTotal : voir la ligne en gras de chaque element.' } else { 'Astuce : mettez votre cle API VirusTotal gratuite dans un fichier vt_key.txt a cote du script pour que les fichiers douteux soient verifies automatiquement (seule l''empreinte est envoyee, jamais le fichier).' }
$html = @"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Rapport Scan-PC</title>
<style>
body{font:14px Segoe UI,Arial,sans-serif;margin:24px;background:#f5f6f8;color:#1b1f24;max-width:1300px}
h1{margin:0 0 4px}.sub{color:#667;margin-bottom:12px}
.cards{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}.card{padding:14px 22px;border-radius:8px;color:#fff;font-size:13px}
.card b{display:block;font-size:28px}.card.high{background:#c62828}.card.warn{background:#ef8f00}.card.info{background:#546e7a}.card.ok{background:#2e7d32}
.guide{background:#fff;border-left:4px solid #1565c0;padding:10px 16px;margin:12px 0;border-radius:6px}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden;margin-bottom:16px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #e5e7eb;vertical-align:top}
th{background:#263238;color:#fff}.d{font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:#455;margin-top:3px}
.meta{font-size:12px;color:#556;margin-top:6px;word-break:break-all}.sha{font-family:Consolas,monospace}
.lk a{font-size:12px;margin-right:12px;color:#1565c0}
.b{padding:2px 8px;border-radius:10px;color:#fff;font-size:12px;white-space:nowrap}.b.high{background:#c62828}.b.warn{background:#ef8f00}.b.info{background:#78909c}
details{background:#fff;padding:10px 14px;border-radius:8px}summary{cursor:pointer;font-weight:600}
.note{margin-top:16px;color:#667;font-size:12px}
</style></head><body>
<h1>Rapport Scan-PC</h1>
<div class="sub">$(E $env:COMPUTERNAME) - $(E $env:USERNAME) - $(Get-Date -Format 'dd/MM/yyyy HH:mm') - Administrateur : $IsAdmin</div>
<h2>$verdict</h2>
<div class="cards"><div class="card high"><b>$nH</b>Suspect</div><div class="card warn"><b>$nW</b>A verifier</div><div class="card info"><b>$nI</b>Probablement normal</div><div class="card ok"><b>$nO</b>Reconnus (editeur de confiance)</div></div>
<div class="guide"><b>Comment lire ce rapport</b><br>
1. Traitez d'abord <b>Suspect</b>, puis <b>A verifier</b>. Chaque ligne explique pourquoi elle est signalee et quoi faire.<br>
2. En cas de doute sur un fichier, cliquez <b>Verifier sur VirusTotal</b> : ~70 antivirus l'analysent. 0 ou 1 detection = tres probablement sain.<br>
3. <b>Un fichier non signe n'est pas un virus</b> (beaucoup de jeux et petits outils ne le sont pas) ; un fichier signe par un editeur connu est tres rarement malveillant.<br>
$vtNote</div>
<table><tr><th>Verdict</th><th>Categorie</th><th>Constat</th><th>Explication et verification</th></tr>
$($main -join "`n")
</table>
<details><summary>$nO elements reconnus sains (signes par un editeur de confiance) - cliquer pour afficher l'inventaire</summary>
<table><tr><th>Categorie</th><th>Element</th><th>Chemin</th></tr>$($okRows -join "`n")</table></details>
<p class="note">Ce scan est en lecture seule : rien n'a ete modifie. Un constat n'est pas une preuve d'infection. En cas de doute fort, faites une analyse complete Defender + Malwarebytes.</p>
</body></html>
"@
$html | Out-File -FilePath $file -Encoding utf8

Write-Host ""
Write-Host ("Termine : {0} suspect(s), {1} a verifier, {2} probablement normal(aux), {3} reconnu(s)" -f $nH, $nW, $nI, $nO) -ForegroundColor $(if ($nH) { 'Red' } elseif ($nW) { 'Yellow' } else { 'Green' })
foreach ($f in ($sorted | Where-Object Sev -eq 'High' | Select-Object -First 15)) { Write-Host ("  [SUSPECT] {0} - {1}" -f $f.Cat, $f.Title) -ForegroundColor Red }
Write-Host "Rapport : $file"
if (-not $NoOpen) { Start-Process $file }
if ($Host.Name -eq 'ConsoleHost' -and -not $NoOpen) { Read-Host "Appuyez sur Entree pour fermer" | Out-Null }
