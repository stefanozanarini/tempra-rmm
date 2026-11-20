# open-rmm microsoft365 module (Windows): checks and actions for Microsoft
# 365 Apps (Click-to-Run) and OneDrive. What is installed is reported by the
# inventory module; this one judges it (status) and fixes it (update,
# set-channel, repair).
#
# status parameters: { "max_update_age_days": 45, "channels": [...],
#                      "onedrive_backup": true, "personal_accounts": true }
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

$c2rDir = Join-Path $env:CommonProgramFiles 'microsoft shared\ClickToRun'
$configPath = 'SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
$policyPath = 'SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate'

# Users not logged on are judged on what was seen of them last, for this
# long (the same as the console keeps their accounts).
$keepDays = 90

function Get-Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-Str($Value) {
    if ($null -eq $Value) { return '' }
    return ([string]$Value).Trim()
}

function Open-HKLM {
    [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
}

function Get-RegValue([Microsoft.Win32.RegistryKey]$Base, [string]$Path, [string]$Name) {
    $k = $Base.OpenSubKey($Path)
    if ($null -eq $k) { return $null }
    try { return $k.GetValue($Name) } finally { $k.Close() }
}

function Get-SidUser([string]$Sid) {
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

# Same table as the inventory module.
$officeChannels = @{
    '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' = 'Current'
    '64256afe-f5d9-4f86-8936-8840a6a4f5be' = 'Current Preview'
    '5440fd1f-7ecb-4221-8110-145efaa6372f' = 'Beta'
    '55336b82-a18d-4dd6-b5f6-9e5095c314a6' = 'Monthly Enterprise'
    '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' = 'Semi-Annual Enterprise'
    'b8f9b850-328d-4355-9145-c59439a0c4cf' = 'Semi-Annual Enterprise Preview'
    'f2e724c1-748f-4b47-8fb8-8e0d210e9208' = 'LTSC 2019'
    '5030841d-c919-4594-8d2d-84ae4f96e58e' = 'LTSC 2021'
    '7983bac0-e531-40cf-be00-fd24fe66619c' = 'LTSC 2024'
}

# End of support of the perpetual Office versions (Click-to-Run LTSC and
# MSI). Microsoft 365 Apps (subscription) has none.
$officeEndOfSupport = @{
    '2007' = [datetime]'2017-10-10'
    '2010' = [datetime]'2020-10-13'
    '2013' = [datetime]'2023-04-11'
    '2016' = [datetime]'2025-10-14'
    '2019' = [datetime]'2025-10-14'
    '2021' = [datetime]'2026-10-13'
    '2024' = [datetime]'2029-10-09'
}

# Get-C2R: the Click-to-Run configuration, or $null when Office is not
# installed with Click-to-Run.
function Get-C2R {
    $hklm = Open-HKLM
    $k = $hklm.OpenSubKey($configPath)
    if ($null -eq $k) { return $null }
    try {
        $version = Get-Str $k.GetValue('VersionToReport')
        if (-not $version) { return $null }
        $url = Get-Str $k.GetValue('UpdateChannel')
        if (-not $url) { $url = Get-Str $k.GetValue('CDNBaseUrl') }
        $channel = ''
        if ($url -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s*$') {
            $channel = $officeChannels[$Matches[1].ToLowerInvariant()]
            if (-not $channel) { $channel = $Matches[1] }
        }
        @{
            version  = $version
            channel  = $channel
            platform = Get-Str $k.GetValue('Platform')
            culture  = Get-Str $k.GetValue('ClientCulture')
            products = @((Get-Str $k.GetValue('ProductReleaseIds')) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            updates  = Get-Str $k.GetValue('UpdatesEnabled')
            root     = Get-Str $k.GetValue('InstallationPath')
        }
    }
    finally { $k.Close() }
}

# Get-MsiOffice: the years of Office suites installed with Windows Installer
# (2016 and older), from the Uninstall keys.
function Get-MsiOffice {
    $hklm = Open-HKLM
    $years = @()
    foreach ($path in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        $k = $hklm.OpenSubKey($path)
        if ($null -eq $k) { continue }
        try {
            foreach ($n in $k.GetSubKeyNames()) {
                if ($n -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { continue }
                $e = $k.OpenSubKey($n)
                if ($null -eq $e) { continue }
                try {
                    $name = Get-Str $e.GetValue('DisplayName')
                    if ([int]$e.GetValue('WindowsInstaller', 0) -ne 1 -or $e.GetValue('ParentKeyName')) { continue }
                    if ($name -match '^Microsoft Office\b(?!.*(Language|Proofing|MUI|Shared|Viewer|Click-to-Run|Runtime)).*\b(2007|2010|2013|2016)$') {
                        $years += $Matches[2]
                    }
                }
                finally { $e.Close() }
            }
        }
        finally { $k.Close() }
    }
    @($years | Sort-Object -Unique)
}

# Get-LastOfficeUpdate: when the installed build was applied, from the
# write time of the main application files (replaced by every update).
function Get-LastOfficeUpdate($C2R) {
    $root = $C2R.root
    if (-not $root) { $root = Join-Path $env:ProgramFiles 'Microsoft Office' }
    $times = @(foreach ($f in 'WINWORD.EXE', 'EXCEL.EXE', 'OUTLOOK.EXE', 'POWERPNT.EXE') {
        $p = Join-Path $root "root\Office16\$f"
        if (Test-Path -LiteralPath $p) { (Get-Item -LiteralPath $p).LastWriteTimeUtc }
    })
    if (-not $times.Count) { return $null }
    ($times | Sort-Object -Descending)[0]
}

function Get-UpdatesCheck($C2R, [int]$MaxAge) {
    $why = @()
    if ($C2R.updates -ieq 'False') { $why += 'configurazione di Office (UpdatesEnabled)' }
    $hklm = Open-HKLM
    $policy = Get-RegValue $hklm $policyPath 'enableautomaticupdates'
    if ($null -ne $policy -and [int]$policy -eq 0) { $why += 'policy (enableautomaticupdates)' }
    try {
        $task = Get-ScheduledTask -TaskPath '\Microsoft\Office\' -TaskName 'Office Automatic Updates 2.0' -ErrorAction Stop
        if ($task.State -eq 'Disabled') { $why += "attività pianificata Office Automatic Updates 2.0 disabilitata" }
    }
    catch { $why += "attività pianificata Office Automatic Updates 2.0 assente" }
    if ($why.Count) {
        # One reason in the summary, so the console can translate it.
        Send-RmmLog "aggiornamenti di Office disattivati: $($why -join '; ')" 'warn'
        return @{ id = 'office-updates'; status = 'failing'; summary = "Aggiornamenti automatici di Office disattivati: $($why[0]) (versione $($C2R.version))" }
    }
    $last = Get-LastOfficeUpdate $C2R
    if ($null -ne $last) {
        $days = [int]((Get-Date).ToUniversalTime() - $last).TotalDays
        if ($days -gt $MaxAge) {
            return @{ id = 'office-updates'; status = 'warning'; summary = "Office non aggiornato da $days giorni (versione $($C2R.version))" }
        }
    }
    @{ id = 'office-updates'; status = 'ok'; summary = "Aggiornamenti di Office attivi (versione $($C2R.version))" }
}

function Get-ChannelCheck($C2R, $Allowed) {
    $ch = $C2R.channel
    # LTSC is judged by office-support; an unknown channel is not judged.
    if (-not $ch -or $ch -like 'LTSC*' -or $ch -match '^[0-9a-f]{8}-') { return }
    $hklm = Open-HKLM
    $byPolicy = [bool](Get-Str (Get-RegValue $hklm $policyPath 'updatebranch')) -or [bool](Get-Str (Get-RegValue $hklm $policyPath 'updatepath'))
    $by = ''
    if ($byPolicy) { $by = ', impostato da policy' }
    if ($Allowed -notcontains $ch) {
        return @{ id = 'office-channel'; status = 'warning'; summary = "Canale di Office non ammesso: $ch$by" }
    }
    @{ id = 'office-channel'; status = 'ok'; summary = "Canale di Office: $ch$by" }
}

# Get-SupportCheck: Microsoft 365 Apps, or the perpetual versions with
# their end of support (failing once ended, warning in its last year).
function Get-SupportCheck($C2R, [string[]]$MsiYears) {
    $years = @($MsiYears)
    $subscription = $false
    if ($C2R) {
        foreach ($p in $C2R.products) {
            if ($p -match '^O365') { $subscription = $true }
            elseif ($p -match '(20\d\d)') { $years += $Matches[1] }
            # Office 2016 Click-to-Run ids carry no year (ProPlusRetail).
            elseif ($p -match '^(ProPlus|Standard|HomeBusiness|HomeStudent|Professional|Personal|ProjectPro|ProjectStd|VisioPro|VisioStd|Word|Excel|Outlook|PowerPoint|Access|Publisher)(Retail|Volume)$') { $years += '2016' }
        }
    }
    $years = @($years | Where-Object { $officeEndOfSupport.ContainsKey($_) } | Sort-Object -Unique)
    if (-not $years.Count) {
        if ($subscription) { return @{ id = 'office-support'; status = 'ok'; summary = 'Microsoft 365 Apps in abbonamento' } }
        return
    }
    $now = Get-Date
    $ended = @($years | Where-Object { $officeEndOfSupport[$_] -le $now })
    if ($ended.Count) {
        $list = ($ended | ForEach-Object { "Office $_ (dal $($officeEndOfSupport[$_].ToString('dd/MM/yyyy')))" }) -join ', '
        return @{ id = 'office-support'; status = 'failing'; summary = "Office fuori supporto: $list" }
    }
    $first = $years | Sort-Object { $officeEndOfSupport[$_] } | Select-Object -First 1
    $end = $officeEndOfSupport[$first]
    if ($end -le $now.AddDays(365)) {
        return @{ id = 'office-support'; status = 'warning'; summary = "Office $first fuori supporto dal $($end.ToString('dd/MM/yyyy'))" }
    }
    @{ id = 'office-support'; status = 'ok'; summary = "Office $first supportato fino al $($end.ToString('dd/MM/yyyy'))" }
}

# Get-UserStates: for each user whose profile is loaded, whether they use a
# work account (Office or OneDrive), whether Desktop and Documents are in a
# work OneDrive, and their personal accounts. Read from the user's hive, as
# the inventory module does.
function Get-UserStates {
    $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    $hklm = Open-HKLM
    $out = @{}
    foreach ($sid in $users.GetSubKeyNames()) {
        if ($sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        $work = $false
        $personal = @()
        $ids = $users.OpenSubKey("$sid\Software\Microsoft\Office\16.0\Common\Identity\Identities")
        if ($null -ne $ids) {
            try {
                foreach ($n in $ids.GetSubKeyNames()) {
                    $i = $ids.OpenSubKey($n)
                    if ($null -eq $i) { continue }
                    try {
                        $mail = Get-Str $i.GetValue('EmailAddress')
                        if (-not $mail) { $mail = Get-Str $i.GetValue('SignInName') }
                        if (-not $mail) { continue }
                        if ((Get-Str $i.GetValue('ProviderId')) -ieq 'AD') { $work = $true } else { $personal += $mail }
                    }
                    finally { $i.Close() }
                }
            }
            finally { $ids.Close() }
        }
        $profilePath = Get-Str (Get-RegValue $hklm "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" 'ProfileImagePath')
        $folders = @()
        $usf = $users.OpenSubKey("$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        if ($null -ne $usf) {
            try {
                foreach ($f in 'Desktop', 'Personal') {
                    $folders += (Get-Str $usf.GetValue($f, '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)) -ireplace '^%USERPROFILE%', $profilePath.Replace('$', '$$')
                }
            }
            finally { $usf.Close() }
        }
        $backup = $false
        $acc = $users.OpenSubKey("$sid\Software\Microsoft\OneDrive\Accounts")
        if ($null -ne $acc) {
            try {
                foreach ($n in $acc.GetSubKeyNames()) {
                    if ($n -notmatch '^(Business\d+|Personal)$') { continue }
                    $a = $acc.OpenSubKey($n)
                    if ($null -eq $a) { continue }
                    try {
                        $root = (Get-Str $a.GetValue('UserFolder')).TrimEnd('\')
                        if (-not $root) { continue }
                        if ($n -eq 'Personal') {
                            $mail = Get-Str $a.GetValue('UserEmail')
                            if (-not $mail) { $mail = 'OneDrive personale' }
                            $personal += $mail
                            continue
                        }
                        $work = $true
                        $inside = @($folders | Where-Object { $_ -and $_.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase) })
                        if ($inside.Count -eq 2) { $backup = $true }
                    }
                    finally { $a.Close() }
                }
            }
            finally { $acc.Close() }
        }
        if (-not $work -and -not $personal.Count) { continue }
        $out[(Get-SidUser $sid)] = @{ work = $work; backup = $backup; personal = @($personal | Sort-Object -Unique) }
    }
    $out
}

# Merge-UserStates: the users seen now, plus those seen in earlier runs
# (state file) within keepDays, each with the time it was last seen.
function Merge-UserStates($Current, [string]$StateDir) {
    $now = (Get-Date).ToUniversalTime()
    $all = @{}
    $file = ''
    if ($StateDir) {
        $file = Join-Path $StateDir 'users.json'
        if (Test-Path -LiteralPath $file) {
            try {
                $saved = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
                foreach ($p in $saved.PSObject.Properties) {
                    # PowerShell 7 turns ISO dates into DateTime, 5.1 leaves strings.
                    $v = $p.Value.seen
                    if ($v -is [datetime]) { $seen = $v.ToUniversalTime() }
                    else { $seen = [datetime]::Parse([string]$v, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal') }
                    if (($now - $seen).TotalDays -gt $keepDays) { continue }
                    $all[$p.Name] = @{ work = [bool]$p.Value.work; backup = [bool]$p.Value.backup; personal = @($p.Value.personal); seen = $seen.ToString('o') }
                }
            }
            catch { Send-RmmLog "users.json: $($_.Exception.Message)" 'warn' }
        }
    }
    foreach ($u in $Current.Keys) {
        $s = $Current[$u]
        $all[$u] = @{ work = $s.work; backup = $s.backup; personal = $s.personal; seen = $now.ToString('o') }
    }
    if ($file) { ConvertTo-Json -InputObject $all -Depth 4 -Compress | Set-Content -LiteralPath $file -Encoding UTF8 }
    $all
}

function Format-Names([string[]]$Names) {
    $list = @($Names | Select-Object -First 8) -join ', '
    if ($Names.Count -gt 8) { $list += ', ...' }
    $list
}

function Get-BackupCheck($Users) {
    $work = @($Users.Keys | Where-Object { $Users[$_].work } | Sort-Object)
    if (-not $work.Count) { return }
    $missing = @($work | Where-Object { -not $Users[$_].backup })
    if ($missing.Count) {
        return @{ id = 'onedrive-backup'; status = 'warning'; summary = "Desktop e Documenti non in OneDrive aziendale per: $(Format-Names $missing)" }
    }
    @{ id = 'onedrive-backup'; status = 'ok'; summary = "Desktop e Documenti in OneDrive aziendale per tutti gli utenti ($($work.Count))" }
}

function Get-PersonalCheck($Users) {
    if (-not $Users.Count) { return }
    $found = @(foreach ($u in ($Users.Keys | Sort-Object)) {
        foreach ($a in $Users[$u].personal) { if ($a) { "$($u.Split('\')[-1]): $a" } }
    })
    if ($found.Count) {
        return @{ id = 'personal-account'; status = 'warning'; summary = "Account Microsoft personali in Office o OneDrive: $(Format-Names $found)" }
    }
    @{ id = 'personal-account'; status = 'ok'; summary = 'Nessun account Microsoft personale in Office o OneDrive' }
}

function Get-RequiredC2R {
    $c2r = Get-C2R
    if ($null -eq $c2r) { throw 'Microsoft 365 Apps (Click-to-Run) non è installato' }
    $client = Join-Path $c2rDir 'OfficeC2RClient.exe'
    if (-not (Test-Path -LiteralPath $client)) { throw "OfficeC2RClient.exe non trovato in $c2rDir" }
    $c2r.client = $client
    $c2r
}

function Invoke-Tool([string]$File, [string[]]$Arguments, [int]$TimeoutMinutes) {
    Send-RmmLog "$File $($Arguments -join ' ')"
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit($TimeoutMinutes * 60000)) {
        try { $p.Kill() } catch { }
        throw "$([IO.Path]::GetFileName($File)) non ha terminato entro $TimeoutMinutes minuti"
    }
    $p.ExitCode
}

# Invoke-OfficeUpdate: OfficeC2RClient hands the update to the Click-to-Run
# service and returns; the version changes once it is applied. Without
# force_close an update finding Office apps open waits for them to close.
function Invoke-OfficeUpdate($C2R, [bool]$ForceClose) {
    $force = if ($ForceClose) { 'true' } else { 'false' }
    $code = Invoke-Tool $C2R.client @('/update', 'user', 'displaylevel=false', 'updatepromptuser=false', "forceappshutdown=$force") 10
    if ($code -ne 0) { throw "OfficeC2RClient.exe /update: codice di uscita $code" }
    $deadline = (Get-Date).AddMinutes(50)
    $idleSince = $null
    $version = $C2R.version
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 30
        $now = Get-C2R
        if ($now -and $now.version -ne $C2R.version) { $version = $now.version; break }
        Send-RmmProgress 50 'aggiornamento in corso'
        # The client process stays while it downloads and installs.
        if (Get-Process -Name 'OfficeC2RClient' -ErrorAction SilentlyContinue) { $idleSince = $null; continue }
        if ($null -eq $idleSince) { $idleSince = Get-Date }
        elseif (((Get-Date) - $idleSince).TotalMinutes -ge 3) { break }
    }
    $note = ''
    if ($version -eq $C2R.version) {
        $note = 'Versione invariata: Office era già aggiornato, oppure l''aggiornamento attende la chiusura delle app di Office.'
        if ($ForceClose) { $note = 'Versione invariata: Office era già aggiornato, oppure l''aggiornamento è ancora in corso.' }
    }
    @{ version_before = $C2R.version; version_after = $version; updated = $version -ne $C2R.version; note = $note }
}

Invoke-RmmModule @{
    status = {
        param($Params, $Request)
        $maxAge = Get-Prop $Params 'max_update_age_days'
        if (-not $maxAge) { $maxAge = 45 }
        # @($null) has Count 1 in PowerShell, not 0: filter nulls before
        # checking, otherwise the default list below never applies.
        $allowed = @(Get-Prop $Params 'channels') | Where-Object { $_ }
        if (-not $allowed.Count) { $allowed = @('Current', 'Monthly Enterprise', 'Semi-Annual Enterprise') }
        $backupOn = Get-Prop $Params 'onedrive_backup'
        $personalOn = Get-Prop $Params 'personal_accounts'

        $checks = @()
        $c2r = Get-C2R
        $msi = @(Get-MsiOffice)
        if ($c2r) {
            $checks += Get-UpdatesCheck $c2r ([int]$maxAge)
            $ch = Get-ChannelCheck $c2r $allowed
            if ($ch) { $checks += $ch }
        }
        $sup = Get-SupportCheck $c2r $msi
        if ($sup) { $checks += $sup }
        $users = Merge-UserStates (Get-UserStates) ([string]$Request.state_dir)
        if ($backupOn -ne $false) {
            $c = Get-BackupCheck $users
            if ($c) { $checks += $c }
        }
        if ($personalOn -ne $false) {
            $c = Get-PersonalCheck $users
            if ($c) { $checks += $c }
        }
        $out = @{ msi_office = $msi; users = $users.Count; checks = @($checks) }
        if ($c2r) { $out.office = @{ version = $c2r.version; channel = $c2r.channel; products = $c2r.products } }
        $out
    }

    update = {
        param($Params, $Request)
        $c2r = Get-RequiredC2R
        Send-RmmProgress 10 "versione $($c2r.version)"
        Invoke-OfficeUpdate $c2r ([bool](Get-Prop $Params 'force_close'))
    }

    'set-channel' = {
        param($Params, $Request)
        $channel = [string](Get-Prop $Params 'channel')
        if ($channel -notin @('MonthlyEnterprise', 'Current', 'SemiAnnual')) { throw "canale non valido: $channel" }
        $c2r = Get-RequiredC2R
        $hklm = Open-HKLM
        foreach ($v in 'updatebranch', 'updatepath') {
            $set = Get-Str (Get-RegValue $hklm $policyPath $v)
            if ($set) { throw "Il canale è impostato da una policy (GPO o Intune: $v = $set): va cambiato lì, altrimenti Office torna al canale della policy." }
        }
        $code = Invoke-Tool $c2r.client @('/changesetting', "Channel=$channel") 5
        if ($code -ne 0) { throw "OfficeC2RClient.exe /changesetting: codice di uscita $code" }
        Send-RmmProgress 20 "canale $channel"
        $r = Invoke-OfficeUpdate $c2r ([bool](Get-Prop $Params 'force_close'))
        $r.channel_before = $c2r.channel
        $after = Get-C2R
        if ($after) { $r.channel_after = $after.channel }
        $r
    }

    repair = {
        param($Params, $Request)
        $c2r = Get-RequiredC2R
        $type = [string](Get-Prop $Params 'type')
        $repairType = switch ($type) { 'full' { 'FullRepair' } default { 'QuickRepair' } }
        $exe = Join-Path $c2rDir 'OfficeClickToRun.exe'
        if (-not (Test-Path -LiteralPath $exe)) { throw "OfficeClickToRun.exe non trovato in $c2rDir" }
        $platform = $c2r.platform
        if (-not $platform) { $platform = 'x64' }
        $culture = $c2r.culture
        if (-not $culture) { $culture = 'en-us' }
        Send-RmmProgress 10 $repairType
        $code = Invoke-Tool $exe @('scenario=Repair', "platform=$platform", "culture=$culture", "RepairType=$repairType", 'forceappshutdown=True', 'DisplayLevel=False') 110
        if ($code -ne 0) { throw "Ripristino di Office ($repairType): codice di uscita $code" }
        $after = Get-C2R
        $version = ''
        if ($after) { $version = $after.version }
        @{ repair = $repairType; version = $version }
    }
}
