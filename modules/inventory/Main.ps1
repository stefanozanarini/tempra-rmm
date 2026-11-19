# open-rmm inventory module (Windows). Read-only: it never changes the system.
# Every section is collected on its own, so a failing WMI class only leaves
# that section empty (with a warning) instead of failing the inventory.
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

function Get-Section {
    param([string]$Name, [scriptblock]$Block, $Default)
    try { & $Block }
    catch {
        Send-RmmLog "${Name}: $($_.Exception.Message)" 'warn'
        $Default
    }
}

function ConvertTo-Iso($Date) {
    if ($Date -is [datetime]) { return $Date.ToUniversalTime().ToString('o') }
    return $null
}

function Get-Str($Value) {
    if ($null -eq $Value) { return '' }
    return ([string]$Value).Trim()
}

# Decodes the uint16 arrays of WmiMonitorID.
function ConvertFrom-WmiChars($Chars) {
    if (-not $Chars) { return '' }
    return (-join ($Chars | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ })).Trim()
}

function Open-HKLM {
    [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
}

function Get-RegValue([Microsoft.Win32.RegistryKey]$Base, [string]$Path, [string]$Name) {
    $k = $Base.OpenSubKey($Path)
    if ($null -eq $k) { return $null }
    try { return $k.GetValue($Name) } finally { $k.Close() }
}

$chassisTypes = @{
    3 = 'desktop'; 4 = 'desktop'; 5 = 'desktop'; 6 = 'desktop'; 7 = 'desktop'; 13 = 'all-in-one'; 15 = 'desktop'; 16 = 'desktop'; 35 = 'mini-pc'; 36 = 'desktop'
    8 = 'laptop'; 9 = 'laptop'; 10 = 'laptop'; 14 = 'laptop'; 31 = 'laptop'; 32 = 'laptop'; 30 = 'tablet'
    17 = 'server'; 23 = 'server'; 28 = 'server'
}

function Get-SystemInfo {
    $cs = Get-CimInstance Win32_ComputerSystem
    $csp = Get-CimInstance Win32_ComputerSystemProduct
    $bios = Get-CimInstance Win32_BIOS
    $enc = @(Get-CimInstance Win32_SystemEnclosure)[0]
    $manufacturer = Get-Str $cs.Manufacturer
    $model = Get-Str $cs.Model
    $sku = Get-Str $cs.SystemSKUNumber
    # Lenovo puts the machine type in Model and the marketing name in Version.
    if ($manufacturer -match '^LENOVO' -and (Get-Str $csp.Version)) {
        $sku = $model
        $model = Get-Str $csp.Version
    }
    $chassis = ''
    if ($enc -and $enc.ChassisTypes) { $chassis = $chassisTypes[[int]$enc.ChassisTypes[0]] }
    @{
        manufacturer   = $manufacturer
        model          = $model
        sku            = $sku
        serial         = Get-Str $bios.SerialNumber
        chassis        = Get-Str $chassis
        domain         = Get-Str $cs.Domain
        part_of_domain = [bool]$cs.PartOfDomain
        # A VM may show its host's maker and model (VMware with
        # SMBIOS.reflectHost), but not its BIOS or serial number.
        virtual        = [bool]("$manufacturer $model $(Get-Str $bios.Manufacturer) $(Get-Str $bios.SMBIOSBIOSVersion) $(Get-Str $bios.SerialNumber)" -match
            'VMware|\bVMW\d|VirtualBox|innotek|Virtual Machine|VRTUAL|QEMU|KVM|\bXen\b|Parallels|Hyper-V|Amazon EC2|Google Compute Engine|BHYVE')
    }
}

function Get-OSInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $hklm = Open-HKLM
    $cv = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $type = Get-Str (Get-RegValue $hklm $cv 'InstallationType')
    $ubr = Get-RegValue $hklm $cv 'UBR'
    $family = if ($type -eq 'Client') { 'client' } elseif ($type -match 'Server') { 'server' } else { '' }
    $build = Get-Str $os.BuildNumber
    if ($null -ne $ubr) { $build = "$build.$ubr" }
    @{
        name              = Get-Str $os.Caption
        version           = Get-Str $os.Version
        build             = $build
        display_version   = Get-Str (Get-RegValue $hklm $cv 'DisplayVersion')
        family            = $family
        installation_type = $type
        architecture      = Get-Str $os.OSArchitecture
        install_date      = ConvertTo-Iso $os.InstallDate
        last_boot         = ConvertTo-Iso $os.LastBootUpTime
        logged_on_user    = Get-Str $cs.UserName
        # logonui.exe is the process that draws the lock screen, the
        # Ctrl+Alt+Del screen and UAC's secure-desktop prompt: a simple,
        # well-known way to tell a locked session from an unlocked one
        # without P/Invoke. A remote-control session on a locked PC would
        # only ever capture that secure desktop, not the user's own.
        screen_locked     = [bool](Get-Process -Name logonui -ErrorAction SilentlyContinue)
    }
}

function Get-FirmwareInfo {
    $bios = Get-CimInstance Win32_BIOS
    $uefi = $null
    $secureBoot = $null
    try {
        $secureBoot = [bool](Confirm-SecureBootUEFI)
        $uefi = $true
    }
    catch [System.PlatformNotSupportedException] { $uefi = $false; $secureBoot = $false }
    catch { }
    $date = ''
    if ($bios.ReleaseDate -is [datetime]) { $date = $bios.ReleaseDate.ToString('yyyy-MM-dd') }
    @{
        vendor      = Get-Str $bios.Manufacturer
        version     = Get-Str $bios.SMBIOSBIOSVersion
        date        = $date
        uefi        = $uefi
        secure_boot = $secureBoot
    }
}

function Get-CpuInfo {
    foreach ($p in Get-CimInstance Win32_Processor) {
        @{ name = Get-Str $p.Name; cores = [int]$p.NumberOfCores; threads = [int]$p.NumberOfLogicalProcessors }
    }
}

function Get-MemoryInfo {
    $modules = @(foreach ($m in Get-CimInstance Win32_PhysicalMemory) {
        $speed = $m.ConfiguredClockSpeed
        if (-not $speed) { $speed = $m.Speed }
        @{
            slot           = Get-Str $m.DeviceLocator
            capacity_bytes = [int64]$m.Capacity
            speed_mhz      = [int]$speed
            manufacturer   = Get-Str $m.Manufacturer
            part_number    = Get-Str $m.PartNumber
            serial         = Get-Str $m.SerialNumber
        }
    })
    $total = [int64]0
    foreach ($m in $modules) { $total += $m.capacity_bytes }
    if ($total -eq 0) { $total = [int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory }
    @{ total_bytes = $total; modules = $modules }
}

function Get-DiskInfo {
    foreach ($d in Get-PhysicalDisk) {
        $media = Get-Str $d.MediaType
        if ($media -eq 'Unspecified') { $media = '' }
        @{
            model      = Get-Str $d.FriendlyName
            serial     = Get-Str $d.SerialNumber
            media_type = $media
            bus        = Get-Str $d.BusType
            size_bytes = [int64]$d.Size
            health     = Get-Str $d.HealthStatus
        }
    }
}

$encryptionMethods = @{ 1 = 'AES-128-Diffuser'; 2 = 'AES-256-Diffuser'; 3 = 'AES-128'; 4 = 'AES-256'; 6 = 'XTS-AES-128'; 7 = 'XTS-AES-256' }

function Get-BitLockerStates {
    $out = @{}
    $vols = Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' -ClassName Win32_EncryptableVolume
    foreach ($v in $vols) {
        if (-not $v.DriveLetter) { continue }
        $state = switch ([int]$v.ConversionStatus) {
            0 { 'off' }
            1 { if ([int]$v.ProtectionStatus -eq 1) { 'on' } else { 'suspended' } }
            2 { 'encrypting' }
            3 { 'decrypting' }
            4 { 'encrypting' }
            5 { 'decrypting' }
            default { '' }
        }
        $method = ''
        $r = Invoke-CimMethod -InputObject $v -MethodName GetEncryptionMethod -ErrorAction SilentlyContinue
        if ($r -and $encryptionMethods.ContainsKey([int]$r.EncryptionMethod)) { $method = $encryptionMethods[[int]$r.EncryptionMethod] }
        $out[(Get-Str $v.DriveLetter).ToUpper()] = @{ state = $state; method = $method }
    }
    $out
}

function Get-VolumeInfo {
    $bl = Get-Section 'bitlocker' { Get-BitLockerStates } @{}
    foreach ($v in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3') {
        $letter = (Get-Str $v.DeviceID).ToUpper()
        $b = $bl[$letter]
        @{
            mount      = $letter
            label      = Get-Str $v.VolumeName
            fs         = Get-Str $v.FileSystem
            size_bytes = [int64]$v.Size
            free_bytes = [int64]$v.FreeSpace
            bitlocker  = if ($b) { $b.state } else { '' }
            encryption = if ($b) { $b.method } else { '' }
        }
    }
}

function Get-NetworkInfo {
    foreach ($n in Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE') {
        $ips = @($n.IPAddress)
        @{
            name    = Get-Str $n.Description
            mac     = Get-Str $n.MACAddress
            ipv4    = @($ips | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
            ipv6    = @($ips | Where-Object { $_ -match ':' })
            gateway = @($n.DefaultIPGateway | Where-Object { $_ })
            dns     = @($n.DNSServerSearchOrder | Where-Object { $_ })
            dhcp    = [bool]$n.DHCPEnabled
        }
    }
}

function Get-TpmInfo {
    $t = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    if (-not $t) { return @{ present = $false } }
    $version = ''
    if ($t.SpecVersion) { $version = (Get-Str $t.SpecVersion).Split(',')[0].Trim() }
    @{ present = $true; ready = [bool]($t.IsEnabled_InitialValue -and $t.IsActivated_InitialValue); version = $version }
}

function Get-BatteryInfo {
    # root\wmi (BatteryStaticData and friends) gives wear (design vs full
    # charge capacity) but its WMI provider is known to fail outright on
    # some systems ("generic failure", seen in the field even as SYSTEM on
    # otherwise healthy laptops): Win32_Battery (root\cimv2) is far more
    # reliably available, so it is always queried and used as the base
    # list of batteries, enriched with wear data when root\wmi works.
    #
    # When root\wmi gives no capacities (on many laptops BatteryStaticData
    # fails while the rest works), Windows' own battery report (powercfg
    # /batteryreport, the same data as its HTML report) fills them in.
    $charge = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
    if ($charge.Count -eq 0) { return }
    $static = @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryStaticData -ErrorAction SilentlyContinue)
    $report = $null
    $full = @{}
    foreach ($f in @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue)) { $full[$f.InstanceName] = [int64]$f.FullChargedCapacity }
    $cycles = @{}
    foreach ($c in @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryCycleCount -ErrorAction SilentlyContinue)) { $cycles[$c.InstanceName] = [int]$c.CycleCount }
    for ($i = 0; $i -lt $charge.Count; $i++) {
        $s = if ($i -lt $static.Count) { $static[$i] } else { $null }
        $design = 0; $fc = 0; $health = 0; $cycleCount = 0; $name = Get-Str $charge[$i].Name
        if ($s) {
            $design = [int64]$s.DesignedCapacity
            $fc = [int64]$full[$s.InstanceName]
            if ($design -gt 0 -and $fc -gt 0) { $health = [int][math]::Round(100 * $fc / $design) }
            $cycleCount = [int]$cycles[$s.InstanceName]
            if (Get-Str $s.DeviceName) { $name = Get-Str $s.DeviceName }
        }
        if ($health -eq 0) {
            if ($null -eq $report) { $report = @(Get-BatteryReport) }
            $r = if ($i -lt $report.Count) { $report[$i] } else { $null }
            if ($r -and $r.design -gt 0 -and $r.full -gt 0) {
                $design = $r.design; $fc = $r.full
                $health = [int][math]::Round(100 * $fc / $design)
                if ($r.cycles -gt 0) { $cycleCount = $r.cycles }
                if ($r.name) { $name = $r.name }
            }
        }
        @{
            name                 = $name
            design_capacity      = $design
            full_charge_capacity = $fc
            health_percent       = $health
            charge_percent       = [int]$charge[$i].EstimatedChargeRemaining
            cycle_count          = $cycleCount
        }
    }
}

# Get-BatteryReport reads design and full charge capacity and the cycle
# count of each battery from powercfg's XML battery report, in the order
# Windows lists them. Nothing when powercfg fails or there is no battery.
function Get-BatteryReport {
    $out = Join-Path ([IO.Path]::GetTempPath()) ("tempra-battery-" + [guid]::NewGuid().ToString('N') + '.xml')
    try {
        $null = & powercfg.exe /batteryreport /xml /output $out 2>&1
        if (-not (Test-Path -LiteralPath $out)) { return }
        [xml]$x = Get-Content -LiteralPath $out -Raw -Encoding UTF8
        foreach ($b in @($x.BatteryReport.Batteries.Battery)) {
            if ($null -eq $b) { continue }
            $design = [int64]0; $full = [int64]0; $cycles = 0
            $null = [int64]::TryParse((Get-Str $b.DesignCapacity), [ref]$design)
            $null = [int64]::TryParse((Get-Str $b.FullChargeCapacity), [ref]$full)
            $null = [int]::TryParse((Get-Str $b.CycleCount), [ref]$cycles)
            @{ name = ((Get-Str $b.Manufacturer) + ' ' + (Get-Str $b.Id)).Trim(); design = $design; full = $full; cycles = $cycles }
        }
    } catch {
        return
    } finally {
        Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    }
}

function Get-MonitorInfo {
    foreach ($m in @(Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorID -ErrorAction SilentlyContinue)) {
        @{
            manufacturer = ConvertFrom-WmiChars $m.ManufacturerName
            model        = ConvertFrom-WmiChars $m.UserFriendlyName
            serial       = ConvertFrom-WmiChars $m.SerialNumberID
        }
    }
}

# Reads one Uninstall key. Updates and entries without a name are skipped.
function Read-UninstallKey([Microsoft.Win32.RegistryKey]$Root, [string]$Path, [string]$Arch, [string]$Scope) {
    $k = $Root.OpenSubKey($Path)
    if ($null -eq $k) { return }
    try {
        foreach ($name in $k.GetSubKeyNames()) {
            $e = $k.OpenSubKey($name)
            if ($null -eq $e) { continue }
            try {
                $display = Get-Str $e.GetValue('DisplayName')
                if (-not $display) { continue }
                if ($e.GetValue('ParentKeyName')) { continue }
                if ((Get-Str $e.GetValue('ReleaseType')) -match 'Update|Hotfix') { continue }
                $productCode = ''
                if ([int]$e.GetValue('WindowsInstaller', 0) -eq 1 -and $name -match '^\{[0-9A-Fa-f-]{36}\}$') { $productCode = $name.ToUpper() }
                @{
                    name             = $display
                    version          = Get-Str $e.GetValue('DisplayVersion')
                    publisher        = Get-Str $e.GetValue('Publisher')
                    install_date     = Get-Str $e.GetValue('InstallDate')
                    arch             = $Arch
                    scope            = $Scope
                    product_code     = $productCode
                    quiet_uninstall  = [bool](Get-Str $e.GetValue('QuietUninstallString'))
                    system_component = ([int]$e.GetValue('SystemComponent', 0) -eq 1)
                }
            }
            finally { $e.Close() }
        }
    }
    finally { $k.Close() }
}

function Get-SoftwareInfo {
    $path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $hklm = Open-HKLM
    Read-UninstallKey $hklm $path 'x64' 'machine'
    Read-UninstallKey $hklm 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' 'x86' 'machine'
    # Per-user installations of the users whose profile is loaded.
    $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    foreach ($sid in $users.GetSubKeyNames()) {
        if ($sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        Read-UninstallKey $users "$sid\$path" '' 'user'
    }
}

# Get-SidUser: DOMAIN\name of a user SID, or the SID when it cannot be
# translated (deleted account, domain unreachable).
function Get-SidUser([string]$Sid) {
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

# Get-LoadedUsers: the users whose profile (registry hive) is loaded, so
# whose mapped drives and cloud accounts were read. The console keeps the
# last ones seen of every other user.
function Get-LoadedUsers {
    $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    foreach ($sid in $users.GetSubKeyNames()) {
        if ($sid -match '^S-1-5-21-[\d-]+$') { Get-SidUser $sid }
    }
}

# Get-MappedShares: network drives currently connected in the session of
# each user whose profile is loaded. The agent runs as SYSTEM, which has
# none of its own; HKEY_USERS\<SID>\Network\<letter> exists only while that
# user's own session has the drive connected (created on connect, removed
# on disconnect), the same way Get-SoftwareInfo reads per-user installs.
function Get-MappedShares {
    $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    foreach ($sid in $users.GetSubKeyNames()) {
        if ($sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        $net = $users.OpenSubKey("$sid\Network")
        if ($null -eq $net) { continue }
        try {
            $user = Get-SidUser $sid
            foreach ($letter in $net.GetSubKeyNames()) {
                $d = $net.OpenSubKey($letter)
                if ($null -eq $d) { continue }
                try {
                    $remote = Get-Str $d.GetValue('RemotePath')
                    if (-not $remote) { continue }
                    @{
                        user        = $user
                        drive       = "$($letter):"
                        remote_path = $remote
                        provider    = Get-Str $d.GetValue('ProviderName')
                    }
                }
                finally { $d.Close() }
            }
        }
        finally { $net.Close() }
    }
}

# Get-IdentityInfo: how the computer is joined to Entra ID, Intune and
# Defender for Endpoint, read locally (no Graph, no credentials). dsregcmd
# prints "Name : VALUE" lines with English names in every language; the
# Entra device id is the key that links this computer to Entra and Intune.
function Get-IdentityInfo {
    $ds = @{}
    $exe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
    if (Test-Path -LiteralPath $exe) {
        foreach ($line in @(& $exe /status)) {
            if ($line -match '^\s*(\w+)\s*:\s*(.*?)\s*$' -and -not $ds.ContainsKey($Matches[1])) { $ds[$Matches[1]] = $Matches[2] }
        }
    }
    $entra = $ds['AzureAdJoined'] -eq 'YES'
    $domain = $ds['DomainJoined'] -eq 'YES'
    if (-not $ds.Count) { $domain = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain }
    $join = if ($entra -and $domain) { 'hybrid' } elseif ($entra) { 'entra' } elseif ($domain) { 'domain' } else { 'workgroup' }
    $hklm = Open-HKLM
    # MDM enrollments (Intune and others): the active one has
    # EnrollmentState 1 and a discovery URL; manage.microsoft.com is Intune.
    $mdm = ''; $mdmUpn = ''
    $enr = $hklm.OpenSubKey('SOFTWARE\Microsoft\Enrollments')
    if ($null -ne $enr) {
        try {
            foreach ($id in $enr.GetSubKeyNames()) {
                $e = $enr.OpenSubKey($id)
                if ($null -eq $e) { continue }
                try {
                    $url = Get-Str $e.GetValue('DiscoveryServiceFullURL')
                    if ([int]$e.GetValue('EnrollmentState', 0) -ne 1 -or -not $url) { continue }
                    try { $mdm = ([uri]$url).Host } catch { $mdm = $url }
                    $mdmUpn = Get-Str $e.GetValue('UPN')
                    break
                }
                finally { $e.Close() }
            }
        }
        finally { $enr.Close() }
    }
    if (-not $mdm) { $mdm = (Get-Str $ds['MdmUrl']) -replace '^https?://([^/]+).*$', '$1' }
    @{
        join_type        = $join
        tenant_id        = Get-Str $ds['TenantId']
        tenant_name      = Get-Str $ds['TenantName']
        device_id        = Get-Str $ds['DeviceId']
        mdm_server       = $mdm
        mdm_upn          = $mdmUpn
        autopilot        = [bool](Get-Str (Get-RegValue $hklm 'SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot' 'CloudAssignedTenantId'))
        mde_onboarded    = [int](Get-RegValue $hklm 'SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' 'OnboardingState') -eq 1
    }
}

# Update channels of Microsoft 365 Apps, by the GUID at the end of the
# CDN URL (https://officecdn.microsoft.com/pr/<guid>).
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

# Get-OfficeInfo: Microsoft 365 Apps or Office installed with Click-to-Run.
# MSI Office (2016 and older) shows only in the software list. UpdateChannel
# (set by policy or the Office deployment tool) wins over CDNBaseUrl.
function Get-OfficeInfo {
    $hklm = Open-HKLM
    $k = $hklm.OpenSubKey('SOFTWARE\Microsoft\Office\ClickToRun\Configuration')
    if ($null -eq $k) { return @{} }
    try {
        $version = Get-Str $k.GetValue('VersionToReport')
        if (-not $version) { return @{} }
        $url = Get-Str $k.GetValue('UpdateChannel')
        if (-not $url) { $url = Get-Str $k.GetValue('CDNBaseUrl') }
        $channel = ''
        if ($url -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s*$') {
            $channel = $officeChannels[$Matches[1].ToLowerInvariant()]
            if (-not $channel) { $channel = $Matches[1] }
        }
        $products = @((Get-Str $k.GetValue('ProductReleaseIds')) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $license = 'perpetual'
        if (@($products | Where-Object { $_ -match '^O365' }).Count) { $license = 'subscription' }
        $updates = Get-Str $k.GetValue('UpdatesEnabled')
        @{
            version          = $version
            channel          = $channel
            platform         = Get-Str $k.GetValue('Platform')
            products         = $products
            license          = $license
            updates_disabled = $updates -ieq 'False'
            shared_computer  = (Get-Str $k.GetValue('SharedComputerLicensing')) -eq '1'
        }
    }
    finally { $k.Close() }
}

# Get-CloudAccounts: for each user whose profile is loaded, the work and
# personal accounts signed in to Office and the OneDrive accounts, with the
# known folders (Desktop, Documents, Pictures) moved into OneDrive. Read from
# the user's own hive, like Get-MappedShares.
function Get-CloudAccounts {
    $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    $hklm = Open-HKLM
    foreach ($sid in $users.GetSubKeyNames()) {
        if ($sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        $user = Get-SidUser $sid
        $office = @()
        $ids = $users.OpenSubKey("$sid\Software\Microsoft\Office\16.0\Common\Identity\Identities")
        if ($null -ne $ids) {
            try {
                foreach ($n in $ids.GetSubKeyNames()) {
                    $i = $ids.OpenSubKey($n)
                    if ($null -eq $i) { continue }
                    try {
                        $mail = Get-Str $i.GetValue('EmailAddress')
                        if (-not $mail) { $mail = Get-Str $i.GetValue('SignInName') }
                        if (-not $mail -or @($office | Where-Object { $_.account -ieq $mail }).Count) { continue }
                        $kind = 'personal'
                        if ((Get-Str $i.GetValue('ProviderId')) -ieq 'AD') { $kind = 'work' }
                        $office += @{ account = $mail; kind = $kind }
                    }
                    finally { $i.Close() }
                }
            }
            finally { $ids.Close() }
        }
        # Known folders: User Shell Folders holds %USERPROFILE%-relative paths.
        $profilePath = Get-Str (Get-RegValue $hklm "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" 'ProfileImagePath')
        $folders = @{}
        $usf = $users.OpenSubKey("$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        if ($null -ne $usf) {
            try {
                foreach ($f in @(@('Desktop', 'Desktop'), @('Personal', 'Documents'), @('My Pictures', 'Pictures'))) {
                    $p = Get-Str $usf.GetValue($f[0], '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $folders[$f[1]] = $p -ireplace '^%USERPROFILE%', $profilePath.Replace('$', '$$')
                }
            }
            finally { $usf.Close() }
        }
        $onedrive = @()
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
                        $kind = 'work'
                        if ($n -eq 'Personal') { $kind = 'personal' }
                        $moved = @($folders.Keys | Where-Object { $folders[$_] -and $folders[$_].StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase) } | Sort-Object)
                        $onedrive += @{
                            account       = Get-Str $a.GetValue('UserEmail')
                            kind          = $kind
                            tenant_id     = Get-Str $a.GetValue('ConfiguredTenantId')
                            folder        = $root
                            known_folders = $moved
                        }
                    }
                    finally { $a.Close() }
                }
            }
            finally { $acc.Close() }
        }
        if (-not $office.Count -and -not $onedrive.Count) { continue }
        @{
            user             = $user
            office           = $office
            onedrive         = $onedrive
            onedrive_version = Get-Str (Get-RegValue $users "$sid\Software\Microsoft\OneDrive" 'Version')
        }
    }
}

# Remote-access tool ids. Supremo (NanoSystems) is 32-bit and normally
# registers under WOW6432Node; the id may be a string with spaces or a DWORD.
function Get-RegistryId([string[]]$Paths, [string]$Name) {
    $hklm = Open-HKLM
    foreach ($p in $Paths) {
        $v = Get-RegValue $hklm $p $Name
        if ($null -ne $v -and "$v" -ne '' -and "$v" -ne '0') { return "$v" }
    }
    return ''
}

function Get-AnyDeskId {
    foreach ($dir in Get-ChildItem -Path $env:ProgramData -Filter 'AnyDesk*' -Directory -ErrorAction SilentlyContinue) {
        $conf = Join-Path $dir.FullName 'system.conf'
        if (-not (Test-Path -LiteralPath $conf)) { continue }
        foreach ($line in Get-Content -LiteralPath $conf -ErrorAction SilentlyContinue) {
            if ($line -match '^\s*ad\.anynet\.id\s*=\s*(\d+)') { return $Matches[1] }
        }
    }
    return ''
}

function Get-RemoteAccessInfo {
    @{
        supremo_id    = Get-RegistryId @('SOFTWARE\WOW6432Node\Supremo', 'SOFTWARE\Supremo') 'ClientID'
        anydesk_id    = Get-AnyDeskId
        teamviewer_id = Get-RegistryId @('SOFTWARE\WOW6432Node\TeamViewer', 'SOFTWARE\TeamViewer') 'ClientID'
    }
}

# Get-LocalAdmins lists the members of the built-in Administrators group,
# found by its SID (the name is localized). Members are local accounts,
# domain (or Entra ID) users and groups; a member whose account no longer
# exists shows as its SID.
function Get-LocalAdmins {
    $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $name = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    $group = [ADSI]"WinNT://$env:COMPUTERNAME/$name,group"
    $out = @()
    foreach ($m in @($group.Invoke('Members'))) {
        $path = [string]$m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
        $class = ([string]$m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)).ToLowerInvariant()
        $parts = @(($path -replace '^WinNT://', '') -split '/')
        if ($parts.Count -ge 3 -and $parts[-2] -ieq $env:COMPUTERNAME) {
            $out += @{ name = "$env:COMPUTERNAME\$($parts[-1])"; type = $class; scope = 'local' }
        }
        elseif ($parts.Count -ge 2) {
            $scope = 'domain'
            if ($parts[0] -ieq 'AzureAD') { $scope = 'entra' }
            $out += @{ name = "$($parts[0])\$($parts[-1])"; type = $class; scope = $scope }
        }
        else {
            $out += @{ name = $parts[0]; type = $class; scope = 'unknown' }
        }
    }
    $out
}

# Get-PendingBrowserUpdates: Chrome and Edge download an update and switch
# to it when the browser restarts; until then new_chrome.exe (new_msedge.exe)
# waits next to the running one and the installed version stays the old.
function Get-PendingBrowserUpdates {
    $out = @()
    foreach ($b in @(@('Google Chrome', 'Google\Chrome\Application\new_chrome.exe'), @('Microsoft Edge', 'Microsoft\Edge\Application\new_msedge.exe'))) {
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if (-not $root) { continue }
            $f = Join-Path $root $b[1]
            if (Test-Path -LiteralPath $f) {
                $out += @{ name = $b[0]; version = [string](Get-Item -LiteralPath $f).VersionInfo.ProductVersion }
                break
            }
        }
    }
    $out
}

# Get-PrivilegedGroups: on a domain controller, the members of the domain's
# built-in privileged groups, found by SID. Administrators normally holds
# only Administrator, Domain Admins and Enterprise Admins; the operators
# groups are normally empty. Every other member is reported as not
# standard: on a DC, BUILTIN\Administrators is admin of every DC and of
# the AD database.
function Get-PrivilegedGroups {
    if ([int](Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { return @() }
    $root = [ADSI]'LDAP://RootDSE'
    $domain = [ADSI]("LDAP://" + $root.defaultNamingContext)
    $domainSid = (New-Object System.Security.Principal.SecurityIdentifier($domain.objectSid[0], 0)).Value
    $standard = @("$domainSid-500", "$domainSid-512", "$domainSid-519")
    $netbios = $env:USERDOMAIN
    $out = @()
    foreach ($g in @(@('S-1-5-32-544', $true), @('S-1-5-32-548', $false), @('S-1-5-32-549', $false), @('S-1-5-32-550', $false), @('S-1-5-32-551', $false))) {
        try {
            $group = [ADSI]"LDAP://<SID=$($g[0])>"
            if ($null -eq $group.sAMAccountName -or -not [string]$group.sAMAccountName) { continue }
        }
        catch { Send-RmmLog "group $($g[0]): $($_.Exception.Message)" 'warn'; continue }
        $members = @()
        foreach ($dn in @($group.member)) {
            if (-not $dn) { continue }
            $m = [ADSI]("LDAP://" + ($dn -replace '/', '\/'))
            $sid = ''
            try { $sid = (New-Object System.Security.Principal.SecurityIdentifier($m.objectSid[0], 0)).Value } catch { }
            $class = 'user'
            if (@($m.objectClass) -contains 'group') { $class = 'group' }
            elseif (@($m.objectClass) -contains 'computer') { $class = 'computer' }
            $name = [string]$m.sAMAccountName
            if (-not $name) { $name = ($dn -split ',')[0] -replace '^CN=', '' }
            $members += @{ name = "$netbios\$name"; type = $class; standard = ($g[1] -and $standard -contains $sid)
                disabled = ($class -ne 'group' -and $null -ne $m.userAccountControl[0] -and ([int]$m.userAccountControl[0] -band 2) -ne 0) }
        }
        $out += @{ name = [string]$group.sAMAccountName; sid = $g[0]; members = $members }
    }
    $out
}

# Get-PrivilegedCheck turns the groups into the check privileged-groups.
function Get-PrivilegedCheck($Groups) {
    $parts = @()
    foreach ($g in $Groups) {
        $extra = @($g.members | Where-Object { -not $_.standard })
        if ($extra.Count -eq 0) { continue }
        $names = @($extra | Select-Object -First 8 | ForEach-Object { $_.name.Split('\')[-1] })
        $more = if ($extra.Count -gt 8) { ", ..." } else { '' }
        $parts += "$($g.name) ($($extra.Count)): $($names -join ', ')$more"
    }
    if ($parts.Count) {
        return @{ id = 'privileged-groups'; status = 'failing'; summary = "Membri non predefiniti nei gruppi privilegiati del dominio: $($parts -join '; ')" }
    }
    @{ id = 'privileged-groups'; status = 'ok'; summary = 'Gruppi privilegiati del dominio con i soli membri predefiniti' }
}

# Battery wear, not its current charge: health_percent is full charge
# capacity against the design capacity, which drops as the battery ages.
# Desktops report no batteries, so the check is absent for them.
function Get-BatteryCheck($Batteries) {
    $known = @($Batteries | Where-Object { $_.health_percent -gt 0 })
    if ($known.Count -eq 0) { return }
    $worst = $known | Sort-Object health_percent | Select-Object -First 1
    $detail = "$($worst.health_percent)% (cicli: $($worst.cycle_count))"
    if ($worst.health_percent -lt 60) { return @{ id = 'battery'; status = 'failing'; summary = "Batteria usurata, salute $detail" } }
    if ($worst.health_percent -lt 80) { return @{ id = 'battery'; status = 'warning'; summary = "Batteria in usura, salute $detail" } }
    @{ id = 'battery'; status = 'ok'; summary = "Batteria in buona salute, $detail" }
}

Invoke-RmmModule @{
    collect = {
        param($Params, $Request)
        $inv = @{ schema = 1; collected_at = (Get-Date).ToUniversalTime().ToString('o') }
        Send-RmmProgress 5 'system'
        $inv.system = Get-Section 'system' { Get-SystemInfo } @{}
        $inv.os = Get-Section 'os' { Get-OSInfo } @{}
        $inv.firmware = Get-Section 'firmware' { Get-FirmwareInfo } @{}
        Send-RmmProgress 25 'hardware'
        $inv.cpus = @(Get-Section 'cpu' { Get-CpuInfo } @())
        $inv.memory = Get-Section 'memory' { Get-MemoryInfo } @{}
        $inv.disks = @(Get-Section 'disks' { Get-DiskInfo } @())
        $inv.volumes = @(Get-Section 'volumes' { Get-VolumeInfo } @())
        $inv.network = @(Get-Section 'network' { Get-NetworkInfo } @())
        $inv.tpm = Get-Section 'tpm' { Get-TpmInfo } @{}
        $inv.batteries = @(Get-Section 'batteries' { Get-BatteryInfo } @())
        $inv.monitors = @(Get-Section 'monitors' { Get-MonitorInfo } @())
        Send-RmmProgress 60 'software'
        $inv.software = @(Get-Section 'software' { Get-SoftwareInfo } @())
        $inv.remote_access = Get-Section 'remote_access' { Get-RemoteAccessInfo } @{}
        $inv.pending_updates = @(Get-Section 'pending_updates' { Get-PendingBrowserUpdates } @())
        $inv.local_admins = @(Get-Section 'local_admins' { Get-LocalAdmins } @())
        $inv.loaded_users = @(Get-Section 'loaded_users' { Get-LoadedUsers } @())
        $inv.network_shares = @(Get-Section 'network_shares' { Get-MappedShares } @())
        Send-RmmProgress 80 'identity'
        $inv.identity = Get-Section 'identity' { Get-IdentityInfo } @{}
        $inv.office = Get-Section 'office' { Get-OfficeInfo } @{}
        $inv.cloud_accounts = @(Get-Section 'cloud_accounts' { Get-CloudAccounts } @())
        $checks = @()
        $groups = @(Get-Section 'privileged_groups' { Get-PrivilegedGroups } @())
        if ($groups.Count) {
            $inv.privileged_groups = $groups
            $checks += Get-PrivilegedCheck $groups
        }
        $battery = Get-BatteryCheck $inv.batteries
        if ($battery) { $checks += $battery }
        # Always report checks, even empty: the console treats this list as
        # the complete, current set and clears any check (e.g. for a group
        # no longer privileged, or a battery that was removed) left out of
        # it, instead of it showing its last status forever.
        $inv.checks = @($checks)
        $inv
    }
}
