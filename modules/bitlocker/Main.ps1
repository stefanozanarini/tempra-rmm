Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

# Backs up BitLocker recovery keys, encrypted on this endpoint with the
# console's public key before the result ever leaves the machine: the
# console only ever holds ciphertext, never a recovery key in clear. The
# public key (modulus/exponent, not PEM: Windows PowerShell 5.1's .NET
# Framework has no PEM/DER import but has had RSAParameters since .NET 1.1)
# comes from the job's own params, fetched live by the agent for every run
# (internal/agent/executor), so it is always the current one.

# Get-BitlockerBackups encrypts the numerical-password recovery key of
# every volume with BitLocker on. No such volume: an empty result, not an
# error (the same idiom "inventory" uses for battery/privileged-groups).
function Get-BitlockerBackups([string]$ModulusB64, [string]$ExponentB64) {
    $out = @()
    $vols = @(Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' -ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue)
    if (-not $vols.Count) { return $out }
    $rsaParams = New-Object System.Security.Cryptography.RSAParameters
    $rsaParams.Modulus = [Convert]::FromBase64String($ModulusB64)
    $rsaParams.Exponent = [Convert]::FromBase64String($ExponentB64)
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        $rsa.ImportParameters($rsaParams)
        foreach ($v in $vols) {
            if (-not $v.DriveLetter) { continue }
            if ([int]$v.ProtectionStatus -ne 1) { continue } # not "on"
            # KeyProtectorType 3 = numerical password (the 48-digit recovery key).
            $ids = Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = 3 } -ErrorAction SilentlyContinue
            foreach ($kpID in @($ids.VolumeKeyProtectorID)) {
                if (-not $kpID) { continue }
                $r = Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectorNumericalPassword -Arguments @{ VolumeKeyProtectorID = $kpID } -ErrorAction SilentlyContinue
                if (-not $r -or [int]$r.ReturnValue -ne 0 -or -not $r.NumericalPassword) { continue }
                $plain = [System.Text.Encoding]::UTF8.GetBytes([string]$r.NumericalPassword)
                $ciphertext = $rsa.Encrypt($plain, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                $out += @{
                    drive             = ([string]$v.DriveLetter).ToUpper()
                    key_protector_id  = [string]$kpID
                    ciphertext        = [Convert]::ToBase64String($ciphertext)
                }
            }
        }
    }
    finally { $rsa.Dispose() }
    $out
}

Invoke-RmmModule @{
    backup = {
        param($Params, $Request)
        if (-not $Params -or -not $Params.rsa_modulus_b64 -or -not $Params.rsa_exponent_b64) {
            # The console has not created the encryption key yet.
            return @{ volumes = @() }
        }
        @{ volumes = @(Get-BitlockerBackups $Params.rsa_modulus_b64 $Params.rsa_exponent_b64) }
    }
}
