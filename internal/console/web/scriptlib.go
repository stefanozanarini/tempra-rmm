package web

// scriptPreset is a ready-made PowerShell script offered when running an
// ad-hoc script on one or more agents, so an operator does not have to
// write common maintenance tasks from scratch every time. The catalog is
// static (built into the console); a script whose comment says so is a
// template the operator is expected to edit (e.g. a service or process
// name) before running it.
type scriptPreset struct {
	ID, Category, Name, Description, Script string
}

// scriptPresets is grouped by Category in display order.
var scriptPresets = []scriptPreset{
	{
		ID: "print-spooler", Category: "Manutenzione", Name: "Svuota lo spooler di stampa",
		Description: "Ferma il servizio di stampa, elimina i lavori bloccati in coda e lo riavvia.",
		Script: `Stop-Service -Name Spooler -Force
Remove-Item -Path "$env:SystemRoot\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
Start-Service -Name Spooler
Get-Service -Name Spooler | Select-Object Name, Status`,
	},
	{
		ID: "flush-dns", Category: "Manutenzione", Name: "Svuota la cache DNS",
		Description: "Pulisce la cache del resolver DNS del client.",
		Script: `Clear-DnsClientCache
Get-DnsClientCache | Select-Object -First 10`,
	},
	{
		ID: "clear-temp", Category: "Manutenzione", Name: "Pulisci i file temporanei",
		Description: "Elimina i file temporanei dell'utente e di sistema più vecchi di un giorno (quelli in uso restano, nessun errore).",
		Script: `$cutoff = (Get-Date).AddDays(-1)
foreach ($path in @($env:TEMP, "$env:SystemRoot\Temp")) {
    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt $cutoff } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
"pulizia completata"`,
	},
	{
		ID: "restart-service", Category: "Manutenzione", Name: "Riavvia un servizio (modifica il nome prima di eseguire)",
		Description: "Modello: sostituisci il nome del servizio e lancia.",
		Script: `$ServiceName = 'NomeServizio'
Restart-Service -Name $ServiceName -Force
Get-Service -Name $ServiceName | Select-Object Name, Status, StartType`,
	},
	{
		ID: "pending-reboot", Category: "Diagnostica", Name: "C'è un riavvio in sospeso?",
		Description: "Controlla i segnali più comuni di riavvio in sospeso (componenti, Windows Update, rinomina file).",
		Script: `$reasons = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'component based servicing' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'windows update' }
if (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) { $reasons += 'pending file rename' }
if ($reasons) { "riavvio in sospeso: $($reasons -join ', ')" } else { 'nessun riavvio in sospeso rilevato' }`,
	},
	{
		ID: "disk-space-report", Category: "Diagnostica", Name: "Report spazio disco",
		Description: "Spazio libero e totale di ogni volume.",
		Script:      `Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, FileSystemLabel, @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}}, @{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}} | Format-Table -AutoSize | Out-String -Width 200`,
	},
	{
		ID: "kill-process", Category: "Diagnostica", Name: "Termina un processo per nome (modifica il nome prima di eseguire)",
		Description: "Modello: sostituisci il nome del processo e lancia.",
		Script: `$ProcessName = 'nome'
Stop-Process -Name $ProcessName -Force -ErrorAction SilentlyContinue
"terminato, se presente: $ProcessName"`,
	},
	{
		ID: "sfc-scan", Category: "Riparazione", Name: "Verifica integrità file di sistema (SFC)",
		Description: "sfc /scannow: verifica e ripara i file di sistema protetti.",
		Script:      `sfc /scannow | Out-String -Width 200`,
	},
	{
		ID: "dism-restorehealth", Category: "Riparazione", Name: "Ripara l'archivio componenti (DISM)",
		Description: "DISM /RestoreHealth: ripara l'archivio componenti di Windows, serve prima di un SFC che fallisce.",
		Script:      `DISM /Online /Cleanup-Image /RestoreHealth | Out-String -Width 200`,
	},
	{
		ID: "reset-windows-update", Category: "Riparazione", Name: "Reset dei componenti di Windows Update",
		Description: "Ferma i servizi di Windows Update, rinomina le cartelle della cache (ricreate automaticamente) e riavvia i servizi. Non elimina aggiornamenti già installati.",
		Script: `$services = 'wuauserv', 'bits', 'cryptsvc'
Stop-Service -Name $services -Force -ErrorAction SilentlyContinue
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
foreach ($dir in "$env:SystemRoot\SoftwareDistribution", "$env:SystemRoot\System32\catroot2") {
    if (Test-Path $dir) { Rename-Item -Path $dir -NewName "$(Split-Path -Leaf $dir).bak-$stamp" -ErrorAction SilentlyContinue }
}
Start-Service -Name $services
Get-Service -Name $services | Select-Object Name, Status`,
	},
}
