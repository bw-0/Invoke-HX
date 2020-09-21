function Receive-HX_Acquisition{
	[CmdletBinding()]
	param (
		[int]$id,
		[switch]$Proxy

	)

	if ($DLpath = Get-Item ".\$id.zip" -ErrorAction SilentlyContinue){
		Write-Host -ForegroundColor Cyan "A file with this ID already exists in this folder"
		break
	}

	do {

		try {
			if ($Proxy){
				hx Acquire download -ID $id -Verbose -Proxy
		    }
		
			else {
				hx Acquire download -ID $id -Verbose
			}
			$DLpath = Get-Item ".\$id.zip"
		}

		catch {
			"Not ready yet, will try again in 10 seconds"
			Start-Sleep 10
		}
	}

	until ($DLpath -and (Test-Path $DLpath))

	try {Ding "Acquisition Downloaded: $($DLpath.fullname)"}
	catch {"Acquisition Downloaded: $($DLpath.fullname)"}
}