function Get-HX_API_Config {

	[CmdletBinding()]
	Param(
		[switch]$Proxy
	)

	$config_file = "$home/feye_hx.ini"

	$config = Get-Content $config_file -ErrorAction SilentlyContinue

	if (!($config|Where-Object{$_ -match "uri="})){
		do {$read_uri = Read-Host -Prompt "[Get-HX_API_Config]::Enter HX URI, include `"https://`""}
		until ($read_uri -match "https://")
		"uri=$read_uri" | Out-File $config_file -Append
	}

	else {$script:uri = (($config|Where-Object{$_ -match "uri="}) -split "=")[1]}

	if ($Proxy){

		if (!($config|Where-Object{$_ -match "proxy="})){
			#Read in proxy info
			do {$read_proxy = Read-Host -Prompt "[Get-HX_API_Config]::Enter HTTP Proxy address, include `"http://`""}
			until ($read_proxy -match "http://")

			#store proxy info in config file
			"proxy=$read_proxy" | Out-File $config_file -Append
		}

		else{
			#Read proxy info from config file
			$script:proxy_uri = (($config|Where-Object{$_ -match "^proxy="}) -split "=")[1]
			if ($null -eq $script:proxy_uri){
				Write-Error "[Get-HX_API_Config]::Could not read proxy info from $config_file"
				#Read in proxy info
				do {$read_proxy = Read-Host -Prompt "[Get-HX_API_Config]::Enter HTTP Proxy address, include `"http://`""}
				until ($read_proxy -match "http://")
			}
		}
	}
}