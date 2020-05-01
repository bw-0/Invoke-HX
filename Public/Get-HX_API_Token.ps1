function Get-HX_API_Token {
	[CmdletBinding()]
	Param(
		[switch]$Proxy
	)

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	#Returns a PS credential object which has the Username:Password string already built and base64'd
	$cred = Get-HX_API_Auth
	if ($null -eq $cred){
		Write-Error "[Get-HX_API_Token]::Could not get API auth"
		break
	}
	
	#Built the auth string for HX API
	$header = @{
		Authorization = "Basic $($cred.GetNetworkCredential().password)"
	}

	if ($Proxy){
		Write-Verbose "Getting Token w/ Proxy $Proxy_uri"
		Get-HX_API_Config -Proxy
		if ($null -eq $Proxy_uri){
			Write-Error "[Get-HX_API_Token]::Could not get Proxy Config from .ini file"
		}
		$r = Invoke-WebRequest -Method get -Uri $uri/hx/api/v3/token -Headers $header -ContentType "application/json" -Proxy $Proxy_uri -ProxyUseDefaultCredentials
	}

	else{
		Get-HX_API_Config
		Write-Verbose "Getting Token without Proxy. Use -proxy if you have a HTTP proxy"
		$r = Invoke-WebRequest -Method get -Uri $uri/hx/api/v3/token -Headers $header -ContentType "application/json"
	}

	if ($r.StatusCode -eq 204){
		$script:token= @{"X-FeApi-Token"=[string]$r.Headers.'X-FeApi-Token'}
		$script:token_time=get-date
	}

	else {
		write-host "`n" #If the token request fails you get an error from Invoke-WebRequest, then the one below. Without this newline its confusing to look at with two errors in a row. 
		Write-Error "[Get-HX_API_Token]::Token Request Error: Use -proxy to specify a http proxy if needed"
		break
	}
}