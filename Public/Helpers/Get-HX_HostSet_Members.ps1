function Get-HX_HostSet_Members{
	[CmdletBinding()]
	param (
		$Proxy=$true
	)

	if ($Proxy){
		$PSDefaultParameterValues = @{
			"Invoke-HX_API:Proxy"=$true
		}
	}

	$hs = hx HostSet -limit 10000 -action list

	$targets = $hs.data.entries | Out-GridView -PassThru

	foreach ($hs in $targets){

		if ($policy_hostset._id -eq 1000){
			Write-Host -ForegroundColor Yellow "Skipping `"All Hosts`""
			continue
		}

		$r = hx HostSet get-childitem -ID $hs._id -limit 88888

		#add host count to policy as a property
		$hs.psobject.properties.add([psnoteproperty]::new("HostCount",$r.data.total))

		#strap these kids down
		$hs.psobject.properties.add([psnoteproperty]::new("Children",$r.data.entries))

		Clear-Variable r
	}

	return $targets
}
