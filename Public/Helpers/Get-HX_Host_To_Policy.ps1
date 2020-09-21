function Get-HX_Host_To_Policy{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$false, 
					ValueFromPipeline=$false,
					Position=0
					)]
		[string]$hostname,
		[string]$agentid
	)

	if (!$hostname -and !$agentid){
		write-error -Message 'Provide either -hostname or -agentid'
		return    
	}

	if (!$results){
		$results = Get-HX_Policy_To_Host -type all
	}

	if ($hostname){
		$results|Where-Object{$_.hostsets.children.hostname -contains $hostname}
		return
	}

	if ($agentid){
		$results|Where-Object{$_.hostsets.children._id -contains $agentid}
		return
	}
}
