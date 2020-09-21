function Get-HX_PolicyHost_To_Hostset{
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

	if (!$results){
		$results = Get-HX_Policy_To_Host -type all
		#write-error -Message 'Do this first: $results = Get-HX_Policy_To_Host -type all'
		#return
	}

	if (!$hostname -and !$agentid){
		write-error -Message 'Provide either -hostname or -agentid'
		return    
	}

	if ($hostname){
		$s = foreach ($c in $results.Children){
			$c.GetEnumerator()|ForEach-Object{
				if ($_.Value.hostname -contains $hostname){
					$_.key
				}
			}
		}
		$s|Select-Object -Unique

		return
	}

	if ($agentid){
		$s = foreach ($c in $results.Children){
			$c.GetEnumerator()|ForEach-Object{
				if ($_.Value._id -contains $agentid){
					$_.key
				}
			}
		}
		$s|Select-Object -Unique

		return
	}
}