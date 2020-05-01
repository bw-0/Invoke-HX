function Get-HX_Policy_To_Hosts{

	[CmdletBinding()]
	Param
	(
		# Choose policies to see the number of applicable hosts
		[Parameter(Mandatory=$false, 
					ValueFromPipeline=$false,
					Position=0
					)]
		[ValidateSet("pick","all","malware")]
		[string]$type="pick",
		[switch]$measure,
		[switch]$display
	)

	#not sure why the function isn't reading from my PS profile, but this is what's in there:
	$PSDefaultParameterValues = @{
		"Invoke-HX_API:Proxy"=$true
	}

	#Get needed policies, the relational table of policy ID to Host Set ID, and the host sets.
	$policies = hx Policies list -limit 999
	$hsp      = hx Policies get-host_set_policies -limit 999
	$hostsets = hx HostSet list -limit 999

	#Target policies
	switch ($type){
		"pick"   {$target = $policies.data.entries | Sort-Object priority | Out-GridView -PassThru}
		"all"    {
			if (!$measure){
				write-host "Skipping Default Policy, it contains all hosts and take a long time to return.`nIf you want all hosts use `'hx hosts get -limit 77777`'"
				$target = $policies.data.entries | Where-Object{$_.name -ne "agent default policy" }
			}
			else {$target = $policies.data.entries}
		}
		"malware"{
			$exclude=@("test", "agent default policy")
			write-host
			$target = $policies.data.entries|Where-Object{
				($_.name -notin $exclude) -and
				($_.categories.malware_protection)
			}
		}
	}

	#This hashtable will store retrieved host set counts, creating a cache that reduces the number of API calls that need to be made.
	$ht_count=@{}
	$ht_child=@{}

	foreach ($policy in $target){

		#get the relations for the policy
		$pick_hsp = $hsp.data.entries.Where({$_.policy_id -eq $policy._id})

		#get associated host sets
		$policy_hostsets = $hostsets.data.entries | Where-Object {$_._id -in $pick_hsp.persist_id}

		$ht_temp = @{}

		#get count of hosts per applicable host set
		foreach ($policy_hostset in $policy_hostsets){

			if ($measure){

				if ($policy_hostset.name -notin $ht_count.Keys){

					$r = hx HostSet get-childitem -ID $policy_hostset._id -limit 1

					$ht_count.Add($policy_hostset.name,$r.data.total)

					[int]$hostcount += $ht_count.($policy_hostset.name)
				}

				else {
					write-host "Read from Dic"

					[int]$hostcount += $ht_count.($policy_hostset.name)
				}
			}

			else {

				if ($policy_hostset._id -eq 1000){
					Write-Host -ForegroundColor Yellow "Skipping `"All Hosts`""
					continue
				}

				#Relying on same condition as measure only above because it works
				if ($policy_hostset.name -notin $ht_count.Keys){

					$r = hx HostSet get-childitem -ID $policy_hostset._id -limit 88888

					#Store HostSetName:CountOfChildren
					$ht_count.Add($policy_hostset.name,$r.data.total)

					#++Counter, should probably be $x=$x+count, but dont have time to test since it works as is
					[int]$hostcount += $ht_count.($policy_hostset.name)

					#Store HostSetName:Children
					$ht_child.Add($policy_hostset.name,$r.data.entries)

					#Add children to temp hashtable per policy to build up the children, then slap then on as a property last. Also worth noting that we're adding from the sustainging hash table, which makes it reliant on the previous command, which is good because it wont add something that isn't there; also allows code sharing when reading from the sustaining hash table as exampled below.
					$ht_temp.Add($policy_hostset.name,$ht_child.($policy_hostset.name))

				}

				else {
					write-host "Read from Cache"

					[int]$hostcount += $ht_count.($policy_hostset.name)

					$ht_temp.Add($policy_hostset.name,$ht_child.($policy_hostset.name))
				}
			}
		}

		#add host count to policy as a property
		$policy.psobject.properties.add([psnoteproperty]::new("HostCount",$hostcount))

		#if going full out go ahead and strap these kids down
		if (!$measure){
			$policy.psobject.properties.add([psnoteproperty]::new("Children",$ht_temp))
		}

		Write-Host "Total hosts from selected policies: $(($target.hostcount|Measure-Object -Sum).sum)"

		Clear-Variable hostcount, ht_temp    
	}
	$target

	if ($display){
		write-host ($target | Select-Object enabled,  priority, name, hostcount, updated_at, @{n="HostSets";e={$_.Children.GetEnumerator().name}}| Sort-Object priority | Format-Table | Out-String)
	}
}