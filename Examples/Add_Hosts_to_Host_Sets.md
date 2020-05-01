## Basic
### Good for single new hosts
```
#Get Host IDs that you want to add/remove to/from a host set
$HostIDs = hxs 123456

#Verify Count of hosts to add
$c=($HostIDs._id|measure).count
write-host "$c Hosts to add"

#Pick host set to add hosts to
$picks = (hx HostSet list -limit 10000).data.entries | Out-GridView -PassThru

#Add hosts to host set. If adding multiple hosts at once and one already exists, the whole transaction will fail.
foreach ($pick in $picks){
	Invoke-HX_API -API HostSet -action add -type static -ID $pick._id -hostset_name $pick.name -HostIDs $HostIDs._id -Verbose
}
```
## Advanced
### Good for big jobs, or adding lots of hosts to an existing host set
```
#Get Host IDs that you want to add/remove to/from a host set
$Hosts = (hx Hosts search -query "123456").data.entries

if (!$hosts.count -ge 1){
	write-host "No Hosts Chosen"
	break
}

#Pick host set to add hosts to
$picks = (hx HostSet list -limit 10000).data.entries | Out-GridView -PassThru

#Add hosts to host set. If adding multiple hosts at once and one already exists, the whole transaction will fail.

foreach ($pick in $picks){
	
	$existing = hx HostSet get-childitem -ID $pick._id

	$add, $skip = $Hosts.where({$_._id -notin $existing.data.entries._id}, "split")

	if ($add.count -ge 1){
		Invoke-HX_API -API HostSet -action add -type static -ID $pick._id -hostset_name $pick.name -HostIDs $add._id -Verbose
		
		$UTC = (Get-Date).ToUniversalTime()
		write-host "$(get-date $UTC -Format "yyyy-MM-ddTHH:mm:ssK") $($add.count) host/s added to $($pick.name)"
	}

	else {
		write-host "No Applicable hosts to add"
	}

	if ($skip){
		write-host "[$(get-date $UTC -Format "yyyy-MM-ddTHH:mm:ssK")] $($skip.count) host/s skipped from $($pick.name)"
	}
}
```