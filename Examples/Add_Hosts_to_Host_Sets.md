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
#Get hosts
#This is a single column CSV with "hostname" as the header, and host names you want to add. FQDNs need to be split to get hostname only.
$import = Import-Csv '.\PATH_TO\THIS.csv'

#Some people store a local copy of the fleet, this checks for that first, otherwise make API request
if (gci $env:USERPROFILE\documents\hx\ -Filter HX_hosts_*){
    $hosts = Get-HX_Hosts
}
else {
    $hosts = hx Hosts list -limit 75555
}

$hosts = $hosts.data.entries|?{$_.hostname -in $import.hostname}

#Create hostset
$hostset = (hx HostSet new -hostset_name "INSERT_NAME_HERE" -Verbose).data

#Add hosts
$existing = hx HostSet get-childitem -ID $hostset._id

$add, $skip = $Hosts.where({$_._id -notin $existing.data.entries._id}, "split")

if ($add.count -ge 1){
	try {
		Invoke-HX_API -API HostSet -action add -type static -ID $hostset._id -hostset_name $hostset.name -HostIDs ($add._id|select-object -unique) -Verbose
		$UTC = (Get-Date).ToUniversalTime()
		write-host "$(get-date $UTC -Format "yyyy-MM-ddTHH:mm:ssK") $($add.count) host/s added to $($hostset.name)"
	}
	catch {
		throw "Error adding hosts"
	}
}

else {
	write-host "No Applicable hosts to add"
}

if ($skip){
	write-host "[$(get-date $UTC -Format "yyyy-MM-ddTHH:mm:ssK")] $($skip.count) host/s skipped from $($hostset.name)"
}
```