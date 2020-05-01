# Invoke-HX
*PowerShell functions for interacting with the FireEye HX API*

## Getting Started
* Clone Git Repo to PowerShell Modules Path
  * View PS Modules paths using `$env:PSModulePath`
  * Folder structure should look like:
```
  PS>ls C:\Users\bw-0\Documents\WindowsPowerShell\Modules\Invoke-HX -r -File | ft mode, fullname

Mode   FullName
----   --------
-a---- C:\Users\bw-0\Documents\WindowsPowerShell\Modules\Invoke-HX\Invoke-HX.psd1
-a---- C:\Users\bw-0\Documents\WindowsPowerShell\Modules\Invoke-HX\Invoke-HX.psm1
-a---- C:\Users\bw-0\Documents\WindowsPowerShell\Modules\Invoke-HX\Public\Get-HX_Acquisitions.ps1
-a---- C:\Users\bw-0\Documents\WindowsPowerShell\Modules\Invoke-HX\Public\Get-HX_API_Auth.ps1
-a---- C:\Users\bw-0\Documents\WindowsPowerShell\Modules\Invoke-HX\Public\Get-HX_API_Config.ps1
-a---- C:\Users\bw-0\Documents\WindowsPowerShell\Modules\Invoke-HX\Public\Get-HX_API_Token.ps1
-a---- C:\Users\bw-0\Documents\WindowsPowerShell\Modules\Invoke-HX\Public\Invoke-HX_API.ps1
-a---- C:\Users\bw-0\Documents\WindowsPowerShell\Modules\Invoke-HX\Public\Set-HX_API_Auth.ps1
```
* Import the module: `Import-Module Invoke-HX`
* Run main function `Invoke-HX_API`
  * Be sure to use the `-proxy` switch if your client requires a HTTP proxy to reach the internet
* You'll be prompted for your API credentials on first run
* You'll be prompted to set environmental variables on first run. Use these values:
* HX URI = https://hexxxx-hx-webui-1.helix.apps.fireeye.com

## Structure
The main function `Invoke-HX_API` is organized by each of the available API endpoints. When browsing the source you'll find an API->Action->Type heirarchy.

The structure of a request will usually look like: `Invoke-HX_API [API] [Action] (Limit)`

Results are returned as a PowerShell object. What you expect for results are usually returned in the `data.entries` property

Example of nested values:
```
PS>$x = Invoke-HX_API Hosts search -query "123456"
PS>$x                                                                                       

data                                                                   message details route
----                                                                   ------- ------- -----
@{total=1; query=; sort=; offset=0; limit=50; entries=System.Object[]} OK      {}      /h...

PS>$x.data.entries                                                                          

[REDACTED]

PS>    
```
## Basic Examples
### Search for HX Host
```
#Basic Info:
$Results = Invoke-HX_API -API hosts -action search -query "123456"
$Results.data.entries

#Detailed Info using -sysinfo param
$Results = Invoke-HX_API hosts get -AgentID ABCDEFGHIJKLMNOPQRSTUV -sysinfo
$Results.data

#Helper Function for less typing
Search-HX_Hosts 123456

#Even less typing with alias
HXS 123456
```
### Request File Aquisition from Host
```
Invoke-HX_API -API Hosts -action acquire-file -agentid ABCDEFGHIJKLMNOPQRSTUV -filepath C:\Users\Bryon\file.ps1 -comment "Incident#"
```
### Request/Approve Host Containment
```
# Invoke-BigRedButton is a state-aware helper function to contain hosts.
# Run Once to Request Containment. Run Again to Approve Containment.
# The only parameter takes a hostname, IP address, or Agent ID and will only procede when a single host is targeted

Invoke-BigRedButton "Desktop-123456"
```
### Uncontain Host
*Note*: the use of positional parameters for `-API` in position 0, and `-action` in position 1
```
HX Contain Cancel -AgentID ABCDEFGHIJKLMNOPQRSTUV
```
### Get Enterprise Search Stats
```
$s = Invoke-HX_API -API Searches -action list
$s.data.entries | format-table _id, state, {$_.host_set.name}, create_time, {$_.create_actor.username}, update_time, {$_.update_actor.username}
```
### Get Hosts with a Host Set
```
#Get all host sets
$hs = hx HostSet list -limit 1000

#Pick a host set
$pick = $hs.data.entries | out-gridview -passthru

#Get child items from $pick'd host
$results = (hx HostSet get-childitem -ID $pick._id).data.entries
```
### Delete Triages (Use if Alert Storm)
```
#Get listing of recent triages
$list = hx Acquire list -type triage -limit 50

#Pick triages you want to delete
$picks = $list.data.entries | out-gridview -passthru

#SendIt
$picks | ForEach-Object {hx Acquire -action delete -type triage -id $_._id}
```

### Restore Quarantines (Use if Alert Storm)
```
#Get listing of recent quarantines
$q = hx Quarantine list -limit 100

#Pick quarantines to restore
$picks = $q.data.entries | out-gridview -passthru

#SendIt
$picks | ForEach-Object {hx Quarantine restore -ID $_._id}
```
## Use Case Examples
### Alerts
* [Acknowledge Alert Groups](Examples/Acknowledge_Alert_Groups.md)
* [Get Alerts By Host Set](Examples/Get_Alerts_By_Host_Set.md)

### Acquire
* [Acquire Files by MD5](Examples/Acquire_Files_by_MD5.md)
* [Acquire Files From Alerts](Examples/Acquire_Files_From_Alerts.md)
* [Download File Acquisitions](Examples/Download_File_Acquisitions.md)
* [Request and Download Triage](Examples/Request_Triage_and_Download.md)

### Enterprise Search
* [Analyze Enterprise Search Results](Examples/Analyze_Enterprise_Search_Results.md)

### Hosts
* [Get Containment Stats](Examples/Get_Containment_Stats.md)

### Host Sets
* [Add Hosts to Host Sets](Examples/Add_Hosts_to_Host_Sets.md)
* [Get Hosts in Host Set](Examples/Get_Hosts_in_Host_Set.md)

### Policies

## Tips
The functions support using a HTTP proxy which is invoked using the `-proxy` switch parameter. If you will be using the proxy by default, it is recomended to add a $PSDefaultParameterValues scripblock to your [PS Profile](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-6) to set this value by default. It'll save you time from having to always add the `-proxy` switch to every request
```
$PSDefaultParameterValues = @{
	"Invoke-HX_API:Proxy"=$true
}
```
## Notes
* Please contribute
	1. Clone Repo
	2. Create New Branch
	3. Add Feature
	4. Commit
	5. Push
	6. Create Pull Request