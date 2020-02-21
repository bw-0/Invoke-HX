# Invoke-HX_API
*PowerShell functions for interacting with the FireEye HX API*

## Getting Started
* Clone Repo to PS Modules Path
  * View available PS Modules paths using `$env:PSModulePath`
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

## API Endpoints
Todo

## Examples
### Get hosts within a host set
1. Make a request to the HX controller to get a list of all the host sets
```
PS>$h = invoke-hx_api -API HostSet -action list -limit 1000
```
2. Choose the host set\s. This will result in a pop up menu to choose from.
```
PS>$pick=$h.data.entries|Out-GridView -PassThru
```
3. Make a request to the HX controller to get the members of the host set you chose.
```
PS>$members = invoke-hx_api HostSet -ID $pick._id -action get-childitem
```
4. Review object properties.
```
PS>$members.data.entries[0]

```
5. View your results.
```
PS>$members.data.entries|sort {[datetime]$_.last_audit_timestamp}|format-table last_audit_timestamp, last_poll_timestamp, hostname, last_poll_ip


last_audit_timestamp     last_poll_timestamp      hostname    last_poll_ip 
--------------------     -------------------      --------    ------------ 
2019-06-26T02:51:48.000Z 2019-06-26T04:42:15.000Z redacted    192.0.2.1
2019-06-26T08:21:37.000Z 2019-06-26T11:21:49.000Z redacted    192.0.2.1
2019-06-26T12:39:33.000Z 2019-06-27T00:52:31.000Z redacted    192.0.2.1
2019-06-26T21:28:35.000Z 2019-06-27T00:49:18.000Z redacted    192.0.2.1
2019-06-26T21:30:39.000Z 2019-06-27T00:58:10.000Z redacted    192.0.2.1
2019-06-26T22:02:05.000Z 2019-06-27T00:54:50.000Z redacted    192.0.2.1
2019-06-26T23:59:29.000Z 2019-06-27T00:53:02.000Z redacted    192.0.2.1
2019-06-27T00:12:25.000Z 2019-06-27T01:10:38.000Z redacted    192.0.2.1
2019-06-27T21:14:09.000Z 2019-06-28T00:34:35.000Z redacted    192.0.2.1
2019-06-27T23:33:31.000Z 2019-06-28T00:31:02.000Z redacted    192.0.2.1
2019-06-27T23:33:52.000Z 2019-06-28T00:36:24.000Z redacted    192.0.2.1
2019-06-28T00:31:59.000Z 2019-06-28T00:32:15.000Z redacted    192.0.2.1
2019-07-03T15:26:53.000Z 2019-07-03T19:07:10.000Z redacted    192.0.2.1
2019-07-03T16:06:30.000Z 2019-07-03T19:06:52.000Z redacted    192.0.2.1
2019-07-03T17:09:30.000Z 2019-07-03T19:07:16.000Z redacted    192.0.2.1

```
### Acknowledge Alerts
1. Gather HX Alert Groups
```
$alert_groups = hx Alert_Groups list -limit 1000
```
2. Pick Alerts you want to ACK
```
$pick = $alert_groups.data.entries | Out-GridView -PassThru
```
3. ACK your selection
```
hx Alert_Groups acknowledge -ID $pick._id -comment "Known issue" -Verbose
```
### Acquire files from many alerts
```
#Get last 7 days worth of alert groups
$alert_groups = hx Alert_Groups list -start (get-date).AddDays(-7)

#Get only malware alerts from the whole set
$mal = $alert_groups.data.entries|Where-Object{$_.source -eq "mal"}

#Get a specific malware family based on the assessment property
$pantera = $mal | Where-Object{$_.assessment -match "pantera"}

#Group malware files by MD5, and File_Full_Path to get unique samples
$group_pantera=$pantera | Group-Object {$_.last_alert_parsed.hash_md5}, file_full_path

#Only look at alerts that have been seen on 3+ hosts, then acquire a sample of each
foreach ($a in ($group_pantera | Where-Object{$_.count -ge 3})){
	hx Hosts acquire-file -AgentID $a.Group[0].last_alert.agent._id -filepath $a.Group[0].file_full_path -comment "triggering HX alert on Heur.BZC.WBO.Pantera.57.xxxxx"
}

#Check on acquisition status
$acq = hx Acquire list -type file -limit 100

#Pick the acquistions you want, could filter on comment but we'll choose via Out-GridView
$pick = $acq.data.entries | Out-GridView -PassThru

#Download the acquired files
$pick | ForEach-Object{hx Acquire download -ID $_._id}
```
### Find Alerts by MD5 then acquire
```
$arr=@(
"F88CC05134C555D4E1CD1DEF78162A9A",
"F1139811BBF61362915958806AD30211"
)

#Get last 7 days worth of alert groups
$alert_groups = invoke-hx_api Alert_Groups list -start (get-date).AddDays(-7) -limit 1000

#Get alert groups that have a MD5 that matches our search scope
$scoped = $alert_groups.data.entries | where-object {$_.grouped_by.md5sum -in $arr}

#Group by MD5, and select
$group_md5 = $scoped | Group-Object {$_.grouped_by.md5sum} | sort count -Descending | select -First 5

foreach ($a in $group_md5){
	$param_hx=@{
		AgentID  = $a.Group[0].last_alert.agent._id
		filepath = $a.Group[0].file_full_path
		comment  = "FP Samples for Vendor - ABC123"
	}
	invoke-hx_api hosts acquire-file @param_hx
}
```
## Tips
The functions support using a HTTP proxy which is invoked using the `-proxy` switch parameter. If you will be using the proxy by default, it is recomended to add a $PSDefaultParameterValues scripblock to your [PS Profile](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-6) to set this value by default. It'll save you time from having to always add the `-proxy` switch to every request
```
$PSDefaultParameterValues = @{
	"Invoke-HX_API:Proxy"=$true
}
```
## Notes
* This version only supports local authentication to the HX console.
* Please contribute via Pull Requests