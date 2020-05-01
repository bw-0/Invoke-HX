# Acquire Files From Alerts
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
	hx Hosts acquire-file -AgentID $a.Group[0].last_alert.agent._id -filepath $a.Group[0].file_full_path -comment "triggering HX alert xxxxx"
}
