# Find Alerts by MD5 then acquire
Only works for non-quarantined files. WIP to handle both
```
$arr=@(
"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
"5ABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
"45ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
"345ABCDEFGHIJKLMNOPQRSTUVWXYZ012",
"2345ABCDEFGHIJKLMNOPQRSTUVWXYZ01",
"12345ABCDEFGHIJKLMNOPQRSTUVWXYZ0",
"012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"
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
		comment  = "FP Samples for Vendor - [Signature Name Here]"
	}
	invoke-hx_api hosts acquire-file @param_hx
}
```