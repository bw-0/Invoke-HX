# Get Alerts By Host Set
```
#Get all host sets
$hs = hx HostSet list -limit 1000

#Pick host set
$pick = $hs.data.entries | Out-GridView -PassThru

#Get host set children
$children = hx HostSet get-childitem -ID $pick._id -limit 10000

#Get last 1 day of HX alert groups
$alertgroups = hx Alert_Groups list -limit 10000 -days 1

#Filter alert groups to host set children
$results = $alertgroups.data.entries | Where-Object {$_.grouped_by.host._id -in $children.data.entries._id}

#Optionally parse alerts
#$p=$results.last_alert|ConvertFrom-HX_Alert
```
