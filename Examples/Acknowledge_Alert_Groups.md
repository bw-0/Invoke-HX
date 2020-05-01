# Acknowledge Alert Groups
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