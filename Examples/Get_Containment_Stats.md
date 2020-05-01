# Get Containment Stats for All Hosts
```
$c = hx Contain list -limit 100000

$c.data.entries|Where-Object{
    (($_.state -ne "normal") -or ($_.queued -ne $false))
}
```
```
[REDACTED]
```
### Example of Host with containment requested
*Note*: the resultant value of `queued`

*Note*: the use of `-action get` instead of `list` in the example above
```
 PS>(hx Contain get -AgentID ABCDEFGHIJKLMNOPQRSTUV).data

_id                : ABCDEFGHIJKLMNOPQRSTUV
last_sysinfo       : 2020-04-01T17:05:41.822Z
requested_by_actor : @{_id=0000; username=REDACTED}
requested_on       : 2020-04-01T17:09:48.560Z
contained_by_actor : 
contained_on       : 
queued             : True
excluded           : False
missing_software   : False
reported_clone     : False
state              : normal
state_update_time  : 2020-04-01T17:09:48.560Z
url                : /hx/api/v3/hosts/ABCDEFGHIJKLMNOPQRSTUV
```

### Example of Host being contained:
*Note*: `contained_on` value set, but `state = containing`, possible conflict.

```
PS documents\tmp>(hx Contain get -AgentID ABCDEFGHIJKLMNOPQRSTUV).data                       

_id                : ABCDEFGHIJKLMNOPQRSTUV
last_sysinfo       : 2020-04-01T17:05:41.822Z
requested_by_actor : @{_id=0000; username=REDACTED}
requested_on       : 2020-04-01T17:18:39.930Z
contained_by_actor : @{_id=0000; username=REDACTED}
contained_on       : 2020-04-01T17:18:39.930Z
queued             : True
excluded           : False
missing_software   : False
reported_clone     : False
state              : containing
state_update_time  : 2020-04-01T17:18:52.293Z
url                : /hx/api/v3/hosts/ABCDEFGHIJKLMNOPQRSTUV
```

### Example of Contained Host
*Note*: `contained_on` value same as when `state = containing`, possible conflict.

```
PS documents\tmp>(hx Contain get -AgentID ABCDEFGHIJKLMNOPQRSTUV).data

_id                : ABCDEFGHIJKLMNOPQRSTUV
last_sysinfo       : 2020-04-01T17:22:27.591Z
requested_by_actor : @{_id=0000; username=REDACTED}
requested_on       : 2020-04-01T17:18:39.930Z
contained_by_actor : @{_id=0000; username=REDACTED}
contained_on       : 2020-04-01T17:18:39.930Z
queued             : False
excluded           : False
missing_software   : False
reported_clone     : False
state              : contained
state_update_time  : 2020-04-01T17:22:29.687Z
url                : /hx/api/v3/hosts/ABCDEFGHIJKLMNOPQRSTUV
```