# Get Hosts in Host Set
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
PS>$hh = invoke-hx_api HostSet -ID $pick._id -action get-childitem
```
4. Review object properties.
```
PS>$hh.data.entries[0]

[REDACTED]
```
5. View your results.
```
PS>$hh.data.entries|sort {[datetime]$_.last_audit_timestamp}|format-table last_audit_timestamp, last_poll_timestamp, hostname, last_poll_ip


last_audit_timestamp     last_poll_timestamp      hostname    last_poll_ip 
--------------------     -------------------      --------    ------------ 
2019-06-26T02:51:48.000Z 2019-06-26T04:42:15.000Z [REDACTED]  [REDACTED]
2019-06-26T08:21:37.000Z 2019-06-26T11:21:49.000Z [REDACTED]  [REDACTED]
2019-06-26T12:39:33.000Z 2019-06-27T00:52:31.000Z [REDACTED]  [REDACTED]
2019-06-26T21:28:35.000Z 2019-06-27T00:49:18.000Z [REDACTED]  [REDACTED]
2019-06-26T21:30:39.000Z 2019-06-27T00:58:10.000Z [REDACTED]  [REDACTED]
2019-06-26T22:02:05.000Z 2019-06-27T00:54:50.000Z [REDACTED]  [REDACTED]
2019-06-26T23:59:29.000Z 2019-06-27T00:53:02.000Z [REDACTED]  [REDACTED]
2019-06-27T00:12:25.000Z 2019-06-27T01:10:38.000Z [REDACTED]  [REDACTED]
2019-06-27T21:14:09.000Z 2019-06-28T00:34:35.000Z [REDACTED]  [REDACTED]
2019-06-27T23:33:31.000Z 2019-06-28T00:31:02.000Z [REDACTED]  [REDACTED]
2019-06-27T23:33:52.000Z 2019-06-28T00:36:24.000Z [REDACTED]  [REDACTED]
2019-06-28T00:31:59.000Z 2019-06-28T00:32:15.000Z [REDACTED]  [REDACTED]
2019-07-03T15:26:53.000Z 2019-07-03T19:07:10.000Z [REDACTED]  [REDACTED]
2019-07-03T16:06:30.000Z 2019-07-03T19:06:52.000Z [REDACTED]  [REDACTED]
2019-07-03T17:09:30.000Z 2019-07-03T19:07:16.000Z [REDACTED]  [REDACTED]
```