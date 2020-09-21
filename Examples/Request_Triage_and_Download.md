# Request Triage And Dowload
```
#Get Agent ID by searching partial hostname|IP Address|Agent ID, just like Hosts search in WebUI
$search = hx hosts search -query DESKTOP-123456

#Review search results to ensure one host
$search.data.entries

#Request triage given an agent ID
$req = Invoke-HX_API -API hosts -action triage -AgentID $search.data.entries._id

#Check status of triage to know when it's ready for download
do {
    $status = (Invoke-HX_API -API Acquire -action get -type triage -id $req.data._id).data
    Sleep 15
	write-output "Sleeping for 15, brb"
}
until ($status.state -eq "complete")
write-output "Triage Complete for $($search.data.entries.hostname)"

#Download triage when complete
Invoke-HX_API -API Acquire -action download -id $status._id
```
