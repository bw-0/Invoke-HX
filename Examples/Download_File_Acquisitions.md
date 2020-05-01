# Download File Acquisitions
```
#Check on acquisition status
$acq = hx Acquire list -type file -limit 100

#Pick the acquistions you want, could filter on comment but we'll choose via Out-GridView
$pick = $acq.data.entries | Out-GridView -PassThru

#Download the acquired files. Can change the output path with 
$pick | ForEach-Object{hx Acquire download -ID $_._id}
```