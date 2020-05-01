# Analyze Enterprise Search Results
```
#Get all searches
$s = hx Searches list -limit 20

#Pick the search you want to analyze
$p = $s.data.entries | Out-GridView -PassThru

#Get results
$r = hx Searches get-childitem -ID $p._id

#Total count
$r.data.entries.results.data.count

#Sorting results, selecting specific properties, view in GUI.
$r.data.entries.results.data | sort-object "parent process path", "parent process name", "file full path" | select-object "parent process path", "parent process name", "file full path" | out-gridview

#Filter results
$r.data.entries|?{$_.results.data."file full path" -match "cmd\.exe"}
```