function ConvertFrom-HX_Alert{
	[CmdletBinding()]
	Param
	(
			[Parameter(Mandatory=$true, 
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true, 
			ValueFromRemainingArguments=$false, 
			Position=0)]
			[ValidateNotNull()]
			[ValidateNotNullOrEmpty()]
			[alias("alerts")]
			[array]$a
		)
	
	begin{
		#if (!$dict){
		#	Write-Verbose "Build me a dictionary and I'll resolve _ID to hostname`n`$dict = get-hx_host_dictionary"
		#}
	}
	
	process{
	
			if ($dict){
				$host_name = $dict.$($a.agent._id)
			}
			else {$host_name = $a.agent.hostname}
			
			switch ($a.source){
				"mal"{
					switch ($a.event_values.detections.detection."infected-object"."object-type"){
						"file"    {$type = "file-object"}
						"process" {$type = "process-object"}
						default {Write-Error "object-type unknown";break}
					}
					[pscustomobject]@{
						_id=                  $a._id
						alert_time=           [datetime]$a.reported_at
						event_time=           $a.event_at
						TimeToMatch_Mins=     [math]::Round((([datetime]$a.matched_at - [datetime]$a.event_at)).TotalMinutes,2)
						TimeToReport_Mins=    [math]::Round((([datetime]$a.reported_at - [datetime]$a.event_at)).TotalMinutes,2)
						host_id=              $a.agent._id
						resolution=           $a.resolution
						event_type=           $a.subtype
						source=               $a.source
						alert_url=            $a.url
						detection_action=     $a.event_values.detections.detection.action
						detection_engine=     $a.event_values.detections.detection.engine.'engine-type'
						detection_type=       $a.event_values.detections.detection."infected-object"."object-type"
						file_accessed=        $a.event_values.detections.detection."infected-object".$type."access-time"
						file_created=         $a.event_values.detections.detection."infected-object".$type."creation-time"
						file_modified=        $a.event_values.detections.detection."infected-object".$type."modification-time"
						file_path=            $a.event_values.detections.detection."infected-object".$type."file-Path"
						file_path_inner=      $a.event_values.detections.detection."infected-object".$type."inner-file-Path"
						file_size=            $a.event_values.detections.detection."infected-object".$type."size-in-bytes"
						hash_md5=             $a.event_values.detections.detection."infected-object".$type.md5sum
						hash_sha1=            $a.event_values.detections.detection."infected-object".$type.sha1sum
						hash_sha256=          $a.event_values.detections.detection."infected-object".$type.sha256sum
						host_name=            $host_name
						host_os=              $a.event_values."os-details"."$".name +":"+ $a.event_values."os-details"."$".version
						infection_confidence= $a.event_values.detections.detection.infection."confidence-level"
						infection_name=       $a.event_values.detections.detection.infection."infection-name"
						infection_type=       $a.event_values.detections.detection.infection."infection-type"
						is_false_positive=    $a.is_false_positive
						mal_action=           $a.event_values."scanned-object".$type."sub-type"
						process=              $a.event_values."scanned-object".($a.event_values."scanned-object"."scanned-object-type")."actor-process".path
						scan_type=            $a.event_values."scan-type"
						user=                 $a.event_values."scanned-object".$type."actor-process".user.domain +'\'+ $a.event_values."scanned-object".$type."actor-process".user.username                        
					}
				}
				"ioc"{
					switch ($a.event_type){
						"fileWriteEvent"{
							[pscustomobject]@{
								_id=               $a._id
								alert_time=        [datetime]$a.reported_at
								event_time=        $a.event_at
								TimeToMatch_Mins=  [math]::Round((([datetime]$a.matched_at - [datetime]$a.event_at)).TotalMinutes,2)
								TimeToReport_Mins= [math]::Round((([datetime]$a.reported_at - [datetime]$a.event_at)).TotalMinutes,2)
								alert_url=         $a.url
								category=          $a.indicator.category
								event_type=        $a.event_type
								file_path=         $a.event_values."fileWriteEvent/fullPath"
								file_size=         $a.event_values."fileWriteEvent/size"
								hash_md5=          $a.event_values."fileWriteEvent/md5"
								host_id=           $a.agent._id
								host_name=         $host_name
								indicator=         $a.indicator.name
								ioc_text=          $a.event_values."fileWriteEvent/textAtLowestOffset"
								is_false_positive= $a.is_false_positive
								process=           $a.event_values."fileWriteEvent/processPath" +"\"+ $a.event_values."fileWriteEvent/process"
								resolution=        $a.resolution
								source=            $a.source
								source_appliance=  $a.matched_source_alerts.appliance_id
								user=              $a.event_values."fileWriteEvent/username"
							}
						}
						"processEvent"{
							[pscustomobject]@{
								_id=               $a._id
								alert_time=        [datetime]$a.reported_at
								event_time=        $a.event_at
								TimeToMatch_Mins=  [math]::Round((([datetime]$a.matched_at - [datetime]$a.event_at)).TotalMinutes,2)
								TimeToReport_Mins= [math]::Round((([datetime]$a.reported_at - [datetime]$a.event_at)).TotalMinutes,2)
								alert_url=         $a.url
								category=          $a.indicator.category
								event_type=        $a.event_type
								file_path=         ""
								file_size=         ""
								hash_md5=          $a.event_values."processEvent/md5"
								hash_sha1=         ""
								hash_sha256=       ""
								host_id=           $a.agent._id
								host_name=         $host_name
								host_os=           ""
								indicator=         $a.indicator.name
								is_false_positive= $a.is_false_positive
								process=           $a.event_values."processEvent/processPath"
								processCmdLine=    $a.event_values."processEvent/processCmdLine"
								pprocess=          $a.event_values."processEvent/parentProcessPath"
								resolution=        $a.resolution
								source=            $a.source
								source_appliance=  $a.matched_source_alerts.appliance_id
								user=              $a.event_values."processEvent/username"
							}
						}
						"regKeyEvent"{
							[pscustomobject]@{
								_id=               $a._id
								alert_time=        [datetime]$a.reported_at
								event_time=        $a.event_at
								TimeToMatch_Mins=  [math]::Round((([datetime]$a.matched_at - [datetime]$a.event_at)).TotalMinutes,2)
								TimeToReport_Mins= [math]::Round((([datetime]$a.reported_at - [datetime]$a.event_at)).TotalMinutes,2)
								alert_url=         $a.url
								category=          $a.indicator.category
								event_type=        $a.event_type
								host_id=           $a.agent._id
								indicator=         $a.indicator.name
								is_false_positive= $a.is_false_positive
								process=           $a.event_values.'regKeyEvent/process'
								processDir=        $a.event_values.'regKeyEvent/processPath'
								processPath=       $a.event_values.'regKeyEvent/processPath'+"\"+$a.event_values."regKeyEvent/process"
								regpath=           $a.event_values.'regKeyEvent/path'
								regtext=           $a.event_values.'regKeyEvent/text'
								regvalue=          $a.event_values.'regKeyEvent/value'
								resolution=        $a.resolution
								source=            $a.source
								source_appliance=  $a.matched_source_alerts.appliance_id
								user=              $a.event_values."regKeyEvent/username"
							}
						}
						"urlMonitorEvent"{
							[pscustomobject]@{
								_id=                 $a._id
								alert_time=          [datetime]$a.reported_at
								event_time=          $a.event_at
								TimeToMatch_Mins=    [math]::Round((([datetime]$a.matched_at - [datetime]$a.event_at)).TotalMinutes,2)
								TimeToReport_Mins=   [math]::Round((([datetime]$a.reported_at - [datetime]$a.event_at)).TotalMinutes,2)
								alert_url=           $a.url
								category=            $a.indicator.category
								event_type=          $a.event_type
								host_id=             $a.agent._id
								indicator=           $a.indicator.name
								is_false_positive=   $a.is_false_positive
								method=              $a.event_values.'urlMonitorEvent/urlMethod'
								process=             $a.event_values."urlMonitorEvent/process"
								processDir=          $a.event_values.'urlMonitorEvent/processPath'
								processPath=         $a.event_values.'urlMonitorEvent/processPath'+"\"+$a.event_values."urlMonitorEvent/process"
								remoteHost=          $a.event_values.'urlMonitorEvent/hostname'
								remoteIpAddress=     $a.event_values.'urlMonitorEvent/remoteIpAddress'
								remotePort=          $a.event_values.'urlMonitorEvent/remotePort'
								requesturl=          $a.event_values.'urlMonitorEvent/requestUrl'
								resolution=          $a.resolution
								source=              $a.source
								source_appliance=    $a.matched_source_alerts.appliance_id
								useragent=           $a.event_values.'urlMonitorEvent/userAgent'
								user=                $a.event_values."urlMonitorEvent/username"
							}
						}
						"dnsLookupEvent"{
							[pscustomobject]@{
								_id=                 $a._id
								alert_time=          [datetime]$a.reported_at
								event_time=          $a.event_at
								TimeToMatch_Mins=    [math]::Round((([datetime]$a.matched_at - [datetime]$a.event_at)).TotalMinutes,2)
								TimeToReport_Mins=   [math]::Round((([datetime]$a.reported_at - [datetime]$a.event_at)).TotalMinutes,2)
								alert_url=           $a.url
								category=            $a.indicator.category
								event_type=          $a.event_type
								host_id=             $a.agent._id
								indicator=           $a.indicator.name
								is_false_positive=   $a.is_false_positive
								resolution=          $a.resolution
								source=              $a.source
								source_appliance=    $a.matched_source_alerts.appliance_id
								event_hostname=      $a.event_values.'dnsLookupEvent/hostname'
								process=             $a.event_values.'dnsLookupEvent/process'
								processpath=         $a.event_values.'dnsLookupEvent/processPath'
								user=                $a.event_values.'dnsLookupEvent/username'
							}
						}
						default {Write-Host "IOC-Event_Type Unknown:$a`n";continue}
					}
				}
				"exd"{
					[pscustomobject]@{
						
						_id=               $a._id
						alert_time=        [datetime]$a.reported_at
						event_time=        $a.event_at
						TimeToMatch_Mins=  [math]::Round((([datetime]$a.matched_at - [datetime]$a.event_at)).TotalMinutes,2)
						TimeToReport_Mins= [math]::Round((([datetime]$a.reported_at - [datetime]$a.event_at)).TotalMinutes,2)
						alert_url=         $a.url
						event_type=        $a.event_type
						action=            $a.resolution
						file_path=         ($a.event_values.analysis_details|Where-Object{$_.detail_type -eq "file"}).file.value|Select-Object -Unique
						file_size=         ($a.event_values.analysis_details|Where-Object{$_.detail_type -eq "file"}).file.filesize|Where-Object{$_ -ne "N/A"}|Select-Object -Unique
						hash_md5=          ($a.event_values.analysis_details|Where-Object{$_.detail_type -eq "file"}).file.md5sum|Where-Object{$_ -ne "N/A"}|Select-Object -Unique
						host_id=           $a.agent._id
						host_os=           ($a.event_values.analysis_details|Where-Object{$_.detail_type -eq "os"}).os.name +':'+ ($a.event_values.analysis_details|Where-Object{$_.detail_type -eq "os"}).os.version
						is_false_positive= $a.is_false_positive
						process=           ($a.event_values.analysis_details|Where-Object{$_.detail_type -eq "process"}).process.value|Select-Object -Unique
						pprocess=          ($a.event_values.analysis_details|Where-Object{$_.detail_type -eq "process"}).process.parentname | Select-Object -Unique
						resolution=        $a.resolution
						source=            $a.source
					}
				}
				default {Write-Host "Alert Source Unknown:$a`n"}
			}
	}
}

function Get-HX_Host_Dictionary{
		$dict= @{}
		#check for local cache of _ID:Hostname dictionary
		if (
				(Test-Path $HOME/feye_hx_dict.json) -and
				(((Get-Item $HOME/feye_hx_dict.json)).LastWriteTime -gt (get-date).AddDays(-2))
		){
			$j = Get-Content $HOME/feye_hx_dict.json | ConvertFrom-Json
			$j.psobject.properties | ForEach-Object {
				$dict[$_.Name]=$_.Value
			}
			Write-Verbose "[Parse-HX_API]::INFO::Got HX Host Dictionary from cache"
		}
		Else {
			Invoke-RestMethod https://example.com/hxhostsdict.json -OutFile $HOME/feye_hx_dict.json
			$j = Get-Content $HOME/feye_hx_dict.json | ConvertFrom-Json
			$j.psobject.properties | ForEach-Object {
				$dict[$_.Name]=$_.Value
			}
			Write-Verbose "[Parse-HX_API]::INFO::Got HX Host Dictionary from intranet"
		}
		return $dict
}
#$alerts=(hx Alerts get -limit 1000 -start (get-date).AddDays(-7)).data.entries|parse-hx_alert
#$alerts|ogv -PassThru

<#Time Constraints
#Last month
$s = "$((get-date).Month -1)/01/$((get-date).year)"
$e = "$((get-date).Month   )/01/$((get-date).year)"

#Between days of the current month
$s = "$((get-date).Month   )/01/$((get-date).year)"
$e = "$((get-date).Month   )/15/$((get-date).year)"

$alerts = (hx Alerts -action get -start $s -end $e -limit 10000).data.entries
$alerts = (hx Alerts -action get                   -limit 10000).data.entries

$parsed=$alerts|parse-hx_alert|sort alert_time -Descending

#$pick=$parsed|select *|ogv -PassThru

#$alerts|?{$_.url -in $pick.alert_url[0]}

$parsed|group process, file_path|%{
	$n = $_.name -split ","
	[pscustomobject]@{
		count=$_.count
		process=$n[0]
		file=$n[1]
	}
	Clear-Variable n
}|ogv

write-host "HX Alerts Summary"
write-host "Start:$s"
write-host "  End:$e"
write-host "Count, Detection, Type"
$parsed|group source, event_type|sort name|ft count,name
#>

<#On-Demand Scan
$a = hx Alerts -action get -limit 1500
$a.data.entries.Where({
	($_.source -eq "mal") -and
	($_.event_values.'scan-type' -eq "ods")
})|group domain, hostname|ft count,name
#>
