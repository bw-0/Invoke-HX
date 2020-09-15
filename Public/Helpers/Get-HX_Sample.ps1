function Get-HX_Sample{

	[CmdletBinding(DefaultParameterSetName='Parameter Set 1')]
	Param
	(
		# This is looking for an HX alert PS object, not an alertGroup. If you have an alertGroup, send the value of 'last_alert'
		[Parameter(Mandatory=$false, 
				   ValueFromPipeline=$true,
				   ValueFromPipelineByPropertyName=$true, 
				   ValueFromRemainingArguments=$false, 
				   Position=0,
				   ParameterSetName='Parameter Set 1')]
		[Alias("last_alert","last_alert_parsed")]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()] 
		$Alert,
		$Alertid,
		$Acquisitions,
		[string]$Comment,
		[switch]$Proxy
	)

	process {

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
				if (!$dict){
					Write-Verbose "Build me a dictionary and I'll resolve _ID to hostname`n`$dict = get-hx_host_dictionary"
				}
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

		function Receive-HX_Acquisition{
			[CmdletBinding()]
			param (
				[int]$id,
				[switch]$Proxy,
				$limitz="yes"
			)

			if ($DLpath = Get-Item ".\$id.zip" -ErrorAction SilentlyContinue){
				Write-Host -ForegroundColor Cyan "A file with this ID already exists in this folder"
				break
			}

			do {

				if ($i -gt 3){
					Write-Host "Already tried three times, spawning child process to continue efforts."
					$spawn = "
						import-module invoke-hx
						Receive-HX_Acquisition $id -limitz no
					"
					Start-Process powershell $spawn
				}

				try {
					if ($Proxy){
						hx Acquire download -ID $id -Verbose -Proxy
					}

					else {
						hx Acquire download -ID $id -Verbose
					}
					$DLpath = Get-Item ".\$id.zip"
				}

				catch {
					"Not ready yet, will try again in 10 seconds"
					Start-Sleep 10
					$i++
					if ("no" -eq $limitz){$i=0}
				}
			}

			until ($DLpath -and (Test-Path $DLpath))

			try {Ding "Acquisition Downloaded: $($DLpath.fullname)"}
			catch {"Acquisition Downloaded: $($DLpath.fullname)"}
		}

		if (!$Alert -and !$Alertid){Throw "No alert or alertID provided"}

		if ($Alertid -and !$Alert){

			if ($Proxy){
					$Alert = (hx Alerts get -ID $Alertid -Proxy).data
				}

				else {
					$Alert = (hx Alerts get -ID $Alertid).data
				}
			}

		write-verbose "Parsing Alert"
		try {
			$Alert = ConvertFrom-HX_Alert $alert
			write-host -ForegroundColor Cyan "Parsed Alert:`n$alert"
		}

		catch {Write-Error "Could not parse the alert:`n$alert";break}

		Write-Host -ForegroundColor Yellow "Searching existing Acquisitions"

		$check = hx Acquire get -type file -MD5 $Alert.hash_md5

		if ($check.data.Count -gt 0){
			Write-host "File already acquired"

			if ($check.data.entries){
				$id = $check.data.entries[0]._id
			}
			else {$id = $check.data._id}

			Write-Verbose "Start - Acquire existing file"
			if ($Proxy){
				Receive-HX_Acquisition -id $id -Proxy
			}

			else {
				Receive-HX_Acquisition -id $id
			}
			Write-Verbose "End   - Acquire existing file"

			BREAK

			throw "should've broke"

		}

		else {
			Write-Verbose "No existing acquistions exist"
		}

		switch ($Alert.source){

			{$_ -in @("EXD","IOC")}{
				Write-Verbose "SWITCH - ALERT-SOURCE - IOC"
			}

			"MAL"{
				Write-Verbose "SWITCH - ALERT-SOURCE - MAL"

				switch ($Alert.resolution){

					"ALERT"{
						Write-Verbose "SWITCH - ALERT-RESOLUTION - ALERT"
						Write-Verbose "ACTION - ACQUIRE FILE"

						if ($Proxy){
							$r = hx hosts acquire-file -AgentID $alert.host_id -filepath $alert.file_path -comment $Comment -Proxy
						}

						else {
							$r = hx hosts acquire-file -AgentID $alert.host_id -filepath $alert.file_path -comment $Comment
						}
					}

					"QUARANTINED"{
						Write-Verbose "SWITCH - ALERT-RESOLUTION - QUARANTINED"

						if ($Proxy){
							$quarantines = hx Hosts get-quarantines -AgentID $alert.host_id -limit 1000 -Proxy
						}

						else {
							$quarantines = hx Hosts get-quarantines -AgentID $alert.host_id -limit 1000
						}

						$target = $quarantines.data.entries|Where-Object{$_.file_md5 -eq $Alert.hash_md5}|Sort-Object {[datetime]$_.quarantined_at}|Select-Object -Last 1

						if (($target|Measure-Object).count -eq 1){
							Write-Verbose "ACTION - ACQUIRE QUARANINE"

							if ($Proxy){
								$r = hx Quarantine acquire -ID $target._id -Proxy
							}

							else {
								$r = hx Quarantine acquire -ID $target._id

							}

						}

						else {
							return [pscustomobject]@{
								"data"=[pscustomobject]@{
									"code"=1
									"state"="ERR-Quarantined file not found on host"
									"entries"=$target
								}
							}
						}
					}
				}
			}

			default {
				return [pscustomobject]@{
					"data"=[pscustomobject]@{
						"code"=1
						"state"="ERR-Alert Source is not defined in Get-HX_Sample"
						"entries"=$check.data.entries
					}
				}
			}
		}
		return $r
	}
}
