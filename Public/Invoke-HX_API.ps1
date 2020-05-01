<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Invoke-HX_API HostSet new -type dynamic -hostset_name "AD_LAB1"
.EXAMPLE
   Another example of how to use this cmdlet
.NOTES
   General notes
#>
function Invoke-HX_API{
	[CmdletBinding()]
	[Alias("hx")]

	param (
		[switch]$Proxy,
		[switch]$sysinfo,

		[Parameter(Mandatory=$false,Position=0)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("Hosts","HostSet","Searches","Indicators","Conditions","IndicatorCategories","Alerts","SourceAlerts","Acquire","Quarantine","Scripts","Contain","Configuration","Policies","LogOut","URL","Alert_Groups")]
		$API,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("file","triage","bulk","live","static","dynamic","all")]
		$type,

		[Parameter(Mandatory=$false,Position=1)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("acknowledge","acquire","acquire-file","acquire-live","add","approve","cancel","delete","download","get","get-childitem","get-host_set_policies","get-quarantines","list","new","remove","request","restore","search","stop","triage","update")]
		$action,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1,100000)]
		[Alias("l")] 
		[int]$limit,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(0,100000)]
		[Alias("o")] 
		[int]$offset,

		[Parameter(
			Mandatory=$false,
			ValueFromPipeline=$true
		)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		$AgentID,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		$ID,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		$URL,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		$hostset_name,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		$query,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		$filepath,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		$comment,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		$InFile,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		$OutFile,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		$Policy,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[string]$MD5,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[int]$ScriptID,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[string]$ScriptName,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[string]$ScriptContent,

		#Specify the amount of hours in the past you want to search relative to now.
		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1,672)]
		[Alias("h")] 
		[int]$hours,

		#Specify the amount of days in the past you want to search relative to now.
		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1,16)]
		[Alias("d")] 
		[int]$days,

		#Timestamp less than the desired timeframe,flexible format because it's cast to a datetime,but the official format is 2019-08-22T16:51:53.000Z
		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[Alias("s")] 
		[string]$start,

		#Timestamp greater than the desired timeframe,flexible format because it's cast to a datetime,but the official format is 2019-08-22T16:51:53.000Z
		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[Alias("e")] 
		[string]$end,

		#Collection of HX Host IDs. Param used for creating new static host sets.
		$HostIDs
	)

	begin{
		#region time contraints
		#$after and $before must be before $hours and $days so that $hours and $days are not reformatted to local times.
		if ($start){
			$start=(([datetime]$start).ToString("yyy-MM-ddTHH:mm:ss.000000Z"))
		}

		if ($end){
			$end=(([datetime]$end).ToString("yyy-MM-ddTHH:mm:ss.000000Z"))
		}

		#Because $hours and $days are relative to now,we convert the time to UTC.
		if ($hours){
			$start=(([datetime](get-date).AddHours(-$hours)).ToUniversalTime().ToString("yyy-MM-ddTHH:mm:ss.000000Z"))
			Remove-Variable hours
		}

		if ($days){
			$start=(([datetime](get-date).Adddays(-$days)).ToUniversalTime().ToString("yyy-MM-ddTHH:mm:ss.000000Z"))
			Remove-Variable days
		}
		#endregion

		if (
			($hours -and $days) -or
			($hours -and $start) -or
			($hours -and $end) -or
			($days -and $start) -or
			($days -and $end)
		){
			Write-error "Time contraints must be hours|days|start|end|start&&end";break
		}
	}

	process{
		if ($Proxy){
			Get-HX_API_Config -Proxy
		}

		else{
			Get-HX_API_Config
		}

		if(
			($null -eq $token) -or 
			($token_time -lt ((get-date).AddMinutes(-14)))
		){
			if ($Proxy){
				Get-HX_API_Token -Proxy
			}
			else{
				Get-HX_API_Token
			}
		}

		$header=$token

		$body=@{}

		if ($limit){$body+=@{"limit"=$limit}}
		if ($offset){$body+=@{"offset"=$offset}}

		switch ($API){
			"Acquire"{
				switch ($type){
					"file"{
						switch ($action){
							"list"{
								$endpoint="/hx/api/v3/acqs/files"
								$method="GET"
								$body+=@{"sort"='request_time+descending'}
							}
							"get"{
								$method="GET"

								if (($null -eq $id) -and ($null -eq $MD5)){
									Write-Error "[Invoke-HX_API]::No Acquisition ID or MD5 provided"
									break
								}
								
								if ($MD5){
									"Get by MD5"
									$endpoint="/hx/api/v3/acqs/files?md5=$MD5"
								}
								
								else {
									"Get by ID"
									$endpoint="/hx/api/v3/acqs/files/$ID"
								}
							}
						}
					}
					"triage"{
						switch ($action){
							"list"{
								$method="GET"
								$endpoint="/hx/api/v3/acqs/triages"
								$body+=@{"sort"='request_time+descending'}
							}
							"get"{
								if (!$id){
									Write-Error "[Invoke-HX_API]::No Acquisition ID provided"
								}
								$method="GET"
								$endpoint="/hx/api/v3/acqs/triages/$id"
							}
							"delete"{
								if (!$id){
									Write-Error "[Invoke-HX_API]::No Acquisition ID provided"
								}
								$method="DELETE"
								$endpoint="/hx/api/v3/acqs/triages/$id"
							}
						}
					}
					"bulk"{
						$endpoint="/hx/api/v3/acqs/bulk"
						switch ($action){
							"list"{
								$method="GET"
								$body+=@{"sort"='create_time+descending'}
							}
							
							"get"{
								$method="GET"
								if (!$id){
									Write-Error "[Invoke-HX_API]::No Acquisition ID provided"
								}
								else{
									$endpoint="/hx/api/v3/acqs/bulk/$id"
								}
							}
							
							"delete"{
								$method="DELETE"
								if (!$id){
									Write-Error "[Invoke-HX_API]::No Acquisition ID provided"
								}
								else{
									$endpoint="/hx/api/v3/acqs/bulk/$id"
								}

							}
							
							"stop"{
								$method="POST"
								$endpoint="/hx/api/v3/acqs/bulk/$id/actions/stop"
							}
							
							"new"{
								$method="POST"
								$endpoint="/hx/api/v3/acqs/bulk/"
								if (!$ScriptContent){$ScriptContent=Read-Host "base64'd script"}
								if (!$hostsetid){$hostsetid=Read-Host "host set ID"}
								if (!$platform){$platform=Read-Host "platform"}
								if (!$comment){$comment=Read-Host "comment"}
								$body+=@{"scripts"=@( @{ "platform"= $platform.ToLower();"b64"=$ScriptContent})}
								$body+=@{"host_set"=@{"_id"=[int]$hostsetid}}
								$body+=@{"comment"=$comment}
								$body=$body|ConvertTo-Json -Compress
							}
						}
					}
					"live"{
						$endpoint="/hx/api/v3/acqs/live"
						switch ($action){
							"list"{
								$method="GET"
								$body+=@{"sort"='request_time+descending'}
							}
							"get"{
								if (!$id){
									Write-Error "[Invoke-HX_API]::No Acquisition ID provided"
								}
								else{
									$method="GET"
									$endpoint="/hx/api/v3/acqs/live/$id"
								}
							}
						}
					}
					"all"{
						$endpoint="/hx/api/v3/acqs/"
						switch ($action){
							"list"{
								$method="GET"
								$body+=@{"sort"='request_time+descending'}
							}
						}
					}
				}
				if (!$type){
					switch ($action){
						"download"{
							if (!$id){
								Write-Error "[Invoke-HX_API]::No Acquisition ID provided"
								break
							}
							$endpoint="/hx/api/v3/acqs/files/$id.zip"
							$resource=$uri+$endpoint
							if (!$OutFile){
								$OutFile= ".\$id.zip"
							}

							if ($proxy){
								$r=Invoke-RestMethod -Method Get -Uri $resource -Headers $header -Body $body -ContentType "application/octet-stream" -OutFile $OutFile -Proxy $Proxy_uri -ProxyUseDefaultCredentials
								return
							}

							else{
								$r=Invoke-RestMethod -Method get -Uri $resource -Headers $header -Body $body -ContentType "application/octet-stream" -OutFile $OutFile
								return
							}
						}

						"search"{
							$method="GET"
							$endpoint="/hx/api/v3/acqs/"
							$body+=@{"search"=$query}
						}
					}
				}
			}
			"Alerts"{
				switch ($action){
					"get"{
						$method="GET"

						if ($id){
							$endpoint="/hx/api/v3/alerts/$id"
							continue
						}

						else{
							$endpoint="/hx/api/v3/alerts"
							$body+=@{"sort"='reported_at+descending'}
						}

						if ($query){
							$body+=$query
						}

						if ($start -and $end){
							$filter=@{
								"operator"="between"
								"arg"=@($start,$end)
								"field"="reported_at"
							}
							$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
						}

						elseif ($start){
							$filter=@{
								"operator"="gt"
								"arg"=@($start)
								"field"="reported_at"
							}
							$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
						}

						elseif ($end){
							$filter=@{
								"operator"="lt"
								"arg"=@($end)
								"field"="reported_at"
							}
							$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
						}
					}

					default{
						Write-Error "[Invoke-HX_API]::No value for the `"Action`" parameter"
					}
				}
				#$body=$body | ConvertTo-Json
			}
			"Alert_Groups"{
				$endpoint="/hx/api/v3/alert_groups"
				switch ($action){
					"list"{
						$method="GET"
					}
					"acknowledge"{
						$method="PATCH"
						if (!$comment){$comment=Read-Host "comment"}
						if (!$id){$id=Read-Host "Alert Group IDs"}
						$body+=@{"alert_ids"=@($ID)}
						$body+=@{
							"acknowledgement"=@{
								"acknowledged"=$true
								"comment"=$comment
							}
						}
						$body=$body|ConvertTo-Json -Compress
					}
					"delete"{
						$method="DELETE"
						if (!$id){$id=Read-Host "Alert Group IDs"}
						$endpoint="/hx/api/v3/alert_groups/$id"
					}
				}
			}
			"Conditions"{

			}
			"Configuration"{

			}
			"Contain"{
				switch($action){
					"list"{
						$method="GET"
						$endpoint="/hx/api/v3/containment_states"
					}
					"get"{
						$method="GET"
						$endpoint="/hx/api/v3/hosts/$AgentID/containment"
					}
					"request"{
						$method="POST"
						$endpoint="/hx/api/v3/hosts/$AgentID/containment"
					}
					"approve"{
						$method="PATCH"
						$endpoint="/hx/api/v3/hosts/$AgentID/containment"
						$body='{"state":"contain"}'
					}
					"cancel"{
						$method="DELETE"
						$endpoint="/hx/api/v3/hosts/$AgentID/containment"
					}
				}
			}
			"Hosts"{

			$endpoint="/hx/api/v1/hosts"

			if (!$action){$method="GET"}
			else{
				switch($action){
					"get"{
						$method="GET"
						$endpoint+="/$AgentID"
					}
					"delete"{
						$method="DELETE"
						$endpoint+="/$AgentID"
					}
					"search"{
						$method="GET"
						if (!$query){
							$query=Read-Host -Prompt "Search Query"
						}
						$body+=@{"search"=$query}
					}
					"acquire-file"{
						if (!$filepath){
							Write-Error "No FilePath provided. Use -filepath param giving full path of file you want to acquire"
							break
						}
						if (!$AgentID){
							Write-Error "No AgentID provided. You must provide an HX Agent ID to acquire a file"
							break
						}
						if (!$comment){
							Write-Error "You didn't provide a comment for your file acquistion, stay organized yall"
							break
						}

						$filepath=$filepath -split "\\|/"
						$req_path=$filepath[0..($filepath.Length -2)] -join "\"
						$req_filename=$filepath[-1]
						$method="POST"
						$endpoint="/hx/api/v3/hosts/$AgentID/files"
						$body+=@{
							"req_path"=$req_path
							"req_filename"=$req_filename
							"comment"=$comment
						}
						$body=$body|ConvertTo-Json -Compress
					}
					"acquire-live"{

						$method="POST"						
						$endpoint="/hx/api/v3/hosts/$AgentID/live"

						if (!$AgentID){
							Write-Error "No AgentID provided. You must provide an HX Agent ID to acquire a file"
							break
						}

						if (!$comment){
							do {$comment = Read-Host -Prompt "Required Comment"}
							until ($comment -match "\w{4,}")
						}

						if ($ScriptID){
							$body+=@{
								"script"="_id=$ScriptID"
							}
						}

						if ($InFile){

							try {$InFile = Get-Item $InFile}

							catch {Write-Error "Could not open file";break}

							$Content = Get-Content $InFile.FullName -Encoding UTF8 -raw

							$ScriptContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Content))

							$ScriptName = $InFile.BaseName

							$body+=@{
								"comment"=$comment
								"name"="$ScriptName"
								"script"= @{
									"b64"=$ScriptContent
								}
							}
						}

						else{
							if (!$ScriptName){$ScriptName=Read-Host "ScriptName"}
							if (!$ScriptContent -or !$InFile){$ScriptContent=Read-Host "Base64'd UTF-8 Script Content"}
							$body+=@{
								"comment"=$comment
								"name"="$ScriptName"
								"script"= @{
										"b64"=$ScriptContent
								}
							}
						}
						$body=$body|ConvertTo-Json -Compress
					}
					"get-quarantines"{
						$method="GET"
						$endpoint="/hx/api/v3/hosts/$AgentID/quarantines"
					}
					"triage"{

						if (!$comment){
							do {$comment = Read-Host -Prompt "Required Comment"}
							until ($comment -match "\w{4,}")
						}

						$method="POST"
						$endpoint="/hx/api/v3/hosts/$AgentID/triages"
						$body+=@{
							"comment"=$comment
						}
						$body=$body|ConvertTo-Json -Compress
					}
				}
			}

			if (($null -eq $AgentID)-and($sysinfo)){
				Write-Error "[Invoke-HX_API]::Must Specify AgentID when using SysInfo"
			}
			elseif ($AgentID -and $sysinfo){$endpoint+="/sysinfo"}

		}
			"HostSet"{
				switch ($action){
					"get"{
						$method="GET"
						$endpoint="/hx/api/v3/host_sets/$id"
					}
					"get-childitem"{
						$method="GET"
						if ($null -eq $ID){
							Write-Error "[Invoke-HX_API]::Must Specify HostSet ID when using get-childitem"
							break
						}
						$endpoint="/hx/api/v1/host_sets/$id/hosts"
					}
					"list"{
						$method="GET"
						$endpoint="/hx/api/v3/host_sets"
					}
					"new"{
						if (!$type){$type=read-host -Prompt "Static or Dynamic?"}
						if (!$hostset_name){$hostset_name=read-host -Prompt "Name for new Host Set?"}
						$method="POST"
						switch ($type){
							"dynamic"{
								$endpoint="/hx/api/v3/host_sets/dynamic"
								$hostset_key=read-host -Prompt "HostSet Key"
								$hostset_opr=read-host -Prompt "HostSet Operator"
								$hostset_val=read-host -Prompt "HostSet Value"
								$hostset_kvp= @{
									"operator"= $hostset_opr
									"key"=$hostset_key
									"value"=$hostset_val
								}
								$body+=@{
									"name"=$hostset_name
									"query"=$hostset_kvp
								}
							}
							"static"{
								$endpoint="/hx/api/v3/host_sets/static"
								if (!$HostIDs.GetType().isarray){$HostIDs=,$HostIDs} #Force a single object to be in an array when formatted as JSON
								$body+=@{
									"name"=$hostset_name
									"changes"=@(
										@{
											"command"="change"
											"add"=$HostIDs
										}
									)
								}
							}
						}
						$body=$body|ConvertTo-Json -Depth 10 -Compress
					}
					"add"{
						switch ($type){
							"static"{
								$method="PUT"
								$endpoint="/hx/api/v3/host_sets/static/$id"
								if (!$HostIDs.GetType().isarray){$HostIDs=,$HostIDs} #Force a single object to be in an array when formatted as JSON
								$body += @{
									"name"=$hostset_name
									"changes"=@(
										@{
											"command"="change"
											"add"=$HostIDs
										}
									)
								}
								$body=$body|ConvertTo-Json -Depth 10 -Compress
							}
							"dynamic"{}
						}
					}
					"remove"{
						switch ($type){
							"static"{
								$method="PUT"
								$endpoint="/hx/api/v3/host_sets/static/$id"
								if (!$HostIDs.GetType().isarray){$HostIDs=,$HostIDs} #Force a single object to be in an array when formatted as JSON
								$body += @{
									"name"=$hostset_name
									"changes"=@(
										@{
											"command"="change"
											"remove"=$HostIDs
										}
									)
								}
								$body=$body|ConvertTo-Json -Depth 10 -Compress
							}
							"dynamic"{}
						}
					}
				}
			}
			"IndicatorCategories"{

			}
			"Indicators"{
				$endpoint="/hx/api/v3/indicators"
				$method="GET"
			}
			"LogOut"{
				$endpoint="/hx/api/v3/token"
				$method="DELETE"
			}
			"Policies"{
				$endpoint="/hx/api/v3/policies"

				switch ($action){
					"list"{
						$method="GET"
					}
					"update"{
						$endpoint=$endpoint+"/$ID"
						$method="put"
						$policy|ConvertTo-Json -Compress -Depth 100
						$body=$policy|ConvertTo-Json -Compress -Depth 100
					}
					"get-host_set_policies"{
						$endpoint="/hx/api/v3/host_set_policies"
						$method="GET"
					}
				}
			}
			"Quarantine"{
				switch ($action){
					"get" {
						$endpoint="/hx/api/v3/quarantines/$id"
						$method="GET"
					}
					"list" {
						$endpoint="/hx/api/v3/quarantines"
						$method="GET"
						$body+=@{"sort"='quarantined_at+descending'}
					}
					"acquire"{
						if ($null -eq $ID){
							$id=read-host -Prompt "Quarantine ID"
						}
						$endpoint="/hx/api/v3/quarantines/$id/files"
						$method="POST"
					}
					"download"{
						if (!$id){
							Write-Error "[Invoke-HX_API]::No Acquisition ID provided"
							break
						}
						$endpoint="/hx/api/v3/quarantines/files/$id.zip"
						$resource=$uri+$endpoint
						
						if (!$OutFile){
							$OutFile= ".\$id.zip"
						}

						if ($proxy){
							$r=Invoke-RestMethod -Method Get -Uri $resource -Headers $header -Body $body -ContentType "application/octet-stream" -OutFile $OutFile -Proxy $Proxy_uri -ProxyUseDefaultCredentials -Verbose
							return
						}

						else{
							$r=Invoke-RestMethod -Method get -Uri $resource -Headers $header -Body $body -ContentType "application/octet-stream" -OutFile $OutFile
							return
						}
					}
					"restore"{
						if (!$id){
							Write-Error "[Invoke-HX_API]::No Quarantine ID provided"
							break
						}
						$method = "POST"
						$endpoint = "/hx/api/v3/quarantines/$id/action/restore"
					}
				}
			}
			"Searches"{
				switch ($action){
					"list"{
						if ($id){$endpoint="/hx/api/v3/searches/$ID"}
						else{$endpoint="/hx/api/v3/searches"}
						$method="GET"
					}
					"get-childitem"{
						if (!$id){
							Write-Error "[Invoke-HX_API]::You must supply the search _ID #"
							break
						}
						$endpoint="/hx/api/v3/searches/$ID/results"
						$method="GET"
					}
					"stop"{
						$method="POST"
						$endpoint="/hx/api/v3/searches/$id/actions/stop"
					}
				}
			}
			"Scripts"{
				$endpoint="/hx/api/v3/scripts"
				switch ($action){
					"list"{$method="GET"}
					"get"{
						$method="GET"
						if (!$id){
							Write-Error "[Invoke-HX_API]::No Script ID provided. Use `"-action list`" to get all scripts,or provide a script ID"
						}
						else{$endpoint="/hx/api/v3/scripts/$id"}
					}
					"download"{
						$method="GET"
						$endpoint="/hx/api/v3/scripts.zip"
						$resource=$uri+$endpoint
						if (!$OutFile){
							Write-Error "[Invoke-HX_API]::No value for `$outfile provided."
						}

						if ($proxy){
							$r=Invoke-RestMethod -Method Get -Uri $resource -Headers $header -Body $body -ContentType "application/octet-stream" -OutFile $OutFile -Proxy $Proxy_uri -ProxyUseDefaultCredentials
							return
						}

						else{
							$r=Invoke-RestMethod -Method get -Uri $resource -Headers $header -Body $body -ContentType "application/octet-stream" -OutFile $OutFile
							return
						}
					}
				}
			}
			"SourceAlerts"{
			}
			"URL"{
				$method="GET"
				$endpoint=$url
			}
			default{"API Endpoint Not Defined,Please Contribute"}
		}

		#These API endpoints have different syntax for filtering based on DateTime,but we want to use the same -start and -end params regardless,so they need to be massaged here.
		switch ($endpoint){
			"/hx/api/v3/alerts"{
				if ($start -and $end){
					$filter=@{
						"operator"="between"
						"arg"=@($start,$end)
						"field"="reported_at"
					}
					$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
				}

				elseif ($start){
					$filter=@{
						"operator"="gt"
						"arg"=@($start)
						"field"="reported_at"
					}
					$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
				}

				elseif ($end){
					$filter=@{
						"operator"="lt"
						"arg"=@($end)
						"field"="reported_at"
					}
					$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
				}
			}
			"/hx/api/v3/alert_groups"{
				if ($start -and $end){
					$filter=@{
						"operator"="between"
						"arg"=@($start,$end)
						"field"="last_event_at"
					}
					$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
				}

				elseif ($start){
					$filter=@{
						"operator"="gt"
						"arg"=@($start)
						"field"="last_event_at"
					}
					$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
				}

				elseif ($end){
					$filter=@{
						"operator"="lt"
						"arg"=@($end)
						"field"="last_event_at"
					}
					$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
				}
			}
			default{}
		}

		if (!$content_type){$content_type="application/json"}

		$resource=$uri+$endpoint

		write-verbose "Resource: $resource"
		write-verbose "EndPoint: $endpoint"
		write-verbose "Method: $method"		
		write-verbose "Content_type: $content_type"
		write-verbose "Body: $body"
		#write-verbose "Header: $header"

		if ($proxy){
			$r=Invoke-RestMethod -Method $method -Uri $resource -Headers $header -Body $body -ContentType $content_type -Proxy $Proxy_uri -ProxyUseDefaultCredentials -Verbose
		}

		else{
			$r=Invoke-RestMethod -Method $method -Uri $resource -Headers $header -Body $body -ContentType $content_type -Verbose
		}
		
		if ($r.message -eq 'OK'){
			$token_time=get-date
		}

		return $r

	}#endprocess

	end{
		if ($api -eq "logout"){
			$token=$null
			$header=$null
		}
	}
}
