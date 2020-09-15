<#
.Synopsis
	Short description
.DESCRIPTION
	Long description
.EXAMPLE
	Invoke-HX_API HostSet new -type dynamic -hostset_name "AD_LAB1"
.EXAMPLE
	$r = hx Acquire -type bulk -action new -ScriptContent (base64 encode-utf8 (gc .\List-systemdrive_E.json -raw)) -ID 1234 -platform "*" -comment "policy tuning"
.EXAMPLE
    $h1 = hx HostSet new -hostset_name "UPD_CHG0312634_08_30_2020" -Verbose
.NOTES
   General notes
#>
function Invoke-HX_API{
	[CmdletBinding()]
	[Alias("HX","hx")]

	param (
		[switch]$Proxy,
		[switch]$sysinfo,

		[Parameter(Mandatory=$false,Position=0)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("Acquire","Alert_Filters","Alert_Groups","Alerts","Conditions","Configuration","Contain","Hosts","HostSet","HostsV3","IndicatorCategories","Indicators","LogOut","Policies","Quarantine","Scripts","Searches","SourceAlerts","URL")]
		$API,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("all","bulk","custom","dynamic","execution","file","ioc","live","mal","presence","static","triage")]
		$type,

		[Parameter(Mandatory=$false,Position=1)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("acknowledge","acquire","acquire-file","acquire-live","add","append","approve","cancel","delete","disable","download","enable","get","get-childitem","get-host_set_policies","get-quarantines","list","new","remove","request","restore","search","stop","triage","update")]
		$action,
		$body=@{},

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
		[ValidateSet("simple","complex")]
		$hostset_type,

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

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[string]$IPaddress,

		#Collection of HX Host IDs. Param used for creating new static host sets.
		$HostIDs,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("win","linux","osx","*")]
		[string]$platform,

		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[string]$Indicator_Name,

		#Collection of tests used for conditions
		$Tests,

		#HX Indicators Add
		$Condition,

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
		[string]$end
	)

	begin{
		#$start and $end must be before $hours and $days so that $hours and $days are not reformatted to local times.
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

		#region Config/Auth

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

		if ($limit){$body+=@{"limit"=$limit}}
		if ($offset){$body+=@{"offset"=$offset}}

		#endregion

		#region API Selection

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
							"get-childitem"{
								$method="GET"
								if (!$id){
									Write-Error "[Invoke-HX_API]::No Acquisition ID provided"
								}
								else{
									$endpoint="/hx/api/v3/acqs/bulk/$id/hosts"
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
							"download"{
								if (!$url){
									Write-Error "[Invoke-HX_API]::Please provide value for `$URL parameter in this format: /hx/api/v3/acqs/bulk/714/hosts/0123456789012345678901.zip you can find it using Invoke-HX_API Acquire get-childitem -type bulk -limit 100000 -ID xxx"
									break
								}

								$endpoint = $URL

								$resource = $uri + $endpoint

								$OutFile  = $url -replace "/hx/api/v3","$($pwd.path)"

								if ($proxy){
									Write-Verbose "Special Invoke-RestMethod for Bulk Acquisition Downloads"
									Write-Verbose "`$OutFile = $outfile"
									$r=Invoke-RestMethod -Method Get -Uri $resource -Headers $header -Body $body -ContentType "application/octet-stream" -OutFile (New-Item -Path $OutFile -Force) -Proxy $Proxy_uri -ProxyUseDefaultCredentials -Verbose
									return
								}

								else{
									Write-Verbose "Special Invoke-RestMethod for Bulk Acquisition Downloads"
									$r=Invoke-RestMethod -Method get -Uri $resource -Headers $header -Body $body -ContentType "application/octet-stream" -OutFile (New-Item -Path $OutFile -Force)
									return
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
								if (!$id){$id=Read-Host "host set ID"}
								if (!$platform){$platform=Read-Host "platform [win,linux,osx,*]"}
								if (!$comment){$comment=Read-Host "comment"}
								$body+=@{"scripts"=@( @{ "platform"= $platform.ToLower();"b64"=$ScriptContent})}
								$body+=@{"host_set"=@{"_id"=[int]$id}}
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
            "Alert_filters"{
				switch ($action){
					"list"{
        	            $endpoint="/hx/api/v3/alert_filters"
                        $method = "GET"
                    }
                    "new"{
        	            $endpoint="/hx/api/v3/alert_filters"
                        $method = "POST"
                        switch ($type){
                            "ioc"{
                                $body+=@{
                                    "filter"=@{
                                        "condition_id"=$Condition
                                    }
                                    "disposition"=""
                                }
                            }
                        }
                    }
                    "update"{
        	            $endpoint="/hx/api/v3/alert_filters/:$id"
                        $method = "patch"
                        switch ($type){
                            "ioc"{
                                $body+=@{
                                    "filter"=@{
                                        "condition_id"=$Condition
                                    }
                                    "disposition"=""
                                }
                            }
                        }
                    }
                }
				$body=$body|ConvertTo-Json -Compress
            }
			"Alert_Groups"{
				$endpoint="/hx/api/v3/alert_groups"
				switch ($action){
					"get"{
						$method="GET"
						if (!$AgentID -and !$query -and !$id -and !$IPaddress){
							throw "You must provide -agentid or -query (hostname) or -id (alertgroup _id) or -IPaddress"
						}
						if ($AgentID){
							$body+=@{"host.id"=$AgentID}
						}
						if ($query){
							$body+=@{"host.hostname"=$query}
						}
						if ($IPaddress){
							$body+=@{"host.primary_ip_address"=$IPaddress}
						}
						if ($id){
							$endpoint="/hx/api/v3/alert_groups/$id"
						}
					}
                    "get-childitem"{
                    	$method="GET"

                        if (!$id){$id=Read-Host "Alert Group IDs"}
                        $endpoint="/hx/api/v3/alert_groups/$id/alerts"
                    }
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
					"search"{
						$method="GET"
						$endpoint="/hx/api/v3/alert_groups/"

						if (!$query -and !$IPaddress -and !$Indicator_Name){
							throw "You must provide -query <hostname> or -IPaddress or -Indicator_Name <Indicator.uri_name>"
						}
						if ($query -and $IPaddress){
							throw "You must provide -query <hostname> OR -IPaddress"
						}

						if ($query){
							$filter=@{
								"operator"="contains"
								"arg"=@(,$query)
								"field"="host.hostname"
							}
							$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
						}
						if ($IPaddress){
							$filter=@{
								"operator"="contains"
								"arg"=@(,$IPaddress)
								"field"="host.primary_ip_address"
							}
							$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
						}
                        if ($Condition){
							$filter=@{
								"operator"="eq"
								"arg"=@(,$Condition)
								"field"="condition._id"
							}
							$body+=@{"filterQuery"=($filter|ConvertTo-Json -Compress)}
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

					}
					"list"{
						$method="GET"
						$endpoint="/hx/api/v3/alerts"
						$body+=@{"sort"='reported_at+descending'}
					}

					default{
						Write-Error "[Invoke-HX_API]::No value for the `"Action`" parameter"
					}
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
				#$body=$body | ConvertTo-Json
			}
			"Conditions"{
				switch ($action){
					"get"{
						$method="GET"
						$endpoint="/hx/api/v3/conditions/$id"
					}
					"list"{
						$method="GET"
						$endpoint="/hx/api/v3/conditions"
					}
					"disable"{
						$method="PATCH"
						$endpoint="/hx/api/v3/conditions/$id"
						$body+=@{"enabled"=$false}
						$body=$body|ConvertTo-Json -Compress
					}
					"enable"{
						$method="PATCH"
						$endpoint="/hx/api/v3/conditions/$id"
						$body+=@{"enabled"=$true}
						$body=$body|ConvertTo-Json -Compress
					}
					"new"{
						$method="POST"
						$endpoint="/hx/api/v3/conditions"
						if (!$Tests){
							Write-Error "[Invoke-HX_API]::Provide a collection of tests to be used for this new condition. API Guide pg.353"
							break
						}
						$body+=@{"tests"=$Tests}
						$body=$body|ConvertTo-Json -Compress
					}
					"search"{
						$method="GET"
						$endpoint="/hx/api/v3/conditions"
						$body+=@{"search"=$query}
					}
                    "update"{
						$method="PATCH"
						$endpoint="/hx/api/v3/conditions/$id"
						$body+=$body
						$body=$body|ConvertTo-Json -Compress
                    }
				}
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
			"HostsV3"{
				$endpoint="/hx/api/v3/hosts"
				switch($action){
					"get"{
						$method="GET"
						$endpoint+="/$AgentID"
					}
					"delete"{
						$method="DELETE"
						$endpoint+="/$AgentID"
					}
					"list"{
						$method="GET"
					}
					"search"{
						$method="GET"
						if (!$query){
							$query=Read-Host -Prompt "Search Query"
						}
						$body+=@{"search"=$query}
					}
				}
			}
			"HostSet"{
				switch ($action){
					"get"{
						if (!$id){
							Write-Error "[Invoke-HX_API]::Hostset -ID not provided"
							if (!$id){$id=read-host -Prompt "Hostset ID"}
						}

						$method="GET"
						$endpoint="/hx/api/v3/host_sets/$id"
					}
					"delete"{
						if (!$id){
							Write-Error "[Invoke-HX_API]::Hostset -ID not provided"
							if (!$id){$id=read-host -Prompt "Hostset ID"}
						}

						$method="DELETE"
						$endpoint="/hx/api/v3/host_sets/$id"
					}
					"get-childitem"{
						if (!$id){
							Write-Error "[Invoke-HX_API]::Hostset -ID not provided"
							if (!$id){$id=read-host -Prompt "Hostset ID"}
						}

						$method="GET"
						$endpoint="/hx/api/v1/host_sets/$id/hosts"
					}
					"list"{
						$method="GET"
						$endpoint="/hx/api/v3/host_sets"
					}
					{($_ -eq "new") -or ($_ -eq "update")}{
						if (!$type){$type=read-host -Prompt "Static or Dynamic?"}
						if (!$hostset_name){$hostset_name=read-host -Prompt "Hostset Name?"}
						switch ($type){
							"dynamic"{
								switch ($action){
									"new"{
										$method="POST"
										$endpoint="/hx/api/v3/host_sets/dynamic"}
									"update"{
										if (!$id){
											$id=Read-Host -Prompt "Hostset ID?"
										}
										$method="PUT"
										$endpoint="/hx/api/v3/host_sets/dynamic/$id"
									}
								}
								switch ($hostset_type){
									"simple"{
										if (!$hostset_key){$hostset_key=read-host -Prompt "HostSet Key"}
										if (!$hostset_opr){$hostset_opr=read-host -Prompt "HostSet Operator"}
										if (!$hostset_val){$hostset_val=read-host -Prompt "HostSet Value"}

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
									"complex"{
										#No interactive options, build the complex query manually. Here's a template:
										<#
										$query=@{
											"operator"="SET_OPERATION";
											"operands"=@(
												@{
													operator="ATTRIBUTE_OPERATION";
													key     ="HOST_ATTRIBUTE";
													value   ="TEXT"
												},
												@{
													operator="ATTRIBUTE_OPERATION";
													key     ="HOST_ATTRIBUTE";
													value   ="TEXT"
												}
											)
										}
										#>
										$body+=@{
											"name"=$hostset_name
											"query"=$query
										}
									}
								}
							}
							"static"{
                                switch ($action){
									"new"{
										if (!$hostset_name){
											$hostset_name=Read-Host -Prompt "Hostset Name?"
										}
										$method="POST"
										$endpoint="/hx/api/v3/host_sets/static"

								        $body += @{
								        	"name"=$hostset_name
								        	"changes"=@(
								        		@{
								        			"command"="change"
								        		}
								        	)
								        }
                                    }
									"update"{
										if (!$id){
											$id=Read-Host -Prompt "Hostset ID?"
										}
										$method="PUT"
										$endpoint="/hx/api/v3/host_sets/static/$id"
                                    }
                                }
                            }
						}
						$body=$body|ConvertTo-Json -Depth 10 -Compress
					}
					#Add hosts to hostsets, not add hostsets. Use "-action new" for new host sets.
					"add"{
						if (!$type){
							Write-Error "[Invoke-HX_API]::Hostset -type not provided"
							if (!$type){$type=read-host -Prompt "Static or Dynamic?"}
						}

						if (!$id){
							Write-Error "[Invoke-HX_API]::Hostset -ID not provided"
							if (!$id){$id=read-host -Prompt "Hostset ID"}
						}

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
					#Remove hosts from hostsets, not remove hostsets. Use "-action delete" to delete host sets.
					"remove"{
						if (!$type){
							Write-Error "[Invoke-HX_API]::Hostset -type not provided"
							if (!$type){$type=read-host -Prompt "Static or Dynamic?"}
						}

						if (!$id){
							Write-Error "[Invoke-HX_API]::Hostset -ID not provided"
							if (!$id){$id=read-host -Prompt "Hostset ID"}
						}
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
				switch ($action){
					#There's a portion of the #region Post-processing that will automatically get all the conditions associated with an indicator, so this -action get, is really get then for each result, get-children.
					"get"{
						if (!$id){
							Write-Error "[Invoke-HX_API]::Provide Indicator.uri_name as -id"
							break
						}
						$method="GET"
						$endpoint = "/hx/api/v3/indicators"
						$body+=@{"uri_name"=$ID}
					}
					"get-childitem"{
						if (!$id){
							Write-Error "[Invoke-HX_API]::Provide Indicator.url as -id"
							break
						}
						$method="GET"
						$endpoint = "$id/conditions"
					}
					"list" {
						$method="GET"
						if (!$type){
							do{
								$type=Read-Host -Prompt "Choose Type: `"All`" or `"Custom`""
							}
							until(
								$type -in @("all","custom")
							)
						}
						switch ($type){
							"all"   {$endpoint="/hx/api/v3/indicators"}
							"custom"{$endpoint="/hx/api/v3/indicators/custom"}
							default {$endpoint="/hx/api/v3/indicators/custom"}
						}
					}
					"replace"{
						#Bulk Replace Conditions Request

						if (!$id){write-host -ForegroundColor Yellow "Provide Indicator.uri_name as -id"}

						Write-Host -f Magenta "This action REPLACES the conditions of an indicator with what you send with `$input, it DOES NOT APPEND, IT REPLACES"
						do{$r=Read-Host -Prompt "Type `"yes`" to continue. Ctrl+C to quit"}until($r-eq"yes")

						$method="PUT"
						$endpoint="/hx/api/v3/indicators/custom/$id/conditions"

						#$input should be a new line separated list of MD5 or Domain or IP Address
						if ($input -match ","){
							Write-Error -Message "`Parameter: -input should be a new line separated list of MD5 or Domain or IP Address. Your list had a comma, try again."
							break
						}

						else {$body = $input}

						$content_type="text/plain"

					}
					"append" {
						#Bulk Append Conditions Request

						if (!$id){write-host -ForegroundColor Yellow "Provide Indicator.uri_name as -id"}

						$method="PATCH"
						$endpoint="/hx/api/v3/indicators/custom/$id/conditions"

						if ($null -eq $query){
							throw "`Parameter: -query should be a new line separated list of MD5 or Domain or IP Address. You sent nothing, try again."
						}
						#$input should be a new line separated list of MD5 or Domain or IP Address
						if ($query -match ","){
							Write-Error -Message "`Parameter: -input should be a new line separated list of MD5 or Domain or IP Address. Your list had a comma, try again."
							break
						}

						else {$body = $input}

						$content_type="text/plain"
					}
					"new" {
						$method = "PUT"

						if ($null -eq $Indicator_Name){
							$id=read-host -Prompt "Name for new indicator; Please follow naming convention. Ask if you dont know what it be"
						}

						if ($null -eq $comment){
							$id=read-host -Prompt "Description for new indicator"
						}

						$endpoint="/hx/api/v3/indicators/custom/$Indicator_Name"

						$body+=@{
							"description"=$comment
							"display_name"=$Indicator_Name
						}

						$body=$body|ConvertTo-Json -Compress
					}
					"update"{
						$method="PATCH"
						$endpoint="/hx/api/v3/indicators/custom/$id/"

						if ($null -ne $comment){
							$body+=@{
								"description"=$comment
							}
						}

						$body=$body|ConvertTo-Json -Compress

					}
					"add"{
						$method = "POST"

						if (
							($null -eq $type) -or
							($type -notin @("presence","execution"))
						){
							do {
								$type=read-host -Prompt "presence or execution?"
							}
							until($type -in @("presence","execution"))
						}
						$endpoint = "/hx/api/v3/indicators/custom/$Indicator_Name/conditions/$type"

						#The intent is to pipeline results from the conditions API to the indicators API. The API requires only the tests to be sent, but it still needs to be an object, so we just pop off the unneeded properties, bam.
						$condition.psobject.Properties.Remove("_id")       |out-null
						$condition.psobject.Properties.Remove("uuid")      |out-null
						$condition.psobject.Properties.Remove("event_type")|out-null
						$condition.psobject.Properties.Remove("enabled")   |out-null
						$condition.psobject.Properties.Remove("is_private")|out-null
						$condition.psobject.Properties.Remove("url")       |out-null

						$body=$Condition

						$body=$body|ConvertTo-Json -Compress
					}
                    "remove"{
                        #Detach condition from Indicator
                        Write-Host -f y "-id <Indicator._id> -condition <Condition.UUID>"
                        $method = "DELETE"
                        $endpoint = "/hx/api/v3/indicators/custom/$ID/conditions/$type/$Condition"
                    }
				}
			}
			"LogOut"{
				$endpoint="/hx/api/v3/token"
				$method="DELETE"
			}
			"Policies"{
				$endpoint="/hx/api/v3/policies"

				switch ($action){
					"get"{
						$method="GET"
						$endpoint=$endpoint+"/$ID"
					}
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

		#endregion

		#region Pre-processing

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

		#endregion

		#region Invoke-RestMethod

		if (!$content_type){$content_type="application/json"}

		$resource=$uri+$endpoint
        Write-Verbose "#######Invoke-RESTMethod#Start"
		write-verbose "API: $API"
		write-verbose "Action: $action"
		write-verbose "Resource: $resource"
		write-verbose "EndPoint: $endpoint"
		write-verbose "Method: $method"
		write-verbose "Content_type: $content_type"
		write-verbose "Body: $body"
        write-verbose "Body2JSON: $($body|ConvertTo-Json)"
		#write-verbose "Header: $header"

		if ($proxy){
			$r=Invoke-RestMethod -Method $method -Uri $resource -Headers $header -Body $body -ContentType $content_type -Proxy $Proxy_uri -ProxyUseDefaultCredentials -Verbose -ErrorAction Continue -ErrorVariable err
		}

		else{
			$r=Invoke-RestMethod -Method $method -Uri $resource -Headers $header -Body $body -ContentType $content_type -Verbose -ErrorAction Continue -OutVariable err
		}
        
        Write-Verbose "#######Invoke-RESTMethod#End"
		
        if (
			$r.message -eq 'OK'
		){
			$token_time=get-date
		}

		#endregion

		#region Post-processing
        Write-Verbose "#########Post-processing-Start"

		if (
			($r) -and
			($API -eq "Indicators") -and
			($action -in @("get","list")) -and
			(Get-Command ConvertFrom-HX_Alert)
		){
			if ($r.data.entries){
				$r.data.entries|ForEach-Object{
					Write-Verbose "[Invoke-HX_API]::Secondary call for conditions - Foreach"
					$_.psobject.properties.add([psnoteproperty]::new("conditions",(hx Indicators get-childitem -ID $_.url -Verbose).data.entries))
				}
			}
			else{
				Write-Verbose "[Invoke-HX_API]::Secondary call for conditions - Justone"
				$r.data.psobject.properties.add([psnoteproperty]::new("conditions",(hx Indicators get-childitem -ID $r.data.url -Verbose).data.entries))
			}
		}

		if (
			($r) -and
			($API -in @("Alerts","Alert_Groups"))-and
			(Get-Command ConvertFrom-HX_Alert)
		){
			switch ($api){
				"Alerts"{
					if ($r.data.entries){
						$r.data.entries|ForEach-Object{
							$_.psobject.properties.add([psnoteproperty]::new("alert_parsed",($_|ConvertFrom-HX_Alert)))
						}
					}
					else{
						$r.data.psobject.properties.add([psnoteproperty]::new("alert_parsed",($r.data|ConvertFrom-HX_Alert)))
					}
				}
				"Alert_Groups"{
					if ($r.data.entries){
						$r.data.entries|ForEach-Object{
							$_.psobject.properties.add([psnoteproperty]::new("last_alert_parsed",($_.last_alert|ConvertFrom-HX_Alert)))
						}
					}
					else{
						$r.data.psobject.properties.add([psnoteproperty]::new("alert_parsed",($r.data|ConvertFrom-HX_Alert)))
					}
				}
			}
		}

		if (
			($API -eq "Conditions") -and
			($action -eq "new") -and
			(($err|out-string|ConvertFrom-Json).details.message -eq "Record already exists")
		){
			Write-Verbose "[Invoke-HX_API]::Condition Already Exists, Going to get existing version"
			$r = Invoke-HX_API -API Conditions -action get -ID ($err|out-string|ConvertFrom-Json).data._id -Verbose
		}

        Write-Verbose "#########Post-processing-End"
		#endregion

		return $r
	}

	end{
		if ($api -eq "logout"){
			$token=$null
			$header=$null
		}
	}
}
