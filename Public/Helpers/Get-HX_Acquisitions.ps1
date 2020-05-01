function Get-HX_Acquisitions {
	[CmdletBinding()]
	Param(
	[Parameter(Mandatory=$false, 
		Position=1)]
		[int]$limit=10,

	[Parameter(Mandatory=$false, 
		Position=0)]
	[string]$results="all",
	[switch]$download,
	[switch]$hosts
	)

	$acq = @()
	$acq += (Invoke-HX_API -API Acquire -type bulk   -action list -limit $limit).data.entries
	$acq += (Invoke-HX_API -API Acquire -type file   -action list -limit $limit).data.entries
	$acq += (Invoke-HX_API -API Acquire -type live   -action list -limit $limit).data.entries
	$acq += (Invoke-HX_API -API Acquire -type triage -action list -limit $limit).data.entries

	foreach ($a in $acq){

		$user = $a.request_actor.username

		if ($hosts){
			$acqhost  = (Invoke-HX_Api url -URL $a.host.url).data
			$target=$acqhost.hostname
		}
		else {$acqhost = ""}

		switch -Regex ($a.url){
		"file"{
			$acqtype  = "file"
			$t_start  = $a.request_time
			$t_last   = $a.finish_time
			$acqhost  = $acqhost
			$target   = $target
			$targetid = $a.host._id
			$user     = $a.request_actor.username

			$req=$a.req_path+"\"+$a.req_filename

			$a | Add-Member -NotePropertyName "Req" -NotePropertyValue $req -Force

		}

		"triages"{
			$acqtype = "triages"
			$t_start=$a.request_time
			$t_last=$a.finish_time
			$acqhost  = $acqhost
			$target   = $target
			$targetid = $a.host._id
			$user = $a.request_actor.username

		}
		"live"{
			$acqtype = "live"
			$t_start=$a.request_time
			$t_last=$a.finish_time
			$name=$a.name
			$acqhost  = $acqhost
			$target   = $target
			$targetid = $a.host._id
			$user = $a.request_actor.username

		}
		"bulk"{
			$acqtype = "bulk"
			$t_start=$a.create_time
			$t_last=$a.update_time
			$target=$a.host_set.name
			$targetid=$a.host_set._id
			$user = $a.create_actor.username

			#Stuff to get the acquistion script that defines what is actually collected, seems unnecesary to do every time. 
			<#
			try{
				$script=invoke-hx_api url -URL $a.scripts.download
				$script_info=switch ($script.GetType().name){
					"xmldocument"{
						foreach ($c in $script.command.script.commands){
							[pscustomobject]@{
								"commodule"=$c.command.type, $c.command.module.name -join ";"
								"param"=$c.command.config.parameters.param|%{$_.name, $_.value.'#text' -join "="}
							}
						}
					}
					"pscustomobject"{
						[pscustomobject]@{
							"commodule"=$script.jobfilter.type
							"param"=$script.jobfilter.value
						}
					}
				}
				$a|Add-Member -NotePropertyName "script_info" -NotePropertyValue $script_info
				Clear-Variable script, script_info -ErrorAction SilentlyContinue
			}
			catch {$script_info=($Error[0].ErrorDetails.Message|ConvertFrom-Json).details.message}
			#>
		}
		default {
			write-host "no ACQTYPE"
			$acqtype = "ERR-TypeNotDefined"
			$t_start = "ERR-TypeNotDefined"
			$t_last = "ERR-TypeNotDefined"

		}
	}

		$a | Add-Member -NotePropertyName "AcqType" -NotePropertyValue $acqtype -Force
		$a | Add-Member -NotePropertyName "TimeFirst" -NotePropertyValue $t_start -Force
		$a | Add-Member -NotePropertyName "TimeLast" -NotePropertyValue $t_last -Force
		$a | Add-Member -NotePropertyName "User" -NotePropertyValue $user -Force
		$a | Add-Member -NotePropertyName "Name" -NotePropertyValue $name -Force
		$a | Add-Member -NotePropertyName "Target" -NotePropertyValue $target -Force
		$a | Add-Member -NotePropertyName "TargetID" -NotePropertyValue $targetid -Force

		Clear-Variable t_start, t_last, acqtype, user, name, target, acqhost, req -ErrorAction SilentlyContinue
	}

	switch ($results){
		"all" {$acq}
		"some"{
			$pick = $acq|Sort-Object state, timelast |Select-Object _id,state,timefirst,timelast,user,acqtype,target,name,comment,url|Out-GridView -PassThru
			$pick
		}
	}
	
	if ($download){
		if ($pick){$acq = $pick}
		$acq | ForEach-Object{
			Invoke-HX_Api Acquire download -ID $_._id}
	}
}