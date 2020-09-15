#This is predicated on having a git repository like: hxcontent\exclusions with an individual Exclusion Definition File (EDF) for each app.
#EDF Template
#{
#	"name":  "_template",
#	"client":  {
#		"MD5":  [
#			
#		],
#		"path":  {
#			"osx":  [
#				
#			],
#			"win":  [
#				
#			]
#		},
#		"process":  {
#			"osx":  [
#				
#			],
#			"win":  [
#				
#			]
#		}
#	},
#	"server":  {
#		"MD5":  [
#			
#		],
#		"path":  {
#			"osx":  [
#				
#			],
#			"win":  [
#				
#			]
#		},
#		"process":  {
#			"osx":  [
#				
#			],
#			"win":  [
#				
#			]
#		}
#	}
#}
function Set-HX_Exclusions{

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("push","sync")]
		[string]$type,
		[Parameter(Mandatory=$true)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("check","fix")]
		[string]$action
	)

	function Initialize-Working_Tree ($path_repo){

		Set-Location  $path_repo

		git status | Tee-Object -Variable git_status

		if (
			$git_status -notcontains "nothing to commit, working tree clean"
		){
			Write-Verbose "git pull"
			git pull
			Start-Sleep 4
			$git_status = git status
			if ($git_status -notcontains "nothing to commit, working tree clean"){
				throw "You have changes that need to be committed"
			}
		}
		else {
			write-verbose "repo up to date"
		}
	}

	if ((Get-Location).Path -notmatch "\\hxcontent$"){
		throw "Please move to root of hxcontent repo to ensure relative paths are correct"
	}
	else {$path_hxcontent = (Get-Location).Path}

	Initialize-Working_Tree $path_hxcontent

	#region Get Exclusions

	#Import Exclusion Definition Files from repo

	$file_dir = Get-ChildItem $path_hxcontent\Exclusions
	$file_apps = $file_dir.Where({($_.name -notmatch "^_")-and($_.name -ne "test.json")})
	$apps = $file_apps | ForEach-Object{Get-Content $_.FullName|ConvertFrom-Json}


	#region verify each exclusion is formatted correctly

	foreach ($a in $apps){

		if (
			$a.name -match "client" -and
			$a.name -match "server"
		){
			$a.name;throw "Policy Format Error - Policy Name cannot be client && server"
		}
		else{}

		if (
			$null -ne $a.name -and
			(($a.psobject.properties|Measure-Object).Count -eq 3)-and
			($a.psobject.properties.name|ForEach-Object{$_ -in @("name","client","server")})
		){}
		else{
			$a.name;throw "Policy Format Error - Top Level"
		}

		if (
			(($a.client.psobject.properties|Measure-Object).Count -eq 3)-and
			($a.client.psobject.properties.name|ForEach-Object{$_ -in @("md5","path","process")})-and
			($a.client.psobject.Properties["md5"].value.GetType().isarray -eq $true) -and
			($a.client.psobject.Properties["path"].value.GetType().isarray -eq $false) -and
			($a.client.psobject.Properties["process"].value.GetType().isarray -eq $false)
		){}
		else{
			$a.name;throw "Policy Format Error - Client Level"
		}

		if (
			(($a.client.path.psobject.properties|Measure-Object).Count -eq 2)-and
			($a.client.path.psobject.properties.name|ForEach-Object{$_ -in @("osx","win")})
		){}
		else{
			$a.name;throw "Policy Format Error - Client Level - Paths"
		}

		if (
			(($a.client.process.psobject.properties|Measure-Object).Count -eq 2)-and
			($a.client.process.psobject.properties.name|ForEach-Object{$_ -in @("osx","win")})
		){}
		else{
			$a.name;throw "Policy Format Error - Client Level - Processes"
		}

		if (
			(($a.server.psobject.properties|Measure-Object).Count -eq 3)-and
			($a.server.psobject.properties.name|ForEach-Object{$_ -in @("md5","path","process")})-and
			($a.server.psobject.Properties["md5"].value.GetType().isarray -eq $true) -and
			($a.server.psobject.Properties["path"].value.GetType().isarray -eq $false) -and
			($a.server.psobject.Properties["process"].value.GetType().isarray -eq $false)

		){}
		else{
			$a.name;throw "Policy Format Error - Server Level"
		}

		if (
			(($a.server.path.psobject.properties|Measure-Object).Count -eq 2)-and
			($a.server.path.psobject.properties.name|ForEach-Object{$_ -in @("osx","win")})
		){}
		else{
			$a.name;throw "Policy Format Error - Server Level - Paths"
		}

		if (
			(($a.server.process.psobject.properties|Measure-Object).Count -eq 2)-and
			($a.server.process.psobject.properties.name|ForEach-Object{$_ -in @("osx","win")})
		){}
		else{
			$a.name;throw "Policy Format Error - Server Level - Processes"
		}
	}

	#endregion


	$server = $apps.Where({$_.name -in @("NAME_OF_SERVER_ONLY_APP")})

	$client_excludedMD5s              = $apps.Where({$_.name -notin @($server.name)}).client.md5    | Sort-Object
	$client_excludedFiles_win        =  $apps.Where({$_.name -notin @($server.name)}).client.path.win | Sort-Object
	$client_excludedFiles_osx       =   $apps.Where({$_.name -notin @($server.name)}).client.path.osx   | Sort-Object
	$client_excludedProcesses_win  =    $apps.Where({$_.name -notin @($server.name)}).client.process.win  | Sort-Object
	$client_excludedProcesses_osx =     $apps.Where({$_.name -notin @($server.name)}).client.process.osx    | Sort-Object

	#shortened for easy reference
    $MYAPP=$apps.Where({$_.name -eq "MYAPP"})

    #endregion


	$policies = (Invoke-HX_API Policies list -limit 100).data.entries

	Write-Host -F DarkYellow "`nIf there are any differences, the arrow shows where the exclusion needs to go."
    Write-Host -F DarkYellow "Left arrow means remote copy has something local doesn't, and it would need to go to the local copy to be equal"
    Write-Host -F DarkYellow "Right arrow means local copy has something remote doesn't, and it would need to go to the remote copy to be equal"
	write-host -F yellow     "Local Repo <= " -NoNewline
	write-host -F DarkYellow "SideIndicator" -NoNewline
	write-host -F yellow     " => HX prod policy`n"

	foreach ($policy in $policies){

		#This collection will contain any exclusions needing to be pushed to HX and is used for documenting change.
		$digest = @()

		#This was needed for Compare-Object to work as expected
		$old = $policy | ConvertTo-Json -Depth 100 | ConvertFrom-Json

		Write-Host -ForegroundColor Yellow "$($policies.IndexOf($policy)) $($policy.name)"

		#For HX polices that are scoped to a specific application, Get the matching Exclusions based on the policy name
		$app_name = ($policy.name -split "_")[-1]

		$match = ($apps.Where({$_.name -eq $app_name}))


		#region Malware Protection

		if (
			$policy.categories.malware_protection -and
			$policy.name -notin @("Agent Default policy","test")
		){

			#This behaves like a symbolic link to reduce the line length below. Changes here will be reflected in $policy
			$config_mal_osx = $policy.categories.malware_protection.'platform#osx'
			$config_mal_win = $policy.categories.malware_protection.'platform#win'

			Write-Verbose "Switch - Malware - Name"

			switch -Regex ($policy.name){

				#Level 0 - Explicit Server
				#Compound policy per application. This example is windows only so it doesn't need the OSX exclusions as well
				"APP1"{
					write-host "Switch - Malware - Name - Level 1 - APP1" -f cyan

					Write-host -ForegroundColor Cyan "malware_protection.'platform#win'.excludedMD5s"
					Compare-Object @($config_mal_win.excludedMD5s     | Select-Object) @($client_excludedMD5s          + $match.server.md5         + $server.client.MD5         + $MYAPP.server.md5 | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_win.excludedMD5s =      $config_mal_win.excludedMD5s      + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_mal_win.excludedMD5s =      $config_mal_win.excludedMD5s      + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#win'.excludedFiles"
					Compare-Object @($config_mal_win.excludedFiles    | Select-Object) @($client_excludedFiles_win     + $match.server.path.win    + $server.client.path.win    + $MYAPP.server.path.win | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_win.excludedFiles =     $config_mal_win.excludedFiles     + $add.inputobject| Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_mal_win.excludedFiles =     $config_mal_win.excludedFiles     + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#win'.excludedProcesses"
					Compare-Object @($config_mal_win.excludedProcesses| Select-Object) @($client_excludedProcesses_win + $match.server.process.win + $server.client.process.win + $MYAPP.server.process.win | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_win.excludedProcesses = $config_mal_win.excludedProcesses + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_mal_win.excludedProcesses = $config_mal_win.excludedProcesses + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue

					break
				}

				#Level 1 - Implicit Server
				#Each server class will have a matching exclusion definition file. The Policy name needs to follow correct naming convention to work (just a single token after ...server_)
				"server"{
					write-host "Switch - Malware - Name - Level 2 - All Server" -f cyan

					Write-host -ForegroundColor Cyan "malware_protection.'platform#osx'.excludedMD5s"
					Compare-Object @($config_mal_osx.excludedMD5s    | Select-Object) @($client_excludedMD5s           + $match.server.md5         + $server.client.MD5         | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_osx.excludedMD5s = $config_mal_osx.excludedMD5s + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_mal_osx.excludedMD5s = $config_mal_osx.excludedMD5s + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#win'.excludedMD5s"
					Compare-Object @($config_mal_win.excludedMD5s    | Select-Object) @($client_excludedMD5s           + $match.server.md5         + $server.client.MD5         | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_win.excludedMD5s = $config_mal_win.excludedMD5s + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							 $config_mal_win.excludedMD5s = $config_mal_win.excludedMD5s + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#osx'.excludedFiles"
					Compare-Object @($config_mal_osx.excludedFiles    | Select-Object) @($client_excludedFiles_osx     + $match.server.path.osx    + $server.client.path.osx    | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
						$config_mal_osx.excludedFiles = $config_mal_osx.excludedFiles + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
								$config_mal_osx.excludedFiles = $config_mal_osx.excludedFiles + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#win'.excludedFiles"
					Compare-Object @($config_mal_win.excludedFiles    | Select-Object) @($client_excludedFiles_win     + $match.server.path.win    + $server.client.path.win    | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_win.excludedFiles = $config_mal_win.excludedFiles + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							 $config_mal_win.excludedFiles = $config_mal_win.excludedFiles + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#osx'.excludedProcesses"
					Compare-Object @($config_mal_osx.excludedProcesses| Select-Object) @($client_excludedProcesses_osx + $match.server.process.osx + $server.client.process.osx | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_osx.excludedProcesses = $config_mal_osx.excludedProcesses + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							 $config_mal_osx.excludedProcesses = $config_mal_osx.excludedProcesses + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#win'.excludedProcesses"
					Compare-Object @($config_mal_win.excludedProcesses| Select-Object) @($client_excludedProcesses_win + $match.server.process.win + $server.client.process.win | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_win.excludedProcesses = $config_mal_win.excludedProcesses + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_mal_win.excludedProcesses = $config_mal_win.excludedProcesses + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue

					break
				}

				#Level 2 - Clients
				default{
					write-host "Switch - Malware - Name - Level 3 - Client/Default" -f cyan

					Write-host -ForegroundColor Cyan "malware_protection.'platform#osx'.excludedMD5s"
					Compare-Object @($config_mal_osx.excludedMD5s    | Select-Object) @($client_excludedMD5s           | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_osx.excludedMD5s = $config_mal_osx.excludedMD5s + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_mal_osx.excludedMD5s = $config_mal_osx.excludedMD5s + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#win'.excludedMD5s"
					Compare-Object @($config_mal_win.excludedMD5s    | Select-Object) @($client_excludedMD5s           | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_win.excludedMD5s = $config_mal_win.excludedMD5s + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							 $config_mal_win.excludedMD5s = $config_mal_win.excludedMD5s + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#osx'.excludedFiles"
					Compare-Object @($config_mal_osx.excludedFiles    | Select-Object) @($client_excludedFiles_osx     | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
						$config_mal_osx.excludedFiles = $config_mal_osx.excludedFiles + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
								$config_mal_osx.excludedFiles = $config_mal_osx.excludedFiles + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#win'.excludedFiles"
					Compare-Object @($config_mal_win.excludedFiles    | Select-Object) @($client_excludedFiles_win     | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_win.excludedFiles = $config_mal_win.excludedFiles + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							 $config_mal_win.excludedFiles = $config_mal_win.excludedFiles + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#osx'.excludedProcesses"
					Compare-Object @($config_mal_osx.excludedProcesses| Select-Object) @($client_excludedProcesses_osx | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_osx.excludedProcesses = $config_mal_osx.excludedProcesses + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							 $config_mal_osx.excludedProcesses = $config_mal_osx.excludedProcesses + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue


					Write-host -ForegroundColor Cyan "malware_protection.'platform#win'.excludedProcesses"
					Compare-Object @($config_mal_win.excludedProcesses| Select-Object) @($client_excludedProcesses_win | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_mal_win.excludedProcesses = $config_mal_win.excludedProcesses + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_mal_win.excludedProcesses = $config_mal_win.excludedProcesses + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue

					break
				}
			}
		}
		#endregion


		#region Realtime Detection

		if (
			$policy.categories.real_time_indicator_detection -and
			$policy.name -notin @("realtime_detection-Disabled","test","Agent Default policy")
		){

			$config_rtd = $policy.categories.real_time_indicator_detection

			write-host "Switch - Realtime - Name" -f Cyan

			switch -Regex ($policy.name){

				#Level 0 - Explicit Server
				"APP1"{

					write-host "Switch - Realtime - Name - Level 1 - APP1" -f Cyan

					Write-host -ForegroundColor Cyan "real_time_indicator_detection.excludedPaths"
					Compare-Object @($config_rtd.excludedPaths    | Select-Object) @($client_excludedFiles_win        + $match.server.path.win    + $MYAPP.server.path.win    + $server.client.path.win | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_rtd.excludedPaths =        $config_rtd.excludedPaths        + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_rtd.excludedPaths =        $config_rtd.excludedPaths        + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue

					Write-host -ForegroundColor Cyan "real_time_indicator_detection.excludedProcessNames"
					Compare-Object @($config_rtd.excludedProcessNames| Select-Object) @($client_excludedProcesses_win + $match.server.process.win + $MYAPP.server.process.win + $server.client.process.win | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_rtd.excludedProcessNames = $config_rtd.excludedProcessNames + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_rtd.excludedProcessNames = $config_rtd.excludedProcessNames + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue

					break
				}

				#Level 1 - Implicit Server
				"server"{
					write-host "Switch - Realtime - Name - Level 2 - All Server" -f Cyan

					Write-host -ForegroundColor Cyan "real_time_indicator_detection.excludedPaths"
					Compare-Object @($config_rtd.excludedPaths       | Select-Object) @($client_excludedFiles_osx     + $client_excludedFiles_win     + $match.server.path.osx    + $match.server.path.win    + $server.client.path.osx    + $server.client.path.win    | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_rtd.excludedPaths =        $config_rtd.excludedPaths        + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_rtd.excludedPaths =        $config_rtd.excludedPaths        + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue

					Write-host -ForegroundColor Cyan "real_time_indicator_detection.excludedProcessNames"
					Compare-Object @($config_rtd.excludedProcessNames| Select-Object) @($client_excludedProcesses_osx + $client_excludedProcesses_win + $match.server.process.osx + $match.server.process.win + $server.client.process.osx + $server.client.process.win | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_rtd.excludedProcessNames = $config_rtd.excludedProcessNames + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_rtd.excludedProcessNames = $config_rtd.excludedProcessNames + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue

					break
				}

				#Level 2 - Clients
				default{
					write-host "Switch - Realtime - Name - Level 3 - Client/Default" -f Cyan

					Write-host -ForegroundColor Cyan "real_time_indicator_detection.excludedPaths"
					Compare-Object @($config_rtd.excludedPaths    | Select-Object) @($client_excludedFiles_osx + $client_excludedFiles_win | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_rtd.excludedPaths =        $config_rtd.excludedPaths        + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_rtd.excludedPaths =        $config_rtd.excludedPaths        + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue

					Write-host -ForegroundColor Cyan "real_time_indicator_detection.excludedProcessNames"
					Compare-Object @($config_rtd.excludedProcessNames| Select-Object) @($client_excludedProcesses_osx + $client_excludedProcesses_win | Select-Object) -OutVariable compare |Format-Table
					$add = $compare.Where({$_.sideindicator -eq "=>"});$digest+=$add
					$rem = $compare.Where({$_.sideindicator -eq "<="});$digest+=$rem
					switch ($type){
						"push"{
							$config_rtd.excludedProcessNames = $config_rtd.excludedProcessNames + $add.inputobject | Select-Object -Unique | Sort-Object
						}
						"sync"{
							$config_rtd.excludedProcessNames = $config_rtd.excludedProcessNames + $add.inputobject | Where-Object {$_ -notin $rem.inputobject}| Select-Object -Unique | Sort-Object
						}
					}
					Remove-Variable compare, add, rem -ErrorAction SilentlyContinue

					break
				}
			}
		}

		#endregion


		#region Check/Fix Policy

		# Check to see if the original policy equals the in-memory policy that may or may not have had adjustments
		if (($old|ConvertTo-JSON -Depth 100) -ne ($policy|ConvertTo-JSON -Depth 100)){
			Write-Host -ForegroundColor Red "`tChange`n"

			switch ($action){
				"check" {}
				"fix"{
					$date = Get-Date -Format "yyyyMMddHHMMss"
					$digest, $old , $policy | ConvertTo-JSON+ | Out-File "$path_hxcontent\exclusions\_Logs\$date`_$($policy.name).txt" -Encoding utf8 -Force
					Invoke-HX_API Policies update -ID $policy._id -Policy $policy
				}
			}
		}
		else {Write-Host -ForegroundColor Green "`tNo Change`n"}

		#endregion


		Remove-Variable match, config_mal_osx, config_mal_win, config_rtd, digest -ErrorAction SilentlyContinue
	}#Foreach Policy

}
