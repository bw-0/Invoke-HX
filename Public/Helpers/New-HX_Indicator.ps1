function New-HX_Indicator {

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("INTERNAL","OSINT")]
		[string]$source,
		$Comment, #Needed for requesting new Indicator Index IDe from git, can skip if you already have a number/fullname
		$Description, #As seen in WebUI
		$Name, #Valid name for testing: 9.9.DESCRIPTION-MULT-Test
		$id, #If you already have an Indicator Index ID, set it here so we dont go requesting a new one.
		$indicator_uri_name, #If you already have the indicator created, but no conditions, or not exported to SCM, use this.
		$conditions, #If you already have conditions created, you can send them here
		$type="execution" #There appears to be no difference between presence and execution designations, so its being set by default. feel free to override.
	)

	function hol`up {
		param ($msg, $throw, $fc)
		do {
			write-host $msg -ForegroundColor $fc -NoNewline
			$go = Read-Host "[Y]es or [N]o"
			}
		until ($go -in @('y','n'))
		if ($go.Equals('n')){Invoke-Expression $throw}
	}

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

	function Test-Branch {
		param(
			[Parameter(Mandatory=$true,Position=0)]
			[ValidateNotNull()]
			[ValidateNotNullOrEmpty()]
			[ValidateSet("master","notmaster","name")]
			$type,
			[switch]$fix,
			$name
		)

		git branch | Tee-Object -Variable git_branch

		$git_branch_current = ($git_branch | Where-Object {$_ -match "^\*"}) -replace "\* ",""

		switch ($type){
			"master" {
				if ($git_branch_current -eq "master"){
					Write-Host -f Yellow "Current Branch: $git_branch_current"
				}
				else {
					if ($fix){
						write-host "Supposed to be on master branch, Switching now.."
						git checkout master
					}
					else {throw "Supposed to be on master branch. Can be fixed with -fix param switch"}
				}
			}
			"notmaster" {
				if ($git_branch_current -eq "master"){
					if ($fix){
						$newbranch= read-host "Get off Master Branch. New branch name or ctrl+c to exit"
						if ($null = $newbranch){throw "No new branch name given"}
						else {
							git branch $newbranch
							git checkout $newbranch
						}
						if (-not (Test-Branch notmaster)){throw "Couldn't get to a new branch, good luck"}
					}
					else {throw "Cannot be on master branch. Can be fixed with -fix param switch"}
				}
				else{
					Write-Host -f Yellow "Current Branch: $git_branch_current"
				}
			}
			"name"{
				if ($git_branch_current -ne $name){

					if ($fix){
						write-host "Supposed to be on $name branch, Switching now.."

						#just look away for a second..
						git checkout $name  2>&1> $env:TEMP\temp_New-HX_Indicator.txt
						$out = Get-Content $env:TEMP\temp_New-HX_Indicator.txt

						if ($out[0] -match "git : error: pathspec"){
							hol`up "That branch doesn't exist, create it now?" -fc yellow -throw "throw ''"

							git branch   $name
							git checkout $name
						}

						else{
							Write-Host -f Yellow $out
							Write-Host -f Yellow "Current Branch: $git_branch_current"
							Throw "Not sure what'll break if it goes on so we'll just pull the plug here. You had an error switching to a branch in git, figure that out and try again"
						}
					}
					else{throw "Supposed to be on branch: $name. Can be fixed with -fix param switch"}
				}
				else{
					Write-Host -f Yellow "Current Branch: $git_branch_current"
				}
			}
		}
	}

	function New-HX_Rule_Index {
		[CmdletBinding()]
		param (
			$source
		)

		#This JSON file stores the last index ID used for a given intel source. This is how the rules are sequentially numbered while also ensuring multiple operators are not planning introducing a new rule with a duplicated index value.
		try {$ID_index = Get-Content .\ID_Index.json | ConvertFrom-Json}
		catch {Throw "[New-HX_Rule_Index]::Cannot read ID_Index.json"}

		if (!$source){
			$sources = @("INTERNAL","OSINT")
			do {
				$source=read-host "Content Source:$($sources -join ",")"
			}
			until ($source -in $sources)
		}

		switch ($source){
			"Internal" {$ID_source = 1}
			"OSINT"    {$ID_source = 2}
		}

		#bump the index value
		$ID_next = $ID_index.$ID_source + 1

		#Set new value
		$ID_index.$ID_source = $ID_next

		#Update Index ID tracker.
		#This should be pushed ASAP to let others know you have the new ID.
		$ID_index | ConvertTo-JSON+ | Out-File .\ID_Index.json -Encoding utf8

		git add .\ID_Index.json

		if ($null -eq $Comment){
			$Comment = Read-Host "Comment for commit of index++"
		}
		git commit -m $Comment | Out-Null

		#This was showing errors but the push was still working so we're redirekting, no warranties included.
		git push *> $null

		#We'll just leave this here.. Use it if you need to revert a remote commit after reverting your local commit:
		#git push origin +master

		$return = "$ID_source.$($ID_index.$ID_source)"

		Write-Verbose "Your New Index value is $return"

		return $return
	}

	function New-HX_Condition_Test {
	
		[CmdletBinding()]
		Param(
			$test_token,
			$test_type,
			$test_operator,
			$test_value
		)
	
		try {
			$taxonomy = Get-Content "$((Get-Module invoke-hx).ModuleBase)\Public\Helpers\HX_Condition_Taxonomy.json" | ConvertFrom-Json
		}
		catch {
			throw "[New-HX_Condition_Test]::Error getting HX_Condition_Taxonomy.json from Invoke-HX module\public\helpers directory"
		}
	
		if (!$test_token){
			do {
				$test_token = $taxonomy.tokens.ForEach({$_.psobject.Properties.name})|Out-GridView -PassThru
				if ($test_token.count -ne 1){write-host -f Red "[New-HX_Condition_Test]::Try again, select only 1 for now. You'll be prompted for more tokens if needed."}
			}
			until ($test_token.count -eq 1)
		}
	
		if (
			($null -eq $test_type)
		){
	
			$list_type=$taxonomy.tokens.$test_token.Where({$null -ne $_})
	
			if ($list_type.count -gt 1){
				do {$test_type = read-host "Choose: $($list_type -join ", " )"}
				until ($test_type -in $list_type)
			}
			elseif ($list_type.count -lt 1){
				throw "[New-HX_Condition_Test]::Error getting test type"
			}
			else {
				Write-Verbose "[New-HX_Condition_Test]::Auto-Choosing value type"
				$test_type = $list_type[0]
			}
		}
	
		if ($null -eq $test_operator){
	
			$list_operator=$taxonomy.operators.$test_type.Where({$null -ne $_})
	
			if ($list_operator.count -gt 1){
				do {$test_operator= read-host "Choose: $($list_operator -join ", ")"}
				until ($test_operator -in $list_operator)
			}
			else {
				Write-Verbose "[New-HX_Condition_Test]::Auto-Choosing operator"
				$test_operator = $list_operator
			}
		}
	
		if ($null -eq $test_value){
			$test_value= read-host "Test_Value"
		}
	
		write-verbose "Test_token   : $test_token"
		write-verbose "Test_type    : $test_type"
		Write-verbose "Test_operator: $test_operator"
		Write-verbose "Test_value   : $test_value"
		
		$test = [pscustomobject]@{
			"token"   = $test_token
			"type"    = $test_type
			"operator"= $test_operator
			"value"   = $test_value
		}
	
		return $test
	
	}


	#region Setup

	if ((Get-Location).Path -notmatch "\\hxcontent$"){
		throw "Please move to root of hxcontent repo to ensure relative paths are correct"
	}
	else {$path_hxcontent = (Get-Location).Path}

	Initialize-Working_Tree $path_hxcontent

	#endregion


	#region Get New Index

	if (!$id -and !$indicator_uri_name){
		hol`up "Since you didn't supply an Index ID for the new rule the next step will create a new one.`nIf you already have an index number you should cancel and use the -id param`nSure you want to get a new Index ID and commit the change using Git?" -fc y -throw 'throw "You successfully pumped the brakes"'
		Initialize-Working_Tree ".\hx-meta" | Out-Null
		Test-Branch -type master -fix | Out-Null
		$id = New-HX_Rule_Index -verbose
		Set-Location $path_hxcontent
	}

	#endregion


	#region Indicator Name/Description

	$regex_half =                                              "^[A-Z]+-(?<CKC>REC|WEAP|DELIVERY|EXP|INSTALL|C2|AOO|MULT)-(?<DESCRIPTION>[A-Za-z0-9_]+)$"
	$regex_full = "^(?<SOURCE>[0-9]{1})\.(?<INDEXOF>[0-9]{1,3})\.[A-Z]+-(?<CKC>REC|WEAP|DELIVERY|EXP|INSTALL|C2|AOO|MULT)-(?<DESCRIPTION>[A-Za-z0-9_]+)$"

	Write-Host $indicator_uri_name

	if (
		!$indicator_uri_name -and !$name
	){
		do {
			$name = read-host "New Indicator name, leave out the index numbers, they'll be applied automatically`nMust Match:$regex_half`n"
		}
		until (
			($name -match $regex_half)
		)
	}

	if (
		($null -ne $indicator_uri_name) -and
		($indicator_uri_name -notmatch $regex_full)
	){
		throw "[New-HX_Indicator]::The Indicator name you provided doesn't fit the naming convention, figure that out and come back"
	}

	if (!$Description -and !$indicator_uri_name){
		do {
			$Description=read-host "Indicator Description"
		}
		until ($null -ne $Description)
	}

	#endregion


	#region Create Indicator
	if ($indicator_uri_name){
		try {
			$indicator = (hx Indicators get -id $indicator_uri_name -Verbose).data.entries
		}
		catch {throw "Error with existing indicator"}
	}
	else{
		write-host -ForegroundColor yellow "[New-HX_Indicator]::Creating new indicator."
		$indicator = (hx Indicators new -Indicator_Name "$id.$Name" -comment $description -Verbose).data
	}

	#Retreive new indicator for review
	write-host -ForegroundColor yellow "[New-HX_Indicator]::Review the Indicator we're about to add conditions to:"
	(hx Indicators get -ID $indicator.uri_name).data.entries

    #Build Conditions
	if (!$tests -or !$conditions){
		$conditions=@()

		do {
			#Define tests for the conditon
			write-host -ForegroundColor yellow "[New-HX_Indicator]::Define tests for condition"
			$tests=@()
			do {
				$tests += New-HX_Condition_Test -Verbose
				$more_t=read-host "Add another test? Yes or No"
				}
			until ($more_t -eq "no")

			#Review condition in console
			write-host -ForegroundColor yellow "[New-HX_Indicator]::Review the tests"

			write-host ($tests | ConvertTo-JSON)

			hol`up "That look good to you?" -fc yellow -throw "throw '[New-HX_Indicator]::You pumped the brakes on a messed up Condition. When you try again reference the indicator you already created using -indicator_uri_name'"

			#Create condition
			write-host -ForegroundColor yellow "[New-HX_Indicator]::Going to create new condition"
			$conditions += (hx Conditions new -Tests $tests -Verbose).data

			if ($null -eq $conditions){
				write-host -ForegroundColor Red "[New-HX_Indicator]::Error creating condition`nWhen you try again reference the indicator you already created using -indicator_uri_name $($indicator.uri_name)"
				return $error[0]
			}


			$more_c=read-host "Add another Condition? Yes or No"

		}
		until($more_c -eq "no")

		#Disable new condition as safety switch
		write-host -ForegroundColor yellow "[New-HX_Indicator]::Going to disable new condition"
		try {
			$conditions._id|ForEach-Object{
				hx Conditions disable -ID $_ -Verbose
			}
		}
		catch {return $error[0];throw}
	}

	#Attach conditions to new indicator
	write-host -ForegroundColor yellow "[New-HX_Indicator]::Going to add conditions to indicator"

	$conditions | ForEach-Object {
		hx Indicators add -type $type -Condition $_ -Indicator_Name $indicator.uri_name -Verbose
	}

	#Get updated indicator
	$review = hx Indicators get -ID $indicator.uri_name -Verbose

	#Review indicator
	write-verbose ($review.data.entries | ConvertTo-JSON+)
	write-host -ForegroundColor Green "[New-HX_Indicator]::You made it!!"

	#endregion


	#region Export New rule to SCM

	#The repo which contains the rules does not allow committing to master without a pull request. We need to get off the master branch and onto a new branch.
	Test-Branch -type name -name $indicator.uri_name -fix

	#Convert to JSON for SCM
	$review.data.entries | ConvertTo-JSON+ | Out-File ".\Rules\$($review.data.entries[0].uri_name).json" -Encoding utf8 -Verbose

	Write-Verbose "New indicator created, you must create pull request now"

	return $review.data.entries[0]

	#endregion
}



#region Junkyard
<#

$indicator = (hx Indicators list -type custom).data.entries|ogv -PassThru
$conditions = @()
$conditions += (hx Conditions search -query caff).data.entries|ogv -PassThru


$tests=@()
$tests += New-HX_Condition_Test -Verbose
$conditions += (hx Conditions new -Tests $tests -Verbose).data

#>
#endregion
