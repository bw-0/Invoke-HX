function Update-HX_RealTime_Exclusion {
	<#
	.Synopsis
	   You get a pop-up to choose what policies to edit
	.DESCRIPTION
	   Long description
	.EXAMPLE
	   Update-HX_RealTime_Exclusion -action add -type process -entry "C:\Program Files\BryonWolcott.exe"
	.EXAMPLE
	   Another example of how to use this cmdlet
	.INPUTS
	   Inputs to this cmdlet (if any)
	.OUTPUTS
	   Output from this cmdlet (if any)
	.NOTES
	   General notes
	.COMPONENT
	   The component this cmdlet belongs to
	.ROLE
	   The role this cmdlet belongs to
	.FUNCTIONALITY
	   The functionality that best describes this cmdlet
	#>

	[CmdletBinding()]
	Param
	(
		# what you want to do
		[Parameter(Mandatory=$true, 
					ValueFromPipeline=$false,
					Position=0
					)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("add","remove")]
		[string]$action,

		# if its a process or path
		[Parameter(Mandatory=$true, 
					ValueFromPipeline=$false,
					Position=1
					)]
		[ValidateNotNull()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("process","path")]
		[string]$type,

		# What you want to exclude
		[Parameter(Mandatory=$true, 
					ValueFromPipeline=$true,
					ValueFromPipelineByPropertyName=$true, 
					ValueFromRemainingArguments=$false, 
					Position=2
					)]
		[string]$entry,
		[switch]$Proxy
	)

	Write-Host -ForegroundColor Cyan "[Update-HX_RealTime_Exclusion]::Getting Policies"
	
	if ($Proxy){
		$policies = (Invoke-HX_API -API Policies -action list -limit 100 -Proxy).data.entries
	}
	
	else {
		$policies = (Invoke-HX_API -API Policies -action list -limit 100).data.entries
	}
	
	Write-Host -ForegroundColor Cyan "[Update-HX_RealTime_Exclusion]::Got Policies"	

	$picks = $policies|Out-GridView -PassThru

	foreach ($pick in $picks){

		if (!$pick.categories.real_time_indicator_detection){
			Write-Host -ForegroundColor Magenta "[Update-HX_RealTime_Exclusion]::Policy Named `"$($pick.name)`" Does not have Real-Time Indicator Detection category configured already, Skipping"
			break
		}

		Write-Host "[Update-HX_RealTime_Exclusion]::Processing Policy Name: $($pick.name)"

		switch ($action){
			"add"{
				switch ($type){
					"process"{
							$pick.categories.real_time_indicator_detection.excludedProcessNames = $pick.categories.real_time_indicator_detection.excludedProcessNames+$entry
					}

					"path"{
							$pick.categories.real_time_indicator_detection.excludedPaths = $pick.categories.real_time_indicator_detection.excludedPaths+$entry
					}
				}
			}
			"remove"{
				switch ($type){
					"process"{
						$pick.categories.real_time_indicator_detection.excludedProcessNames = $pick.categories.real_time_indicator_detection.excludedProcessNames | Where-Object {$_ -ne $entry}
					}
					"path"{
						$pick.categories.real_time_indicator_detection.excludedPaths = $pick.categories.real_time_indicator_detection.excludedPaths | Where-Object {$_ -ne $entry}
					}
				}
			}
		}

		if ($proxy){
			Invoke-HX_API -API Policies -action update -ID $pick._id -Policy $pick -Verbose -Proxy
		}

		else{
			Invoke-HX_API -API Policies -action update -ID $pick._id -Policy $pick -Verbose
		}
	}
}
