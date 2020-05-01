#Borrowed from https://github.com/RamblingCookieMonster/PSStackExchange/blob/db1277453374cb16684b35cf93a8f5c97288c41f/PSStackExchange/PSStackExchange.psm1
#Get public and private function definition files.
$Public  = @( Get-ChildItem -Path $PSScriptRoot\Public\  -Recurse -File -Filter *.ps1 -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\ -Recurse -File -Filter *.ps1 -ErrorAction SilentlyContinue )

#Dot source the files
Foreach($import in @($Public + $Private)){
	
	if ($null -eq $import){
		continue
	}
	
	Try{
		. $import.fullname
	}

	Catch{
		Write-Error -Message "Failed to import function $($import.fullname): $_"
	}
}