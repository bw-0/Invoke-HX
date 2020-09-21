function Get-HX_API_Auth{
    #This function doesn't visually output anything, it's used in Get-HX_API_Token.ps1
	$in_file = "$home/feye_hx_api.txt"

	if (!(Test-Path $in_file -ErrorAction SilentlyContinue)){
		Set-HX_API_Auth
	}

	$cred_stored = Get-Content $in_file

	#Check to see if creds are a secure string or base 64 encoded, then create a new PSCredential object to be used later.
	#All secure strings exported to plain text start with the same 48 characters, this small string is enough to differentiate it from base 64
	if ($cred_stored -match "^01000000"){
		New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "null", ($cred_stored | ConvertTo-SecureString)
	}

	else {
		New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "null", ($cred_stored | ConvertTo-SecureString -AsPlainText -Force)
	}

	Remove-Variable cred_stored
}