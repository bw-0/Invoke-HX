function Set-HX_API_Auth{

	$outfile = "$HOME/feye_hx_api.txt"

	$username = Read-Host "username" -AsSecureString
	$password = Read-Host "password" -AsSecureString

	#Prepend Username to Password, separated by a colon
	$password.InsertAt(0,":")
	$BSTR_user = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($username)
	[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR_user).ToCharArray()[-1..-256]|ForEach-Object{$password.InsertAt(0,$_)}

	#Base 64 encode the authentication string
	$BSTR_pass = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
	$b64 =  [Convert]::ToBase64String([System.Text.Encoding]::ascii.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR_pass)))

	#Save creds
	#try/catch to support PowerShell Core on Linux. Linux doesn't support convertfrom-securestring
	try {
		Write-Host "[Set-HX_API_Auth]::Write Credentials to $outfile"
		$b64 | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File $outfile -Force -Verbose
		
	}
	catch {
		Write-Host "[Set-HX_API_Auth]::Write Credentials to $outfile"
		$b64 | Out-File $outfile -Verbose
	}
	
	#CleanUp
	$username.Dispose()
	$password.Dispose()
	[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR_user)
	[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR_pass)
	Clear-Variable b64
}