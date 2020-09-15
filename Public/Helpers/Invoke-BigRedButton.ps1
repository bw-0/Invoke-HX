function Invoke-BigRedButton{
<#
.Synopsis
   Request, and Approve HX Host Containment
.DESCRIPTION
   This function acts like a "Big Red Button" that you can press to 1. Arm a HX host for containment, 2. Approve HX host Containment
   The only parameter is a search query to find the host, it needs to resolve to a single HX host, and will prompt until exactly 1 result is returned.
.EXAMPLE
   Invoke-BigRedButton "Desktop-123456"
.EXAMPLE
   Invoke-BigRedButton 123456
#>
    [CmdletBinding()]
    [Alias("BRB")]
    Param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)
        ]$query
    )

    #not sure why the function isn't reading from my PS profile, but this is what's in there:
    $PSDefaultParameterValues = @{
    	"Invoke-HX_API:Proxy"=$true
    }

    do {
        if (!$query){$query = Read-Host -Prompt "Search Query"}
        $search = Invoke-HX_API -API Hosts -action search -query $query
        switch ($search.data.total){
            {$_ -lt 1}{
                Write-Host "Search returned no results, try again. Ctrl+C to exit"
                $query = Read-Host -Prompt "Search Query"
                break
            }
            {$_ -eq 1}{continue}
            {$_ -gt 1}{
                Write-Host "Search returned multiple results, Choose one, try again. Ctrl+C to exit"
                $query = Read-Host -Prompt "Search Query"                
                break
            }
            default{Write-Host "Search Error :("}
        }
    }
    while ($search.data.total -ne 1)

    $target_ID = $search.data.entries[0]._id
    $armed = hx Contain get -AgentID $target_ID

    if ($armed.data.queued -eq $false){
        do {
            $r1=Read-Host "Containment has not been requested. Request Containment? (Y)es, (N)o"
        }
        until ($r1 -in @('Y','N'))
        switch ($r1){
        'Y'{Invoke-HX_API -API Contain -action request -AgentID $target_ID
                Write-Host "Containment Requested. Run Again for Approval"
            }
        'N'{exit}
        }
    }
    if ($armed.data.queued -eq $true){
        do {
            $r2=Read-Host "Host ready for containment. Confirm Containment Approval? (Y)es, (N)o"
        }
        until ($r2 -in @('Y','N'))
        switch ($r2){
        'Y'{Invoke-HX_API -API Contain -action approve -AgentID $target_ID}
        'N'{exit}
        }
        do {
            Write-Host "Checking Containment Status"
            $confirm=hx -API Contain -action get -AgentID $target_ID
            if ($confirm.data.state -eq "containing"){
                Write-Host "Status=Containing. Will update in 5 seconds"
                Start-Sleep 5
            }
            Write-Host "Status=Normal. Will update in 5 seconds"
            Start-Sleep 5
        }
        until ($confirm.data.state -eq "contained")
        Write-Host "Status=Contained"
        $confirm.data
    }
}