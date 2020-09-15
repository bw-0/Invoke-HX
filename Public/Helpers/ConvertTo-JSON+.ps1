Function ConvertTo-JSON_Pretty{
     [CmdletBinding()]
     [Alias("ConvertTo-JSON+","c2j")]
     Param
     (
         # FEED ME A POWERSHELL OBJECT
         [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    ValueFromPipeline=$true,
                    Position=0)]
         $input
     )
 
    #https://www.powershellgallery.com/packages/pspm/1.1.3/Content/functions%5CFormat-Json.ps1
    function Format-Json {
        param
        (
        [Parameter(Mandatory, ValueFromPipeline)]
        [String]
        $json
    ) 
    
        $indent = 0;
        $result = ($json -Split '\n' | ForEach-Object {
            
            if ($_ -match '[\}\]]') {
                # This line contains ] or }, decrement the indentation level
                $indent--
            }
            
            $line = (' ' * $indent * 2) + $_.TrimStart().Replace(': ', ': ')
            
            if ($_ -match '[\{\[]') {
                # This line contains [ or {, increment the indentation level
                $indent++
            }
            
            $line
        }) -Join "`n"
        
        # Unescape Html characters (<>&')
        $result.Replace('\u0027', "'").Replace('\u003c', "<").Replace('\u003e', ">").Replace('\u0026', "&")    
    }
    
    ($input |ConvertTo-Json -Depth 100|Format-Json) -replace "(?<!:)  ","`t"
}
