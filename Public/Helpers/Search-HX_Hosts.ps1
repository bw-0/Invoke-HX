function Search-HX_Hosts {
    [CmdletBinding()]
    [Alias("HXS")]
    Param(
        $args,
        [switch]$proxy
    )

	if ($Proxy){
        (hx hosts search -query $args -Proxy).data.entries
    }

	else{
        (hx hosts search -query $args).data.entries
    }
}