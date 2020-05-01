function Search-HX_Hosts {
    [CmdletBinding()]
    [Alias("HXS")]
    Param($args)
        (hx hosts search -query $args -Proxy).data.entries
}