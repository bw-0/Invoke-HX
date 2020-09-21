function Get-HX_Children_From_Hostset{
	(hx HostSet get-childitem -ID ((hx HostSet list -limit 999).data.entries|Out-GridView -PassThru)._id).data.entries
}
