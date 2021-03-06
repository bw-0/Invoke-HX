@{
	# Script module or binary module file associated with this manifest.
	RootModule = 'Invoke-HX.psm1'
	
	# Version number of this module.
	ModuleVersion = '1.0'
	
	# ID used to uniquely identify this module
	GUID = '6d8d667f-06d0-4d14-b0cc-a7fcd0690982'
	
	# Author of this module
	Author = 'Bryon Wolcott'
	
	# Description of the functionality provided by this module
	Description = 'This module contains functions that can be used to easily interact with the FireEye HX API'
	
	# Script files (.ps1) that are run in the caller's environment prior to importing this module.
	# ScriptsToProcess = @()
	
	# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
	FunctionsToExport = '*'
	
	# Variables to export from this module
	VariablesToExport = @('')
	
	# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
	AliasesToExport = '*'
	
	# HelpInfo URI of this module
	HelpInfoURI = 'https://github.com/bw-0/Invoke-HX'
}