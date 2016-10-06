Function Get-ADInfo {
    <#
    .SYNOPSIS
        This function retrieves a lot of AD infrastructure informations.
    .DESCRIPTION
        This function query ActiveDirectory to get informations like FFL, DFL, RecycleBin, Schema version, etc...
    .PARAMETER DomainName
        The domain name to query.
        Default : Current user Domain.
    .EXAMPLE
        PS C:\sources\temp> Get-ADInfo -DomainName corp.consoto.com

        RIDs Issued             : 5601
		ForestName              : D2K12R2.local
		TombStoneLifeTime       : 180
		RidRoleOwner            : DC1.D2K12R2.local
		CentralStoreEnabled     : True
		RecycleBin              : 08/04/2014 11:50:03
		RIDs left               : 2147478046
		PdcRoleOwner            : DC1.D2K12R2.local
		AdmxFileVersion         : 7
		Naming Master           : DC1.D2K12R2.local
		DeletedObjectLifeTime   :
		SysvolReplication       : DFSR
		Schema                  : Windows Server 10 Technical Preview 4
		IpOptions               : BridgeRequired
		Schema Master           : DC1.D2K12R2.local
		Exchange Schema         : Exchange 2013 SP1
		Forest Functional Level : Windows2012R2Forest
		InfrastructureRoleOwner : DC1.D2K12R2.local
		Domain Functional Level : Windows2012R2Domain
		DomainName              : D2K12R2.local
		Lync Schema             : Lync Server 2013
		IsRodcPrepared          : 07/25/2014 20:47:09

        Display domain and forest informations.

    .LINK
        https://ItForDummies.net
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$false,
            HelpMessage='Provide a domain name !')]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName=$env:USERDNSDOMAIN
    )
    Begin{
        #Domain Info
        $DomainObject = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList ('domain',$DomainName)
        $domain=[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainObject)
        
        #Forest info
        $ForestName = $domain.Forest
        $ForestObject = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList ('Forest', $ForestName) 
	    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestObject)

        $RootDSE = [ADSI]"LDAP://$DomainName/RootDSE"
    }
    Process{
        #Schema AD
        [String]$schema=([adsi]"LDAP://$($RootDSE.schemaNamingContext)").objectversion #-scope base -attr objectVersion
        
        switch ($schema)
        {
            '30' {$schema='Windows Server 2003 RTM, Windows Server 2003 with Service Pack 1, Windows Server 2003 with Service Pack 2'}
            '31' {$schema='Windows Server 2003 R2'}
            '44' {$schema='Windows Server 2008 RTM'}
            '47' {$schema='Windows Server 2008 R2'}
            '56' {$schema='Windows Server 2012 RTM'}
            '69' {$schema='Windows Server 2012 R2'}
            '72' {$schema='Windows Server 10 Technical Preview'}
            '81' {$schema='Windows Server 10 Technical Preview 2'}
            '82' {$schema='Windows Server 10 Technical Preview 3'}
            '85' {$schema='Windows Server 10 Technical Preview 4'}
            default {$schema="Unknown schema version : $schema."}
        }#End switch
        
        #Exchange Schema:
        try{
            [String]$schemaexchange=[adsi]"LDAP://CN=ms-Exch-Schema-Version-Pt,$($RootDSE.schemaNamingContext)" | Select-Object -ExpandProperty rangeupper -ErrorAction Stop
            switch ($schemaexchange)
            {
                '4397' {$schemaexchange='Exchange Server 2000 RTM'}
                '4406' {$schemaexchange='Exchange Server 2000 SP3'}
                '6870' {$schemaexchange='Exchange Server 2003 RTM'}
                '6936' {$schemaexchange='Exchange Server 2003 SP3'}
                '10628'{$schemaexchange='Exchange Server 2007 RTM'}
                '10637'{$schemaexchange='Exchange Server 2007 RTM'}
                '11116'{$schemaexchange='Exchange 2007 SP1'}
                '14622'{$schemaexchange='Exchange 2007 SP2 or Exchange 2010 RTM'}
                '14625'{$schemaexchange='Exchange 2007 SP3'}
                '14726'{$schemaexchange='Exchange 2010 SP1'}
                '14732'{$schemaexchange='Exchange 2010 SP2'}
                '14734'{$schemaexchange='Exchange 2010 SP3'}
                '15137'{$schemaexchange='Exchange 2013 RTM'}
                '15281'{$schemaexchange='Exchange 2013 CU2'}
                '15281'{$schemaexchange='Exchange 2013 CU3'}
                '15292'{$schemaexchange='Exchange 2013 SP1'}
                '15312'{$schemaexchange='Exchange 2013 CU7'}
				'15317'{$schemaexchange='Exchange 2016'}
                default {$schemaexchange="Exchange schema version unknown : $schemaexchange."}
            }#End switch
        }#End try
        catch{$schemaexchange='Uninstalled.'}
        
        #Lync Schema
        try{
            [String]$schemalync=[adsi]"LDAP://CN=ms-RTC-SIP-SchemaVersion,$($RootDSE.schemaNamingContext)" | Select-Object -ExpandProperty rangeupper -ErrorAction STOP
            switch ($schemalync)
            {
                '1006'{$schemalync='LCS 2005'}
                '1007'{$schemalync='OCS 2007 R1'}
                '1008'{$schemalync='OCS 2007 R2'}
                '1100'{$schemalync='Lync Server 2010'}
                '1150'{$schemalync='Lync Server 2013'}
                default {$schemalync="Lync schema version unknown : $schemalync."}
            }#End switch
        }#End Try
        catch{$schemalync='Uninstalled.'}
        
        #RID
        $searcher=[adsisearcher][adsi]"LDAP://CN=RID Manager$,CN=System,$($RootDSE.defaultNamingContext)"
        $property=($searcher.FindOne()).properties.ridavailablepool
        [int32]$totalSIDS = $($property) / ([math]::Pow(2,32))
        [int64]$temp64val = $totalSIDS * ([math]::Pow(2,32))
        [int32]$currentRIDPoolCount = $($property) - $temp64val
        $ridsremaining = $totalSIDS - $currentRIDPoolCount
        
        #DOL TSL
        $DS = [ADSI]“LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$($RootDSE.configurationNamingContext)”

        #RodcPrepared
        $RodcPrepared = [ADSI]"LDAP://CN=ActiveDirectoryRodcUpdate,CN=ForestUpdates,$($RootDSE.configurationNamingContext)"
        if($RodcPrepared.Name -eq 'ActiveDirectoryRodcUpdate'){
			$IsRodcPrepared = "$($RodcPrepared.properties.whencreated)"
		}
		else{$IsRodcPrepared=$false}
        
        #DeletedObjectLifeTime
        try{$DeletedObjectLifeTime = "$($DS.'msds-deletedobjectlifetime')"}
        catch{$DeletedObjectLifeTime = 'No RecycledBin'}

        #CentralPolicyStore
        if(Test-Path -Path "\\$($domain.Name)\sysvol\$($domain.Name)\Policies\PolicyDefinitions"){
            $CentralStoreEnabled = $true
        }
        else{
            $CentralStoreEnabled = $false
        }

        #Sysvol Replication
        try{
            [ADSI]"LDAP://CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$($RootDSE.defaultNamingContext)" | Select-Object -ExpandProperty AdsPath -ErrorAction Stop | Out-Null
            $SysvolReplication = 'DFSR'
        }
        catch{
            try{
                [ADSI]"LDAP://CN=Domain System Volume (SYSVOL share),CN=File Replication Service,CN=System,$($RootDSE.defaultNamingContext)" | Select-Object -ExpandProperty AdsPath -ErrorAction Stop | Out-Null
                $SysvolReplication = 'FRS'
            }catch{
                $SysvolReplication = 'Unknown'
            }
        }

        #RecycleBin
        try {
           if( ([ADSI]"LDAP://CN=Partitions,$($RootDSE.configurationNamingContext)").'msDS-EnabledFeature' -like "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($RootDSE.configurationNamingContext)"){
                $Searcher = [ADSISearcher]'cn=partitions'
				$Searcher.PropertiesToLoad.AddRange(('msDS-ReplValueMetaData')) | Out-Null
				$Searcher.searchroot.Path="LDAP://$($RootDSE.configurationNamingContext)"

				$RecycleBinEnabledDate = Get-Date -Date (([XML]$Searcher.FindOne().Properties.'msds-replvaluemetadata'.Replace('&','&amp;')).DS_REPL_VALUE_META_DATA | Where-Object -FilterScript {$_.pszObjectDn -like '*Recycle Bin Feature*'}).ftimeCreated

			    $RecycleBin = "$RecycleBinEnabledDate"
           }
           else{$RecycleBin = $false}
        }
        catch{$RecycleBin = $false}

        #AdmxFileVersion
        if($CentralStoreEnabled){
            try{
                [xml]$TaskBarXml = Get-Content -Path "\\$($domain.Name)\sysvol\$($domain.Name)\Policies\PolicyDefinitions\taskbar.admx" -ErrorAction Stop
                if(    $TaskBarXml.policyDefinitions.policies.policy.name | Where-Object {$_ -eq 'HideSCABattery'}           ){$XmlVersion = 'Vista'}
                elseif($TaskBarXml.policyDefinitions.policies.policy.name | Where-Object {$_ -eq 'DisableNotificationCenter'}){$XmlVersion = '10'}
                elseif($TaskBarXml.policyDefinitions.policies.policy.name | Where-Object {$_ -eq 'NoPinningStoreToTaskbar'}  ){$XmlVersion = '8.1'}
                elseif($TaskBarXml.policyDefinitions.policies.policy.name | Where-Object {$_ -eq 'TaskbarNoMultimon'}        ){$XmlVersion = '8'}
                elseif($TaskBarXml.policyDefinitions.policies.policy.name | Where-Object {$_ -eq 'NoPinningToDestinations'}  ){$XmlVersion = '7'}
                else{$XmlVersion = 'Unknown'}
            }
            catch{$XmlVersion = $null}
        }
        else{$XmlVersion = 'NoCentralStore'}

		#IP options 1= IgnoreSchedule 2=DisableAllSiteLinkBridge
		try{
			Switch(([ADSI]"LDAP://CN=IP,CN=Inter-Site Transports,CN=Sites,$($RootDSE.configurationNamingContext)").properties.options){
				1 {$IpOptions = 'IgnoreSchedule'}
				2 {$IpOptions = 'BridgeRequired'}
				3 {$IpOptions = 'IgnoreSchedule+BridgeRequired'}
				default {}
			}
		}
		catch{$IpOptions = 'Failed !'}

        #Object
        New-Object -TypeName PSObject -Property @{
            DomainName                 = $domain.Name
            ForestName                 = $domain.Forest
            PdcRoleOwner               = $domain.PdcRoleOwner
            RidRoleOwner               = $domain.RidRoleOwner
            'InfrastructureRoleOwner'  = $domain.InfrastructureRoleOwner
            'Schema Master'            = $Forest.SchemaRoleOwner
            'Naming Master'            = $Forest.NamingRoleOwner
            'Domain Functional Level'  = $Domain.DomainMode
            'Forest Functional Level'  = $Forest.ForestMode
            Schema                     = $schema
            'Exchange Schema'          = $schemaexchange
            'Lync Schema'              = $schemalync
            'RIDs Issued'              = $currentRIDPoolCount
            'RIDs left'                = $ridsremaining
            TombStoneLifeTime          = "$($DS.tombstonelifetime)"
            DeletedObjectLifeTime      = $DeletedObjectLifeTime
            IsRodcPrepared             = $IsRodcPrepared
            CentralStoreEnabled        = $CentralStoreEnabled
            SysvolReplication          = $SysvolReplication
            RecycleBin                 = $RecycleBin
            AdmxFileVersion            = $XmlVersion
			IpOptions                  = $IpOptions
        }#End Object
    }#End Process
    End{
    }
}
Function Get-ADSchemaAttribute{
    <#
    .SYNOPSIS
        Get schema attribute objects.
    .DESCRIPTION
        This function query the domain and retrieve all the distinguishedname, WhenChanged, WhenCreated of the attributes objects from the schema.
    .EXAMPLE
        Get-ADSchemaAttribute "D2K12R2.local"

        Remote Domain.
    .EXAMPLE
        Get-ADSchemaAttribute 

        Current domain.
    .PARAMETER DomainName
        Name of the domain to query. Defaulted to current domain.
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
		https://ItForDummies.net
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )

	Begin{}
	Process{
		$RootDSE = [ADSI]“LDAP://$DomainName/RootDSE”
		$SchemaSearcher = [ADSISearcher]'objectclass=attributeschema'
		$SchemaSearcher.SearchRoot.Path = "LDAP://$($RootDSE.schemaNamingContext)"
		$SchemaSearcher.PropertiesToLoad.AddRange(@('Name','whenChanged','WhenCreated','DistinguishedName'))
		$SchemaSearcher.PageSize = 10000
		$Attributes = $SchemaSearcher.FindAll()
		$Attributes | Foreach-Object -Process {
			New-Object -TypeName PSObject  -Property @{
				Name              = "$($_.properties.name)"
				DistinguishedName = "$($_.properties.distinguishedname)"
				whenChanged       = "$($_.properties.whenchanged)"
				WhenCreated       = "$($_.properties.whencreated)"
			}
		}
	}
	End{}
}
Function Get-ADObjectWithInheritanceDisabled{
    <#
    .SYNOPSIS
        Get Active directory object with inheritance disabled.
    .DESCRIPTION
        This function retrieves all the Active Directory in the default naming context object with inheritance disabled, except GPO's.
    .EXAMPLE
        Get-ADObjectWithInheritanceDisabled
    .PARAMETER DomainName
        Name of the domaine to query. 
		Defaulted to the current one.
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
        https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )

	Begin{}
	Process{
		$ADSISearcher = [ADSISearcher]'(&(!AdminCount=1)(!objectclass=groupPolicyContainer))'
		$ADSISearcher.PageSize  = 1000000
		$ADSISearcher.SearchRoot = [ADSI]"LDAP://$DomainName"
		$ADSISearcher.PropertiesToLoad.AddRange(@('Name'))
		$ADSISearcher.FindAll() | Foreach-Object -Process {
			$CurrentAdObject = $_.GetDirectoryEntry()

			if($CurrentAdObject.ObjectSecurity.AreAccessRulesProtected){ #Yes=No Heritence, #No=Heritence
				New-Object -TypeName PSObject -Property @{
					DistinguishedName = $($CurrentAdObject.distinguishedName)
					LastModified      = $($CurrentAdObject.whenchanged)
					ObjectClass       = $($CurrentAdObject.objectclass) -join ','
				}
			}
		}
	}
	End{}
}
Function Get-ADUnauditedAttributesInfo{
    <#
    .SYNOPSIS
        This function retrieves all the attributes that aren't audited.
    .DESCRIPTION
        Use "(searchFlags:1.2.840.113556.1.4.803:=256)" LDAP filter.
    .EXAMPLE
        Get-ADUnauditedAttributesInfo
    .LINK
        https://ItForDummies.net
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    Begin{
    }
    Process {
        try{
            $RootDSE = [ADSI]“LDAP://$DomainName/RootDSE”
            $DisabledAuditSearcher = [ADSISearcher]'(searchFlags:1.2.840.113556.1.4.803:=256)'
            $DisabledAuditSearcher.SearchRoot=[adsi]"LDAP://$($RootDSE.schemaNamingContext)"
            $DisabledAuditSearcher.PropertiesToLoad.AddRange(@('name','whencreated','whenchanged','DistinguishedName'))
            $DisabledAuditAttributes = $DisabledAuditSearcher.FindAll()
            $DisabledAuditAttributes | Foreach-Object -Process {
                New-Object -TypeName PSObject -Property @{
                    Name              = "$($_.properties.name)"
					DistinguishedName = "$($_.properties.distinguishedname)"
					whenChanged       = "$($_.properties.whenchanged)"
					WhenCreated       = "$($_.properties.whencreated)"
                }
            }
        }
        catch{Write-Warning -Message $_}
    }#End Process
    End{
    }
}
Function Get-ADSiteLinkInfo {
    <#
    .SYNOPSIS
        This function will retrieve informations about Active Directory sitelinks.
    .DESCRIPTION
        This function makes an ADSI query to the current AD domain and creates custom objects with some sitelink's properties :
        SiteLink,Cost, ReplicationInterval, Sites, NumberOfSites, Description.
    .PARAMETER DomainName
        Domain name to query.
    .EXAMPLE
        Get-ADSiteLinkInfo
    .EXAMPLE
        Get-ADSiteLinkInfo | Where-Object -FilterScript {$_.NumberOfSites -ne 2}

		Get SiteLink with more than two sites.
    .LINK
        https://ItForDummies.net
    #>
    [cmdletbinding()]
    Param(
		[Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    Begin{
    }
    Process {
        try{
            $SiteLinkSearcher = [ADSISearcher]'objectclass=sitelink'
            $RootDSE = [ADSI]“LDAP://$DomainName/RootDSE”
            $SiteLinkSearcher.Searchroot = [ADSI]"LDAP://$($RootDSE.configurationNamingContext)"
            $SiteLinks = $SiteLinkSearcher.FindAll()
            ForEach($SiteLink in $SiteLinks){
                try{
                    if($Sitelink.properties.options -eq 1){$ChangeNotification = $true}
                    elseif($Sitelink.properties.options -eq 5){$ChangeNotification = 'CompressionDisabled'}
                    else{$ChangeNotification = $false}
                }
                catch{
                    $ChangeNotification = "Failed  $($SiteLink.properties.name) -band 0X1."
                }

                New-Object -TypeName PSObject -Property @{
                    'SiteLink'            = $($SiteLink.properties.name)
                    'Cost'                = $($Sitelink.properties.cost)
                    'ReplicationInterval' = $($Sitelink.properties.replinterval)
                    'Sites'               = ($Sitelink.properties.sitelist | Foreach-Object -Process {(($_ -replace 'CN=',',') -split ',')[1]}) -join ','
                    'NumberOfSites'       = $Sitelink.properties.sitelist.count
                    'Description'         = $($Sitelink.properties.description)
                    'ChangeNotification'  = $ChangeNotification
                }
            }
        }
        catch{Write-Warning -Message $_}
    }#End Process
    End{
    }
}
Function Get-ADSubNetInfo {
    <#
    .SYNOPSIS
        This function will retrieves informations about Active Directory subnets.
    .DESCRIPTION
        This function makes an ADSI query to the current domain and create custom objects with subnet's informations in it.
    .PARAMETER DomainName
        Domain name to query.
    .EXAMPLE
        Get-ADSubNetInfo
    .LINK
        https://ItForDummies.net
    #>
    [cmdletbinding()]
    Param(
		[Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    Begin{
    }
    Process {
        try{
            $SubnetSeacher = [ADSISearcher]'objectclass=subnet'
            $RootDSE = [ADSI]“LDAP://$DomainName/RootDSE”
            $SubnetSeacher.SearchRoot = [ADSI]"LDAP://$($RootDSE.configurationNamingContext)"
            $Subnets = $SubnetSeacher.FindAll()
            ForEach($SubNet in $Subnets){
                New-Object -TypeName PSObject -Property @{
                    'Site'        = $Subnet.Properties.siteobject | Foreach-Object -Process {(($_ -replace 'CN=',',') -split ',')[1]}
                    'Subnet'      = $($Subnet.Properties.name)
                    'Description' = $($Subnet.Properties.description)
                    'location '   = $($Subnet.Properties.location)
                }
            }
        }
        catch{Write-Warning -Message $_}
    }#End Process
    End{
    }
}
Function Get-ADSiteInfo {
    <#
    .SYNOPSIS
        This retrieves informations about sites in Active Directory. 
    .DESCRIPTION
        This makes an ADSI query to the current domain and creates custom objects with some properties.
    .PARAMETER DomainName
        Domain name to query.
    .EXAMPLE
        Get-ADSiteInfo
    .EXAMPLE
        Get-ADSiteInfo | Where-Object -FilterScript {$_.Subnet -eq $null}

		Get site without subnet.
    .LINK
        https://ItForDummies.net
    #>
    [cmdletbinding()]
    Param(
		[Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    Begin{
    }
    Process {
        try{
            $SiteSearcher = [ADSISearcher]'objectclass=site'
            $RootDSE = [ADSI]"LDAP://$DomainName/RootDSE"
            $SiteSearcher.SearchRoot = [ADSI]"LDAP://$($RootDSE.configurationNamingContext)"
            $Sites = $SiteSearcher.FindAll()
            ForEach($Site in $Sites){
                #Ntds Site Settings
                $NtdsSiteSettingsDN = "CN=NTDS Site Settings,$($Site.Properties.distinguishedname)"
                $NtdsSiteSettings = [ADSI]"LDAP://$NtdsSiteSettingsDN"
				$DCSearcher = [ADSISearcher]'objectclass=server'
				$DCSearcher.SearchRoot = [ADSI]"LDAP://$($Site.Properties.distinguishedname)"
				$DCs = $DCSearcher.FindAll()

                New-Object -TypeName PSObject -Property @{
                    'Subnet'      = ($Site.Properties.siteobjectbl | Foreach-Object -Process {(($_ -replace 'CN=',',') -split ',')[1]}) -join ','
                    'Site'        = $($Site.Properties.name)
                    'Description' = "$($Site.Properties.description)"
                    'IsTG'        = ($NtdsSiteSettings.properties.interSiteTopologyGenerator -split ',CN=')[1]
                    'BHS'         = $NtdsSiteSettings.properties.bridgeheadServerListBL
					'DC'          = ($DCs | Foreach-Object -Process {"$($_.properties.cn)"}) -join ','
                }
            }
        }
        catch{Write-Warning -Message $_}
    }#End Process
    End{
    }
}
Function Get-ADTrustsInfo {
    <#
    .SYNOPSIS
        Query AD for all trusted domain objects in the specified domain and check their state.
    .DESCRIPTION
        This function query AD and return a custom object with informations suach as the trust name, the creation date, the last modification date, the direction, the type, the SID of the trusted domain, the trusts attributes, and the trust state.
    .PARAMETER DomainName
        Domain name to query.
        Default : Current user domain.
    .EXAMPLE
        Get-ADTrustsInfo -DomainName contoso.com
    .NOTES
        Require some permissions on source domain to see status.
    .LINK
        https://ItForDummies.net
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    Begin{
    }
    Process{
        $TrustSearcher = [ADSIsearcher]'(objectclass=trustedDomain)'
        $TrustSearcher.searchroot.Path="LDAP://$DomainName"
        $TrustSearcher.PropertiesToLoad.AddRange(('whenChanged','whenCreated','trustPartner','trustAttributes','trustDirection','trustType','securityIdentifier')) | Out-Null
        Write-Verbose -Message 'Searching in AD for trusts...'
        $Trusts = $TrustSearcher.FindAll()
        $Trusts | Foreach-Object -Process {
            try{
                switch ($_.Properties.trustdirection)
                {
                        1 {$TrustDirection='Inbound'}
                        2 {$TrustDirection='Outbound'}
                        3 {$TrustDirection='Bidirectional'}
                        default {$TrustDirection='N/A'}
                }

                switch ($_.Properties.trusttype)
                {
                    1 {$TrustType='Windows NT'} #Downlevel (2000 & lower)
                    2 {$TrustType='Active Directory'}#Uplevel (2003 & upper)
                    3 {$TrustType='Kerberos realm'}#Not AD Based
                    4 {$TrustType='DCE'}
                    default {$TrustType='N/A'}
                }
                #Convertion du System.Byte[] en SID lisible.
                Write-Verbose -Message 'Converting the SID...'
                try{
					$SID = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $_.properties.securityidentifier[0], 0).value
					Write-Verbose -Message 'Querying WMI...'
                    $WmiTrustStatuts = Get-WmiObject -namespace 'root/MicrosoftActiveDirectory' -class Microsoft_DomainTrustStatus -ComputerName $DomainName -Filter "SID='$SID'" -ErrorAction Stop | Select-Object -ExpandProperty TrustStatusString -ErrorAction Stop
                }
                catch{
                    Write-Warning -Message 'Failed getting trust health.'
                    $WmiTrustStatuts = 'Failed getting trust health.'
                }
                
                [String[]]$TrustAttributes=$null
                if([int32]$_.properties.trustattributes[0] -band 0x00000001){$TrustAttributes+='Non Transitive'}
                if([int32]$_.properties.trustattributes[0] -band 0x00000002){$TrustAttributes+='UpLevel'}
                if([int32]$_.properties.trustattributes[0] -band 0x00000004){$TrustAttributes+='Quarantine'} #SID Filtering
                if([int32]$_.properties.trustattributes[0] -band 0x00000008){$TrustAttributes+='Forest Transitive'}
                if([int32]$_.properties.trustattributes[0] -band 0x00000010){$TrustAttributes+='Cross Organization'}#Selective Auth
                if([int32]$_.properties.trustattributes[0] -band 0x00000020){$TrustAttributes+='Within Forest'}
                if([int32]$_.properties.trustattributes[0] -band 0x00000040){$TrustAttributes+='Treat as External'}
                if([int32]$_.properties.trustattributes[0] -band 0x00000080){$TrustAttributes+='Uses RC4 Encryption'}
                #http://msdn.microsoft.com/en-us/library/cc223779.aspx
                
                Write-Verbose -Message 'Constructing object...'
                $Object = New-Object -TypeName PSObject -Property @{
                    'Trust Name'          = $($_.Properties.trustpartner)
                    'Created on'          = $($_.Properties.whencreated)
                    'Last Changed'        = $($_.Properties.whenchanged)
                    'Direction'           = $TrustDirection
                    'Type'                = $TrustType
                    'Domain SID'          = $SID
                    'Status'              = $WmiTrustStatuts
                    'Attributes'          = $TrustAttributes -join ','
                }#End object
                Write-Output -InputObject $Object
            }
            catch{Write-Warning -Message "$_"}
        }#End trusts
    }#End process
    End{
    }
} 
Function Get-ADWellKnownGroupMember{
    <#
    .SYNOPSIS
        Get all the priviledge groups, and their members.
    .DESCRIPTION
        This function get all the groups with the admincount attribute equal to one, and display the members.
    .EXAMPLE
        Get-ADWellKnownGroupMember
    .PARAMETER DomainName
        Name of the domain to query.
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
        https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='HelpMessage',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )

    Begin{
    }
    Process{
        $WellKnowGroupSearcher = [ADSISearcher]'(&(AdminCount=1)(objectclass=group))'
		$WellKnowGroupSearcher.searchroot = [ADSI]"LDAP://$DomainName"
        $WellKnowGroupSearcher.PropertiesToLoad.AddRange(('Name','member','memberof'))
        $WellKnowGroupSearcher.FindAll() | Select-Object -Property @{Label='Name';Expression={$_.properties.name}},
            @{Label='Member';Expression={@($_.properties.member).count}},
            @{Label='Members';Expression={[String]::Join(',',($_.properties.member | Foreach-Object -Process { $_.split(',')[0] -replace 'CN=',''}))}},
            @{Label='MemberOf';Expression={[String]::Join(',',($_.properties.memberof | Foreach-Object -Process { $_.split(',')[0] -replace 'CN=',''}))}}
    }
    End{
    }
}
Function Get-ADManuallyCreatednTDSConnectionObject{
    <#
    .SYNOPSIS
        Get the nTDSConnection that were created manually.
    .DESCRIPTION
        Thise function uses this LDAP filter : "(&(objectClass=nTDSConnection)(!options:1.2.840.113556.1.4.804:=1))"
    .EXAMPLE
        Get-ADManuallyCreatednTDSConnectionObject "D2K12R2.local"

        Remote Domain.
    .EXAMPLE
        Get-ADManuallyCreatednTDSConnectionObject 

        Current domain.
    .PARAMETER DomainName
        Name of the domain to query. Defaulted to current domain.
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
        https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )

	Begin{}
	Process{
		$RootDSE = [ADSI]“LDAP://$DomainName/RootDSE”
		$SchemaSearcher = [ADSISearcher]'(&(objectClass=nTDSConnection)(!options:1.2.840.113556.1.4.804:=1))'
		$SchemaSearcher.SearchRoot.Path = "LDAP://$($RootDSE.configurationNamingContext)"
		$SchemaSearcher.PropertiesToLoad.AddRange(@('Name','WhenChanged','whencreated','distinguishedname'))
		$SchemaSearcher.PageSize=10000
		$Attributes = $SchemaSearcher.FindAll()
		$Attributes | Foreach-Object -Process {
			New-Object -TypeName PSObject -Property @{
				DistinguishedName = $($_.properties.distinguishedname)
				WhenChanged       = $($_.Properties.whenchanged)
				WhenCreated       = $($_.Properties.whencreated)
			}
		}
	}
	End{}
}
Function Get-ADName{
    <#
    .SYNOPSIS
        Get domain names.
    .DESCRIPTION
        Get DomainName, NetBios, FQDN and DN of the domain, also get the forest name.
    .EXAMPLE
        Get-ADName -DomainName corp.contoso.com

        Get the names of the corp.contoso.com domain.
    .EXAMPLE
        Get-ADName

        Get the names of the current domain.
    .PARAMETER DomainName
        Name of the domain.

    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
        https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage='Name of the domain.',
			Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )

    Begin{}
    Process{
        $DomainContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList ('domain',$DomainName)
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)

		#RootDSE
		$RootDSE = [ADSI]"LDAP://$DomainName/RootDSE"

        #NetBios
        $NetBiosSearcher = [ADSISearcher]'(&(objectcategory=crossref)(netbiosname=*))'
        $NetBiosSearcher.SearchRoot = [ADSI]"LDAP://CN=Partitions,$($RootDSE.configurationNamingContext)"

        New-Object -TypeName PSObject -Property @{
            DomainName = [ADSI]"LDAP://$($RootDSE.defaultNamingContext)" | Select-Object -ExpandProperty name
            NetBios = "$(($NetBiosSearcher.FindAll().properties | Where-Object -FilterScript {$_.dnsroot -eq $Domain.Name}).netbiosname)"
            FQDN = $Domain.Name
            ForestName = $Domain.Forest
            DN = "$($RootDSE.defaultNamingContext)"
            schemaNamingContext = "$($RootDSE.schemaNamingContext)"
            configurationNamingContext = "$($RootDSE.configurationNamingContext)"
            rootDomainNamingContext = "$($RootDSE.rootDomainNamingContext)"
			SID = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList (([ADSI]"LDAP://$DomainName").objectSid)[0], 0).value
        }
    }
    End{}
}
Function Get-ADAuthorizedDHCP{
    <#
    .SYNOPSIS
        Get authorized DHCP server from AD.
    .DESCRIPTION
    .EXAMPLE
        Get-ADAuthorizedDHCP -DomainName Contoso.com
    .PARAMETER DomainName
        Name of a remote domain.
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
        https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String[]]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )

    Begin{}
    Process{
        ForEach($Domain in $DomainName){
            $DhcpSearcher= [ADSISearcher]'objectclass=dHCPClass'
            $DhcpSearcher.SearchRoot = "LDAP://CN=NetServices,CN=Services,$(([ADSI]"LDAP://$Domain/RootDSE").configurationNamingContext)"
            $DhcpSearcher.PropertiesToLoad.AddRange(('dhcpFlags','dhcpServers','cn','whenCreated','whenChanged'))
            $DhcpSearcher.FindAll() | Foreach-Object -Process {
                New-Object -TypeName PSObject -Property @{
                    dhcpFlags                 = $($_.properties.dhcpflags)
                    dhcpServers               = $($_.properties.dhcpservers)
                    whenCreated               = $($_.properties.whencreated)
                    whenChanged               = $($_.properties.whenchanged)
                    cn                        = $($_.properties.cn)
                }
            }
        }
    }
    End{}
}
Function Get-ADGCAttributesInfo {
    <#
    .SYNOPSIS
        This function retrieves all the attributes in the schema container replicated to Global Catalog.
    .DESCRIPTION
        Use "(&(objectCategory=attributeSchema)(isMemberOfPartialAttributeSet=TRUE))" LDAP filter.
    .PARAMETER DomainName
        Domain name to query.
    .EXAMPLE
        Get-ADGCAttributesInfo
    .LINK
        https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    Begin{}
    Process {
        try {
            $RootDSE = [ADSI]“LDAP://$DomainName/RootDSE”
            $GCAttSearcher=[ADSISearcher]'(&(objectCategory=attributeSchema)(isMemberOfPartialAttributeSet=TRUE))'
            $GCAttSearcher.SearchRoot = [ADSI]"LDAP://$($RootDSE.schemaNamingContext)"
            $GCAttSearcher.PropertiesToLoad.AddRange(('Name','whenChanged','whenCreated','DistinguishedName'))
            $GCAttSearcher.FindAll() | Foreach-Object -Process {
                New-Object -TypeName PSObject  -Property @{
                    Name              = $($_.properties.name)
                    DistinguishedName = $($_.properties.distinguishedname)
                    whenChanged       = $($_.properties.whenchanged)
                    WhenCreated       = $($_.properties.whencreated)
                }
            }
        }
        catch{Write-Warning -Message $_}
    }#End Process
    End{}
}
Function Get-ADUnreplicatedAttributesInfo{
    <#
    .SYNOPSIS
        This function retrieves all the attributes in the schema container unreplicated to other domain controllers.
    .DESCRIPTION
        Use "(&(objectCategory=attributeSchema)(systemFlags:1.2.840.113556.1.4.803:=1))" LDAP filter.
    .PARAMETER DomainName
        Domain name to query.
    .EXAMPLE
        Get-ADUnreplicatedAttributesInfo
    .LINK
        https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    Begin{}
    Process {
        try {
            $RootDSE = [ADSI]“LDAP://$DomainName/RootDSE”
            $UnReplSearcher = [ADSISearcher]'(&(objectCategory=attributeSchema)(systemFlags:1.2.840.113556.1.4.803:=1))'
            $UnReplSearcher.SearchRoot=[ADSI]"LDAP://$($RootDSE.schemaNamingContext)"
            $UnReplSearcher.PropertiesToLoad.AddRange(('Name','whenChanged','whenCreated','DistinguishedName'))
            $UnReplSearcher.FindAll() | Foreach-Object -Process {
                New-Object -TypeName PSObject  -Property @{
                    Name              = $($_.properties.name)
                    DistinguishedName = $($_.properties.distinguishedname)
                    whenChanged       = $($_.properties.whenchanged)
                    WhenCreated       = $($_.properties.whencreated)
                }
            }
        }
        catch{Write-Warning -Message $_}
    }#End Process
    End{}
}
Function Get-ADTombStoneAttributesInfo{
    <#
    .SYNOPSIS
        This advanced function retrieves all the attributes preserved when an object is delete.
    .DESCRIPTION
        Use "(searchFlags:1.2.840.113556.1.4.803:=8)" LDAP filter.
    .PARAMETER DomainName
        Domain name to query.
    .EXAMPLE
        Get-ADTombStoneAttributesInfo
    .LINK
        https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    Begin{}
    Process {
        try {
            $RootDSE = [ADSI]“LDAP://$DomainName/RootDSE”
            $TombStoneAttSearcher = [ADSISearcher]'(searchFlags:1.2.840.113556.1.4.803:=8)'
            $TombStoneAttSearcher.SearchRoot=[ADSI]"LDAP://$($RootDSE.schemaNamingContext)"
            $TombStoneAttSearcher.PropertiesToLoad.AddRange(('Name','whenChanged','whenCreated','DistinguishedName'))
            $TombStoneAttSearcher.FindAll() | Foreach-Object -Process {
                New-Object -TypeName PSObject  -Property @{
                    Name              = $($_.properties.name)
                    DistinguishedName = $($_.properties.distinguishedname)
                    whenChanged       = $($_.properties.whenchanged)
                    WhenCreated       = $($_.properties.whencreated)
                }
            }
        }
        catch{Write-Warning -Message $_}
    }#End Process
    End{}
}
Function Get-ADIndexedAttributesInfo{
    <#
    .SYNOPSIS
        This function retrieves all the schema indexed attributes.
    .DESCRIPTION
        Use "(searchFlags:1.2.840.113556.1.4.803:=1)" LDAP filter.
    .PARAMETER DomainName
        Domain name to query.
    .EXAMPLE
        Get-ADIndexedAttributesInfo
    .LINK
		https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    Begin{}
    Process {
        try{
            $RootDSE = [ADSI]“LDAP://$DomainName/RootDSE”
            $InexedAttSearcher=[ADSISearcher]'(searchFlags:1.2.840.113556.1.4.803:=1)'
            $InexedAttSearcher.SearchRoot = [ADSI]"LDAP://$($RootDSE.schemaNamingContext)"
            $InexedAttSearcher.PropertiesToLoad.AddRange(('Name','whenChanged','whenCreated','DistinguishedName'))
            $InexedAttSearcher.FindAll() | Foreach-Object -Process {
                New-Object -TypeName PSObject  -Property @{
                    Name              = $($_.properties.name)
                    DistinguishedName = $($_.properties.distinguishedname)
                    whenChanged       = $($_.properties.whenchanged)
                    WhenCreated       = $($_.properties.whencreated)
                }
            }
        }
        catch{Write-Warning -Message $_}
    }#End Process
    End{}
}
Function Get-ADFilterAttributeSetInfo {
    <#
    .SYNOPSIS
        This function retrieves all the attributes unreplicated to RODC (Filter Attribute Set).
    .DESCRIPTION
        Use "(searchFlags:1.2.840.113556.1.4.803:=512)" LDAP filter.
    .PARAMETER DomainName
        Domain name to query.
    .EXAMPLE
        Get-ADFilterAttributeSetInfo
    .LINK
		https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    Begin{}
    Process {
        try{
            $RootDSE = [ADSI]“LDAP://$DomainName/RootDSE”
            $RODCFASSearcher=[ADSISearcher]'(searchFlags:1.2.840.113556.1.4.803:=512)'
            $RODCFASSearcher.SearchRoot = [ADSI]"LDAP://$($RootDSE.schemaNamingContext)"
            $RODCFASSearcher.PropertiesToLoad.AddRange(('Name','whenChanged','whenCreated','DistinguishedName'))
            $RODCFASSearcher.FindAll() | Foreach-Object -Process {
                New-Object -TypeName PSObject  -Property @{
                    Name              = $($_.properties.name)
                    DistinguishedName = $($_.properties.distinguishedname)
                    whenChanged       = $($_.properties.whenchanged)
                    WhenCreated       = $($_.properties.whencreated)
                }
            }
        }
        catch{Write-Warning -Message $_}
    }#End Process
    End{}
}
Function Get-ADAdminLastLogon {
    <#
    .Synopsis
        Get Active Directory Admins informations.
    .DESCRIPTION
        Uses AdminCount attribute to search for administrators.
    .EXAMPLE
       Get-ADAdminLastLogon
    .PARAMETER DomainName
        The domain name to query.
	.Link
		https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )
    
    $AdminSearcher=[ADSISearcher]'(&(objectclass=User)(objectcategory=person)(AdminCount=1))'
    $AdminSearcher.PropertiesToLoad.AddRange(('lastLogonTimestamp','cn','pwdLastSet','memberof','useraccountcontrol')) | Out-Null
    $AdminSearcher.searchroot.Path="LDAP://$DomainName"
    $AdminSearcher.FindAll() | Foreach-Object -Process {
        New-Object -TypeName PSObject -Property @{
            Name       = $($_.properties.cn)
            PwdLastSet = [DateTime]::FromFileTime([String]$_.properties.pwdlastset)
            LastLogon  = [DateTime]::FromFileTime([String]$_.properties.lastlogontimestamp)
            MemberOf   = ($_.properties.memberof | Foreach-Object -Process { (($_ -split ',')[0] -split '=')[-1]}) -join ','
            Status     = if($_.properties.useraccountcontrol[0] -band 0x2){'Disabled'}else{'Enabled'}
        }
    }
}
Function Get-ADNamingContextLastBackupDate{
    <#
    .SYNOPSIS
        Get the last backup date from the different naming contexts.
    .DESCRIPTION
        If you can query a remote domain, you need to specify his name.
    .EXAMPLE
        Get-ADNamingContextLastBackupDate
    .EXAMPLE
        Get-ADNamingContextLastBackupDate -DomainName D2K3R2.local

        Remote domain.
    .PARAMETER DomainName
        Name of the domain.
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
		https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of remote domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

    )

    Begin{}
    Process{
		$DNs = ([ADSI]"LDAP://$DomainName/RootDSE").namingContexts
        $DomainContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList ('domain',$DomainName)
        $DC = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext).FindDomainController()

        ForEach($DistinguishedName in $DNs){
            $DC.GetReplicationMetadata("$DistinguishedName").GetEnumerator() |
                Foreach-Object -Process {$_.Value} |
                Select-Object -Property Name, Version, LastOriginatingChangeTime, OriginatingServer,@{Label='Object';Expression={$DistinguishedName}} |
                Where-Object -FilterScript {$_.Name -eq 'dSASignature'}
        }
    }
    End{}
}
Function Get-ADPSO{
    <#
    .SYNOPSIS
        Get the Password Setting Objects from Active Directory.
    .DESCRIPTION
        If you want to query a remote domain, you need to specify his name.
    .EXAMPLE
        Get-ADPSO
    .EXAMPLE
        Get-ADPSO -DomainName D2K3R2.local

        Remote domain.
    .PARAMETER DomainName
        Name of the domain.
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
		https://ItForDummies.net
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='Name of the domain.',
            Position=0)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    )

    Begin{}
    Process{
        $PSOSearcher = [ADSISearcher]'objectclass=msDS-PasswordSettings'
        $PSOSearcher.PropertiesToLoad.AddRange(('msDS-LockoutDuration','msDS-LockoutObservationWindow','msDS-LockoutThreshold','msDS-MaximumPasswordAge','msDS-MinimumPasswordAge','msDS-MinimumPasswordLength','msDS-PasswordComplexityEnabled','msDS-PasswordHistoryLength','msDS-PasswordReversibleEncryptionEnabled','msDS-PasswordSettingsPrecedence','msDS-PSOAppliesTo','name'))
        $PSOSearcher.SearchRoot = [ADSI]"LDAP://$DomainName"
        $PSOSearcher.FindAll() | Foreach-Object -Process {
            New-Object -TypeName PSObject -Property @{
                Name                                       = $($_.properties.name)
                'msDS-LockoutDuration'                     = $($_.Properties.'msds-lockoutduration')
                'msDS-LockoutObservationWindow'            = $($_.Properties.'msds-lockoutobservationwindow')
                'msDS-LockoutThreshold'                    = $($_.Properties.'msds-lockoutthreshold')
                'msDS-MaximumPasswordAge'                  = $($_.Properties.'msds-maximumpasswordage')
                'msDS-MinimumPasswordAge'                  = $($_.Properties.'msds-minimumpasswordage')
                'msDS-MinimumPasswordLength'               = $($_.Properties.'msds-minimumpasswordlength')
                'msDS-PasswordComplexityEnabled'           = $($_.Properties.'msds-passwordcomplexityenabled')
                'msDS-PasswordHistoryLength'               = $($_.Properties.'msds-passwordhistorylength')
                'msDS-PasswordReversibleEncryptionEnabled' = $($_.Properties.'msds-passwordreversibleencryptionenabled')
                'msDS-PasswordSettingsPrecedence'          = $($_.Properties.'msds-passwordsettingsprecedence')
                'msDS-PSOAppliesTo'                        = $($_.Properties.'msds-psoappliesto')
            }
        }
    }
    End{}
}
