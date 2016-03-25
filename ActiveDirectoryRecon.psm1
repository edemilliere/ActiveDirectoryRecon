Function Get-ADInfo {
    <#
    .SYNOPSIS
        This cmdlet retrieve a lot of AD infrastructure informations.
    .DESCRIPTION
        This cmdlet query ActiveDirectory to get the informations.
        "DomaineName;ForestName;PdcRoleOwner;RidRoleOwner;InfrastructureRoleOwner;Schema Master;Naming Master;Domain Functional Level;Forest Functional Level;Schema"
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
        $DomainObject = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('domain',$DomainName)
        $domain=[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainObject)
        
        #Forest info
        $ForestName = $domain.Forest
        $ForestObject = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $ForestName) 
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
        #'msDS-DeletedObjectLifetime'

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
                [xml]$TaskBarXml = Get-Content "\\$($domain.Name)\sysvol\$($domain.Name)\Policies\PolicyDefinitions\taskbar.admx" -ErrorAction Stop
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
        New-Object PSObject -Property @{
            DomainName                 = $domain.Name
            ForestName                 = $domain.Forest
            'PdcRoleOwner'             = $domain.PdcRoleOwner
            'RidRoleOwner'             = $domain.RidRoleOwner
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
            'IsRodcPrepared'           = $IsRodcPrepared
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
