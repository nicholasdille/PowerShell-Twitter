﻿#requires -Version 4
#requires -Modules Helper

function Invoke-BitBucketApi {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('1.0', '2.0')]
        [string]
        $ApiVersion = '2.0'
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path
        ,
        [Parameter()]
        [ValidateSet('Delete', 'Get', 'Post', 'Put')]
        [string]
        $Method = 'Get'
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $Headers = @{}
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Accept = 'application/json'
    )

    if ($Headers.ContainsKey('Accept')) {
        $Headers.Accept = $Accept
    
    } else {
        $Headers.Add('Accept', $Accept)
    }

    $BitBucket = Get-BitBucketOnline

    if ($ApiVersion -eq '2.0') {
        $Values = @()
        $NextPageUri = "https://api.bitbucket.org/$ApiVersion$Path"
        while ($NextPageUri) {
            $Response = Invoke-AuthenticatedWebRequest -Uri $NextPageUri -Method $Method -User $BitBucket.User -Token $BitBucket.Token -Headers $Headers
            $Json = $Response.Content | ConvertFrom-Json
            $Values += $Json.values

            $NextPageUri = $Json.next
        }
        $Values

    } elseif ($ApiVersion -eq '1.0') {
        $Response = Invoke-AuthenticatedWebRequest -Uri "https://api.bitbucket.org/$ApiVersion$Path" -Method $Method -User $BitBucket.User -Token $BitBucket.Token -Headers $Headers
        $Json = $Response.Content | ConvertFrom-Json
        $Json
    }
}