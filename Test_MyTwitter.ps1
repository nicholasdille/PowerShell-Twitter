Function Get-OAuthAuthorization {
	[CmdletBinding(DefaultParameterSetName = 'None')]
	[OutputType('System.Management.Automation.PSCustomObject')]
	param (
		[Parameter(Mandatory)]
		[ValidateSet('Timeline', 'DirectMessage', 'Update')]
		[string]
        $Api
        ,
		[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
		[string]
        $HttpEndPoint
        ,
		[Parameter(Mandatory)]
		[ValidateSet('Post', 'Get')]
		[string]
        $HttpVerb
        ,
		[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
		[hashtable]
        $ApiParameters
	)
	
	Begin {
		$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
		Set-StrictMode -Version Latest
		try {
			[Reflection.Assembly]::LoadWithPartialName('System.Security') | Out-Null
			[Reflection.Assembly]::LoadWithPartialName('System.Net') | Out-Null
			
			if (!(Get-MyTwitterConfiguration)) {
				throw 'No MyTwitter configuration detected.  Please run New-MyTwitterConfiguration'
			} else {
				$script:MyTwitterConfiguration = Get-MyTwitterConfiguration
			}
		} catch {
			Write-Error $_.Exception.Message
		}
	}
	
	Process {
		try {
			## Generate a random 32-byte string. I'm using the current time (in seconds) and appending 5 chars to the end to get to 32 bytes
			## Base64 allows for an '=' but Twitter does not.  If this is found, replace it with some alphanumeric character
			$OauthNonce = [System.Convert]::ToBase64String(([System.Text.Encoding]::ASCII.GetBytes("$([System.DateTime]::Now.Ticks.ToString())12345"))).Replace('=', 'g')
			Write-Verbose "Generated Oauth none string '$OauthNonce'"
			
			## Find the total seconds since 1/1/1970 (epoch time)
			$EpochTimeNow = [System.DateTime]::UtcNow - [System.DateTime]::ParseExact('01/01/1970', 'dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
			Write-Verbose "Generated epoch time '$EpochTimeNow'"
			$OauthTimestamp = [System.Convert]::ToInt64($EpochTimeNow.TotalSeconds).ToString();
			Write-Verbose "Generated Oauth timestamp '$OauthTimestamp'"
			
			## Build the signature
			$SignatureBase = "$([System.Uri]::EscapeDataString($HttpEndPoint))&"
			$SignatureParams = @{
				'oauth_consumer_key' = $MyTwitterConfiguration.ApiKey;
				'oauth_nonce' = $OauthNonce;
				'oauth_signature_method' = 'HMAC-SHA1';
				'oauth_timestamp' = $OauthTimestamp;
				'oauth_token' = $MyTwitterConfiguration.AccessToken;
				'oauth_version' = '1.0';
			}
			
			$AuthorizationParams = $SignatureParams.Clone()
			
			## Add API-specific params to the signature
			foreach ($Param in $ApiParameters.GetEnumerator()) {
				$SignatureParams[$Param.Key] = $Param.Value
			}
			
			## Create a string called $SignatureBase that joins all URL encoded 'Key=Value' elements with a &
			## Remove the URL encoded & at the end and prepend the necessary 'POST&' verb to the front
			$SignatureParams.GetEnumerator() | Sort-Object Name | foreach { $SignatureBase += [System.Uri]::EscapeDataString("$($_.Key)=$($_.Value)&") }
			$SignatureBase = $SignatureBase.TrimEnd('%26')
			$SignatureBase = "$HttpVerb&" + $SignatureBase
			Write-Verbose "Base signature generated '$SignatureBase'"
			
			## Create the hashed string from the base signature
			$SignatureKey = [System.Uri]::EscapeDataString($MyTwitterConfiguration.ApiSecret) + '&' + [System.Uri]::EscapeDataString($MyTwitterConfiguration.AccessTokenSecret);
			
			$hmacsha1 = New-Object System.Security.Cryptography.HMACSHA1;
			$hmacsha1.Key = [System.Text.Encoding]::ASCII.GetBytes($SignatureKey);
			$OauthSignature = [System.Convert]::ToBase64String($hmacsha1.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($SignatureBase)));
			Write-Verbose "Using signature '$OauthSignature'"
			
			## Build the authorization headers. This is joining all of the 'Key=Value' elements again
			## and only URL encoding the Values this time while including non-URL encoded double quotes around each value
			$AuthorizationParams.Add('oauth_signature', $OauthSignature)	
			$AuthorizationString = 'OAuth '
			$AuthorizationParams.GetEnumerator() | Sort-Object name | foreach { $AuthorizationString += $_.Key + '="' + [System.Uri]::EscapeDataString($_.Value) + '", ' }
			$AuthorizationString = $AuthorizationString.TrimEnd(', ')
			Write-Verbose "Using authorization string '$AuthorizationString'"
			
			$AuthorizationString
			
		} catch {
			Write-Error $_.Exception.Message
		}
	}
}

function Get-OAuthAuthorization {
    <#
	.SYNOPSIS
		This function is used to create the signature and authorization headers needed to pass to OAuth
		It has been tested with v1.1 of the API.
	.EXAMPLE
		Get-OAuthAuthorization -Api 'Update' -ApiParameters @{'status' = 'hello' } -HttpVerb GET -HttpEndPoint 'https://api.twitter.com/1.1/statuses/update.json'
	
		This example gets the authorization string needed in the HTTP GET method to send send a tweet 'hello'
	.PARAMETER Api
		The Twitter API name.  Currently, you can only use Timeline, DirectMessage or Update.
	.PARAMETER HttpEndPoint
		This is the URI that you must use to issue calls to the API.
	.PARAMETER HttpVerb
		The HTTP verb (either GET or POST) that the specific API uses.
	.PARAMETER ApiParameters
		A hashtable of parameters the specific Twitter API you're building the authorization
		string for needs to include in the signature
		
	#>
	[CmdletBinding(DefaultParameterSetName = 'None')]
	[OutputType('System.Management.Automation.PSCustomObject')]
	param (
		[Parameter(Mandatory)]
		[ValidateSet('Timeline','DirectMessage','Update')]
		[string]$Api,
		[Parameter(Mandatory)]
		[string]$HttpEndPoint,
		[Parameter(Mandatory)]
		[ValidateSet('POST', 'GET')]
		[string]$HttpVerb,
		[Parameter(Mandatory)]
		[hashtable]$ApiParameters
	)
	
	begin {
		$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
		Set-StrictMode -Version Latest
		try {
			[Reflection.Assembly]::LoadWithPartialName('System.Security') | Out-Null
			[Reflection.Assembly]::LoadWithPartialName('System.Net') | Out-Null
			
			if (!(Get-MyTwitterConfiguration)) {
				throw 'No MyTwitter configuration detected.  Please run New-MyTwitterConfiguration'
			} else {
				$script:MyTwitterConfiguration = Get-MyTwitterConfiguration
			}
		} catch {
			Write-Error $_.Exception.Message
		}
	}
	
	process {
		try {
			## Generate a random 32-byte string. I'm using the current time (in seconds) and appending 5 chars to the end to get to 32 bytes
			## Base64 allows for an '=' but Twitter does not.  If this is found, replace it with some alphanumeric character
			$OauthNonce = [System.Convert]::ToBase64String(([System.Text.Encoding]::ASCII.GetBytes("$([System.DateTime]::Now.Ticks.ToString())12345"))).Replace('=', 'g')
			Write-Verbose "Generated Oauth none string '$OauthNonce'"
			
			## Find the total seconds since 1/1/1970 (epoch time)
			$EpochTimeNow = [System.DateTime]::UtcNow - [System.DateTime]::ParseExact('01/01/1970', 'dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
			Write-Verbose "Generated epoch time '$EpochTimeNow'"
			$OauthTimestamp = [System.Convert]::ToInt64($EpochTimeNow.TotalSeconds).ToString();
			Write-Verbose "Generated Oauth timestamp '$OauthTimestamp'"
			
			## Build the signature
			$SignatureBase = "$([System.Uri]::EscapeDataString($HttpEndPoint))&"
			$SignatureParams = @{
				'oauth_consumer_key' = $MyTwitterConfiguration.ApiKey;
				'oauth_nonce' = $OauthNonce;
				'oauth_signature_method' = 'HMAC-SHA1';
				'oauth_timestamp' = $OauthTimestamp;
				'oauth_token' = $MyTwitterConfiguration.AccessToken;
				'oauth_version' = '1.0';
			}
			
			$AuthorizationParams = $SignatureParams.Clone()
			
			## Add API-specific params to the signature
			foreach ($Param in $ApiParameters.GetEnumerator()) {
				$SignatureParams[$Param.Key] = $Param.Value
			}
			
			## Create a string called $SignatureBase that joins all URL encoded 'Key=Value' elements with a &
			## Remove the URL encoded & at the end and prepend the necessary 'POST&' verb to the front
			$SignatureParams.GetEnumerator() | Sort-Object Name | foreach { $SignatureBase += [System.Uri]::EscapeDataString("$($_.Key)=$($_.Value)&") }
			$SignatureBase = $SignatureBase.TrimEnd('%26')
			$SignatureBase = "$HttpVerb&" + $SignatureBase
			Write-Verbose "Base signature generated '$SignatureBase'"
			
			## Create the hashed string from the base signature
			$SignatureKey = [System.Uri]::EscapeDataString($MyTwitterConfiguration.ApiSecret) + '&' + [System.Uri]::EscapeDataString($MyTwitterConfiguration.AccessTokenSecret);
			
			$hmacsha1 = new-object System.Security.Cryptography.HMACSHA1;
			$hmacsha1.Key = [System.Text.Encoding]::ASCII.GetBytes($SignatureKey);
			$OauthSignature = [System.Convert]::ToBase64String($hmacsha1.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($SignatureBase)));
			Write-Verbose "Using signature '$OauthSignature'"
			
			## Build the authorization headers.  This is joining all of the 'Key=Value' elements again
			## and only URL encoding the Values this time while including non-URL encoded double quotes around each value
			$AuthorizationParams.Add('oauth_signature', $OauthSignature)	
			$AuthorizationString = 'OAuth '
			$AuthorizationParams.GetEnumerator() | Sort-Object name | foreach { $AuthorizationString += $_.Key + '="' + [System.Uri]::EscapeDataString($_.Value) + '", ' }
			$AuthorizationString = $AuthorizationString.TrimEnd(', ')
			Write-Verbose "Using authorization string '$AuthorizationString'"
			
			$AuthorizationString
			
		} catch {
			Write-Error $_.Exception.Message
		}
	}
}

Function New-MyTwitterConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage='What is the Twitter Client API Key?')]
        [ValidateNotNullOrEmpty()]
        [string]
        $APIKey
        ,
        [Parameter(Mandatory, HelpMessage='What is the Twitter Client API Secret?')]
        [ValidateNotNullOrEmpty()]
        [string]
        $APISecret
        ,
        [Parameter(Mandatory, HelpMessage='What is the Twitter Client Access Token?')]
        [ValidateNotNullOrEmpty()]
        [string]
        $AccessToken
        ,
        [Parameter(Mandatory, HelpMessage='What is the Twitter Client Access Token Secret?')]
        [ValidateNotNullOrEmpty()]
		[string]
        $AccessTokenSecret
        ,
		[switch]
        $Force
    )

	Begin {
		$RegKey = 'HKCU:\Software\MyTwitter'
	}

	Process {
		#API key, the API secret, an Access token and an Access token secret are provided by Twitter application
		Write-Verbose 'Checking registry to see if the Twitter application keys are already stored'
		if (!(Test-Path -Path $RegKey)) {
			Write-Verbose 'No MyTwitter configuration found in registry. Creating one.'
			New-Item -Path ($RegKey | Split-Path -Parent) -Name ($RegKey | Split-Path -Leaf) | Out-Null
		}
		
		$Values = 'APIKey', 'APISecret', 'AccessToken', 'AccessTokenSecret'
		foreach ($Value in $Values) {
			if ((Get-Item -Path $RegKey).GetValue($Value) -and !$Force.IsPresent) {
				Write-Verbose "'$RegKey\$Value' already exists. Skipping."

			} else {
				Write-Verbose "Creating $RegKey\$Value"
				New-ItemProperty -Path $RegKey -Name $Value -Value ((Get-Variable $Value).Value) -Force | Out-Null
			}
		}
	}
}

Function Get-MyTwitterConfiguration {
    [CmdletBinding()]
	param()

    Process {
		$RegKey = 'HKCU:\Software\MyTwitter'
		if (!(Test-Path -Path $RegKey)) {
			Write-Verbose 'No MyTwitter configuration found in registry'

		} else {
			$Values = 'APIKey', 'APISecret', 'AccessToken', 'AccessTokenSecret'
			$Output = @{}
			foreach ($Value in $Values) {
				if ((Get-Item -Path $RegKey).GetValue($Value)) {
					$Output.$Value = (Get-Item -Path $RegKey).GetValue($Value)

				} else {
					$Output.$Value = ''
				}
			}
			[pscustomobject]$Output
		}
	}
}

Function Remove-MyTwitterConfiguration {
	[CmdletBinding()]
	param()

    Process {
		$RegKey = 'HKCU:\Software\MyTwitter'
		if (!(Test-Path -Path $RegKey)) {
			Write-Verbose 'No MyTwitter configuration found in registry'

		} else {
			Remove-Item -Path $RegKey -Force
		}
	}
}

Function Get-TweetTimeline {
<#
  .SYNOPSIS
   This Function retrieves the Timeline of a Twitter user.
  .DESCRIPTION
   This Function retrieves the Timeline of a Twitter user.
  .EXAMPLE
   $TimeLine = Get-TweetTimeline -UserName "sstranger" -MaximumTweets 10
   $TimeLine | Out-Gridview -PassThru
   
   This example stores the retrieved Twitter timeline for user sstranger with a maximum of 10 tweets and pipes the result
   to the Out-GridView cmdlet.
   .EXAMPLE
   $TimeLine = Get-TweetTimeline -UserName "sstranger" -MaximumTweets 100
   $TimeLine | Sort-Object -Descending | Out-Gridview -PassThru
   
   This example stores the retrieved Twitter timeline for user sstranger with a maximum of 100 tweets,
   sorts the result descending on retweet counts and pipes the result to the Out-GridView cmdlet.
#>
	[CmdletBinding()]
	[OutputType('System.Management.Automation.PSCustomObject')]
	param (
		[Parameter(Mandatory)]
		[string]$Username,
		[Parameter()]
		[switch]$IncludeRetweets = $true,
		[Parameter()]
		[switch]$IncludeReplies = $true,
		[Parameter()]
		[ValidateRange(1, 200)]
		[int]$MaximumTweets = 200,
        [Parameter()]
        [string]$SinceId,
        [Parameter()]
        [string]$MaxId
	)
	process {
		$HttpEndPoint = 'https://api.twitter.com/1.1/statuses/user_timeline.json'
		$ApiParams = @{
			'include_rts' = @{ $true = 'true';$false = 'false' }[$IncludeRetweets -eq $true]
			'exclude_replies' = @{ $true = 'false'; $false = 'true' }[$IncludeReplies -eq $true]
			'count' = $MaximumTweets
			'screen_name' = $Username
		}
        if ($SinceId) {
            $ApiParams.Add('since_id', $SinceId)
        }
        if ($SinceId) {
            $ApiParams.Add('max_id', $MaxId)
        }
		$AuthorizationString = Get-OAuthAuthorization -Api 'Timeline' -ApiParameters $ApiParams -HttpEndPoint $HttpEndPoint -HttpVerb GET
		
		$HttpRequestUrl = 'https://api.twitter.com/1.1/statuses/user_timeline.json?'
		#$ApiParams.GetEnumerator() | Sort-Object name | ForEach-Object { $HttpRequestUrl += '{0}={1}&' -f $_.Key, $_.Value }
		#$HttpRequestUrl = $HttpRequestUrl.Trim('&')
		#Write-Verbose "HTTP request URL is '$HttpRequestUrl'"
        $HttpRequestUrl = New-RequestUrl -RequestUrl $HttpEndPoint -Parameter $ApiParams
		Invoke-RestMethod -URI $HttpRequestUrl -Method Get -Headers @{ 'Authorization' = $AuthorizationString } -ContentType 'application/json'
    
	}
}

Function New-RequestUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RequestUrl
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $Parameter
    )

    Process {
        $RequestUrl += '?'
        $RequestUrl += ($Parameter.GetEnumerator() | Sort-Object name | ForEach-Object {'{0}={1}' -f $_.Key, $_.Value}) -join '&'
        $RequestUrl
    }
}

Function Get-TwitterUserTimeline {
	[CmdletBinding()]
	[OutputType('System.Management.Automation.PSCustomObject')]
	param (
		[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
		[string]
        $Username
        ,
		[Parameter()]
		[switch]
        $IncludeRetweets = $true
        ,
		[Parameter()]
		[switch]
        $IncludeReplies = $true
        ,
		[Parameter()]
		[ValidateRange(1, 200)]
		[int]
        $Count = 200
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $SinceId
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $MaxId
	)

	Process {
		$HttpEndPoint = 'https://api.twitter.com/1.1/statuses/user_timeline.json'
		$ApiParams = @{
			'include_rts' = @{ $true = 'true';$false = 'false' }[$IncludeRetweets -eq $true]
			'exclude_replies' = @{ $true = 'false'; $false = 'true' }[$IncludeReplies -eq $true]
			'count' = $Count
			'screen_name' = $Username
		}
        if ($SinceId) {
            $ApiParams.Add('since_id', $SinceId)
        }
        if ($MaxId) {
            $ApiParams.Add('max_id', $MaxId)
        }
		$AuthorizationString = Get-OAuthAuthorization -Api Timeline -HttpEndPoint $HttpEndPoint -ApiParameters $ApiParams -HttpVerb Get
		
		$HttpRequestUrl = New-RequestUrl -RequestUrl $HttpEndPoint -Parameter $ApiParams
		Invoke-RestMethod -Uri $HttpRequestUrl -Method Get -Headers @{'Authorization' = $AuthorizationString} -ContentType 'application/json'
	}
}

Function Get-TwitterHomeTimeline {
	[CmdletBinding()]
	[OutputType('System.Management.Automation.PSCustomObject')]
	param (
		[Parameter()]
		[switch]
        $IncludeRetweets = $true
        ,
		[Parameter()]
		[switch]
        $IncludeReplies = $true
        ,
		[Parameter()]
		[ValidateRange(1, 200)]
		[int]
        $Count = 200
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $SinceId
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $MaxId
	)

	Process {
		$HttpEndPoint = 'https://api.twitter.com/1.1/statuses/home_timeline.json'
		$ApiParams = @{
			'include_rts' = @{ $true = 'true';$false = 'false' }[$IncludeRetweets -eq $true]
			'exclude_replies' = @{ $true = 'false'; $false = 'true' }[$IncludeReplies -eq $true]
			'count' = $Count
		}
        if ($SinceId) {
            $ApiParams.Add('since_id', $SinceId)
        }
        if ($MaxId) {
            $ApiParams.Add('max_id', $MaxId)
        }
		$AuthorizationString = Get-OAuthAuthorization -Api Timeline -HttpEndPoint $HttpEndPoint -ApiParameters $ApiParams -HttpVerb Get
		
		$HttpRequestUrl = New-RequestUrl -RequestUrl $HttpEndPoint -Parameter $ApiParams
		Invoke-RestMethod -Uri $HttpRequestUrl -Method Get -Headers @{'Authorization' = $AuthorizationString} -ContentType 'application/json'
	}
}

Function Get-TwitterRetweets {
	[CmdletBinding()]
	[OutputType('System.Management.Automation.PSCustomObject')]
	param (
		[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
		[string]
        $Id
        ,
		[Parameter()]
        [ValidateNotNullOrEmpty()]
		[int]
        $Count = 25
        ,
		[Parameter()]
		[switch]
        $TrimUser
	)

	Process {
		$HttpEndPoint = 'https://api.twitter.com/1.1/statuses/retweets/{0}.json' -f $Id
		$ApiParams = @{
            'count' = $Count
            'trim_user' = $TrimUser
		}
		$AuthorizationString = Get-OAuthAuthorization -Api Timeline -HttpEndPoint $HttpEndPoint -ApiParameters $ApiParams -HttpVerb Get
		
		$HttpRequestUrl = New-RequestUrl -RequestUrl $HttpEndPoint -Parameter $ApiParams
		Invoke-RestMethod -Uri $HttpRequestUrl -Method Get -Headers @{'Authorization' = $AuthorizationString} -ContentType 'application/json'
	}
}

New-MyTwitterConfiguration -Force -APIKey 'vxpvXfrgt6OOimPJz5Ig5qS0K' -APISecret 'Yd9RD8UtGu3a2k8jnDlgwPnjaCuHI0nkDBBoerHEck1h74sNeR' -AccessToken '76157528-QO6cSC9gNoGnKfQhGFPMOieprHK2ppCBSVEfQfnaD' -AccessTokenSecret 'uhvdKOIn7oEiIgSqMt5PsOAnRYOegFaIos9UVco978xln'
#Send-Tweet -Message '@adbertram Thanks for the Powershell Twitter module'

#$tweets = Get-TweetTimeline -Username nicholasdille -MaximumTweets 1 -IncludeRetweets:$false
#$tweets = Get-TwitterTimeline -Username nicholasdille -Count 1 -IncludeRetweets:$false
#1..10 | ForEach-Object {
#    $tweets += Get-TweetTimeline -Username nicholasdille -MaxId ($tweets[-1].id - 1) -IncludeRetweets:$false -IncludeReplies:$false
#}
#$tweets

Get-TwitterHomeTimeline -Count 1

#Get-TwitterRetweets -Id '743819108156841984'