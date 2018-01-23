function Get-TwitterHomeTimeline {
	[CmdletBinding()]
	[OutputType('System.Management.Automation.PSCustomObject')]
	param (
		[Parameter()]
        [ValidateNotNullOrEmpty()]
		[string]
        $Username
        ,
		[Parameter()]
		[switch]
        $ExcludeRetweets
        ,
		[Parameter()]
		[switch]
        $ExcludeReplies
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

	process {
		$HttpEndPoint = 'https://api.twitter.com/1.1/statuses/home_timeline.json'
		$ApiParams = @{
			'include_rts'     = @{ $true = 'true'; $false = 'false' }[$ExcludeRetweets]
			'exclude_replies' = @{ $true = 'true'; $false = 'false' }[$ExcludeReplies]
			'count' = $Count
        }
        if ($Username) {
            $ApiParams.Add('screen_name', $Username)
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