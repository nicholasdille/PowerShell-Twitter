function Set-TwitterData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $User
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Token
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Team = ''
    )

    $script:BitBucketOnlineUser  = $User
    $script:BitBucketOnlineToken = $Token
    $script:BitBucketOnlineTeam  = $Team
}
