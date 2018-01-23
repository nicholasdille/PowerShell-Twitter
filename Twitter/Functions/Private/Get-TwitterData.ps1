function Get-TwitterData {
    [CmdletBinding()]
    param()

    if (-Not (Test-BitBucketOnline)) {
        throw 'Credentials not set. Please use Set-BitBucketOnline first.'
    }

    @{
        User  = $script:BitBucketOnlineUser
        Token = $script:BitBucketOnlineToken
        Team  = $script:BitBucketOnlineTeam
    }
}