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