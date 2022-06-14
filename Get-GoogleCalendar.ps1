<#
.PARAMETER GoogleApiClientId
  The google web API client id as retrieved from the google developer page.
.PARAMETER GoogleApiClientSecret
  The secret token for the web API as retrieved from the google developer page.
.PARAMETER GoogleApiKey
  The API key for as set/retrieved from the google developer page.
.PARAMETER CalendarName
  The name of the calendar to show.
  A list of all available calendars will be returned if empty.
.PARAMETER MinimumStartDate
  The minimum start date/time of the calendar event.
  Can only be used with the -CalendarName parameter.
.PARAMETER MaximumStartTime
  The maximum start date/time of the calendar event.
  Can only be used with the -CalendarName parameter.
.PARAMETER Today
  Only today's events are shown.
  Can only be used with the -CalendarName parameter.
.LINK
  https://github.com/schleeke/google-api-powershell/blob/main/readme.md
#>
[CmdletBinding(DefaultParameterSetName = 'ByDefault')]
PARAM (
    [Parameter(Position = 0)]
    [Parameter(ParameterSetName = 'ByDefault')]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string] $GoogleApiClientId,

    [Parameter(Position = 1)]
    [Parameter(ParameterSetName = 'ByDefault')]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string] $GoogleApiClientSecret,

    [Parameter(Position = 2)]
    [Parameter(ParameterSetName = 'ByDefault')]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string] $GoogleApiKey,

    [Parameter(Position = 3)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string] $CalendarName,

    [Parameter(Position = 4)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [datetime] $MinimumStartDate = [datetime]::MinValue,

    [Parameter(Position = 5)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [datetime] $MaximumStartDate = [datetime]::MaxValue,

    [Parameter(Position = 6)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [switch] $Today

)

#Requires -Version 5.0
$apiScopes = @('https://www.googleapis.com/auth/calendar');
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12;
[string] $userAuthFilePath = [System.IO.Path]::Combine($env:USERPROFILE, '.gapi', 'get-google-calendar.json');

function Script:New-GoogleAuthentication([string[]] $scopes, [string] $clientId, [string] $clientSecret, [string] $apiKey) {
    $retVal = $null;
    if (Test-Path -Path $userAuthFilePath -PathType Leaf) {
        Write-Debug -Message 'Reading authorization file...';
        [string] $content = Get-Content -Path $userAuthFilePath -Encoding utf8;        
        $retVal = ConvertFrom-Json -InputObject $content;
        $retVal.AccessToken = [string]::Empty;
        if (![string]::IsNullOrEmpty($clientId)) {
            $retVal.ClientId = $clientId;
        }
        if (![string]::IsNullOrEmpty($clientSecret)) {
            $retVal.Secret = $clientSecret;
        }
        if (![string]::IsNullOrEmpty($apiKey)) {
            $retVal.ApiKey = $apiKey;
        }
        $content = ConvertTo-Json -InputObject $retVal;
        Set-Content -Value $content -Path $userAuthFilePath -Encoding utf8;
    }
    else {
        Write-Debug -Message 'Creating google API authentication...';
        $apiUrl = "https://accounts.google.com/o/oauth2/auth?scope=$($scopes -join " ")&redirect_uri=urn:ietf:wg:oauth:2.0:oob&response_type=code&client_id=$($clientId)";
        Write-Host '***********************************************************************************';
        Write-Host '* Please authorize this script to the google API in the following browser window. *';
        Write-Host '* Please copy the token into the clipboard.                                       *';
        Write-Host '* The script will fetch it from there once you continued its process...           *';
        Write-Host '***********************************************************************************';
        Start-Process -FilePath "msedge.exe" -ArgumentList $apiUrl, '--new-window';
        [System.Management.Automation.Host.ChoiceDescription] $confirmChoice = New-Object System.Management.Automation.Host.ChoiceDescription("&Yes", "Token copied to clipboard");
        [System.Management.Automation.Host.ChoiceDescription] $cancelChoice = New-Object System.Management.Automation.Host.ChoiceDescription("&Cancel", "Cancel login");
        [int] $result = $Host.UI.PromptForChoice("Google authenticatzion", "Confirm that the clipboard contains the authentication token from the login window.", @($confirmChoice, $cancelChoice), 0);
        if ($result -eq 1) {
            exit; 
        }
        [string] $authCode = Get-ClipBoard;    
        $requestbody = @{
            "code"          = $authcode
            "client_id"     = $clientId
            "client_secret" = $clientSecret
            "redirect_uri"  = 'urn:ietf:wg:oauth:2.0:oob'
            "grant_type"    = "authorization_code" 
        };
        $webResult = Invoke-RestMethod 'https://www.googleapis.com/oauth2/v3/token' -Method Post -Body $requestbody -ErrorAction Stop;
        [datetime] $expirationDate = [datetime]::Now.AddSeconds($webResult.expires_in);
        $retVal = [PSCustomObject]@{
            RefreshToken = $webResult.refresh_token
            AccessToken  = $webResult.access_token
            ClientId     = $clientId
            Secret       = $clientSecret
            ApiKey       = $apiKey
            ValidUntil   = $expirationDate 
        };
        [string] $jsonContent = ConvertTo-Json -InputObject $retVal;
        Set-Content -Path $userAuthFilePath -Encoding utf8 -Force -Value $jsonContent;
    }
    if ([string]::IsNullOrEmpty($retVal.AccessToken) -or ($retVal.ValidUntil -lt [datetime]::Now)) {
        Write-Debug -Message 'Refreshing access token...';
        $requestbody = @{
            "refresh_token" = $retVal.RefreshToken
            "client_id"     = $retVal.ClientId
            "client_secret" = $retVal.Secret
            "grant_type"    = "refresh_token" 
        };
        $webResult = Invoke-RestMethod 'https://www.googleapis.com/oauth2/v3/token' -Method Post -Body $requestbody -ErrorAction Stop;
        $retVal.AccessToken = $webResult.access_token;
        [datetime] $expDate = [datetime]::Now.AddSeconds($webResult.expires_in);
        $retVal.ValidUntil = $expDate;
    }
    return $retVal;
}


$oAuth = Script:New-GoogleAuthentication -scopes $apiScopes -clientId $GoogleApiClientId -clientSecret $GoogleApiClientSecret -apiKey $GoogleApiKey;
$headers = @{
    Authorization = "Bearer $($oAuth.AccessToken)"
    Accept        = "application/json" };
if ($PsCmdlet.ParameterSetName -eq 'ByDefault') {
    $uri = "https://www.googleapis.com/calendar/v3/users/me/calendarList?key=$([System.Net.WebUtility]::UrlEncode($oAuth.ApiKey))";
    $result = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers;
    $result.items | ForEach-Object {
        $retVal = [PSCustomObject]@{
            Id         = [string]$_.Id
            Name       = [string]$_.summary
            Primary    = [bool]$_.primary
            AccessRole = [string]$_.accessRole };
        Write-Output $retVal; }
    exit;
}
if ($PsCmdlet.ParameterSetName -eq 'ByCalendar') {
    $uri = "https://www.googleapis.com/calendar/v3/users/me/calendarList?key=$([System.Net.WebUtility]::UrlEncode($oAuth.ApiKey))";
    $result = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers;
    [string] $calId = [string]::Empty;
    foreach ($calendar in $result.items) {
        if ($calendar.summary -ne $CalendarName) {
            continue; }
        $calId = $calendar.id;
        break; }
    if ([string]::IsNullOrEmpty($calId)) {
        exit; }
    $uri = "https://www.googleapis.com/calendar/v3/calendars/$([System.Net.WebUtility]::UrlEncode($calId))/events?key=$($oAuth.ApiKey)";
    if ($Today.IsPresent) {
        [string] $formattedDateValue = [datetime]::Now.ToString('yyyy-MM-ddT00:00:01zzz');
        $uri += "&timeMin=$([System.Net.WebUtility]::UrlEncode($formattedDateValue))";
        $formattedDateValue = [datetime]::Now.ToString('yyyy-MM-ddT23:59:59zzz');
        $uri += "&timeMax=$([System.Net.WebUtility]::UrlEncode($formattedDateValue))"; }
    else {
        if ($MinimumStartDate -ne [datetime]::MinValue) {
            [string] $formattedDateValue = $MinimumStartDate.ToString('yyyy-MM-ddTHH:mm:sszzz');
            $uri += "&timeMin=$([System.Net.WebUtility]::UrlEncode($formattedDateValue))"; }
        if ($MaximumStartDate -ne [datetime]::MaxValue) {
            [string] $formattedDateValue = $MaximumStartDate.ToString('yyyy-MM-ddTHH:mm:sszzz');
            $uri += "&timeMax=$([System.Net.WebUtility]::UrlEncode($formattedDateValue))"; } }
    $result = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers;
    $result.items   
}