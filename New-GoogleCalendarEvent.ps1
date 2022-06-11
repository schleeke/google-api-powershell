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
.PARAMETER Title
  The title of the event.
.PARAMETER StartDate
  The (optional) minimum date of the earliest entry.
.PARAMETER EndDate
  The (optional) maximum date for the latest entry.
.PARAMETER Description
  The (optional) description for the event.
.PARAMETER Type
  The (optional) Type of the event.
.PARAMETER RecurrenceRules
  An (optional) set of rules for recurring events.
.LINK
  https://developers.google.com/calendar/api/v3/reference/events
  https://developers.google.com/calendar/api/v3/reference/events/insert
  https://dateutil.readthedocs.io/en/stable/rrule.html
#>
[CmdletBinding(DefaultParameterSetName = 'ByCalendar')]
PARAM (
    [Parameter(Position = 0)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string] $GoogleApiClientId,

    [Parameter(Position = 1)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string] $GoogleApiClientSecret,

    [Parameter(Position = 2)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string] $GoogleApiKey,

    [Parameter(Position = 3, Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string] $CalendarName,

    [Parameter(Position = 4, Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string] $Title,

    [Parameter(Position = 5, Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [datetime] $StartDate,

    [Parameter(Position = 6, Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [datetime] $EndDate,

    [Parameter(Position = 7)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string] $Description,

    [Parameter(Position = 8)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [ValidateSet('default', 'outOfOffice', 'focusTime')]
    [string] $Type,

    [Parameter(Position = 9)]
    [Parameter(ParameterSetName = 'ByCalendar')]
    [string[]] $RecurrenceRules
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

function Script:Get-CalendarId([string]$calendarName, $googleAuthentication) {
    $headers = @{
        Authorization = "Bearer $($googleAuthentication.AccessToken)"
        Accept        = "application/json" };
    $uri = "https://www.googleapis.com/calendar/v3/users/me/calendarList?key=$([System.Net.WebUtility]::UrlEncode($googleAuthentication.ApiKey))";
    $result = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers;
    [string] $calId = [string]::Empty;
    foreach ($calendar in $result.items) {
        if ($calendar.summary -ne $CalendarName) {
            continue; }
        $calId = $calendar.id;
        break; }
    return $calId;        
}


# Reference for RRULE
# https://dateutil.readthedocs.io/en/stable/rrule.html
function Script:Get-RecuurenceInformation([string]$definition) {
    $retVal = [PSCustomObject]@{
        Frequence = [string]::Empty
        Count = 0
        Interval = 1
        Valid = $false
        Definition = $definition };
    if ([string]::IsNullOrEmpty($definition)) {
        return $retVal; }
    if (!$definition.StartsWith('RRULE:')) {
        return $retVal; }
    [string[]] $properties = $definition.Substring('RRULE:'.Length) -split ';';    
    [bool] $isCountSet = $false;
    [bool] $isUntilSet = $false;
    foreach($def in $properties) {
        $def = $def.Trim();
        if ($def.IndexOf('=') -lt 1) {
            continue; }
        [int] $index = $def.IndexOf('=');
        [string] $propName = $def.Substring(0, $index).Trim().ToUpper();
        [string] $propValue = $def.Substring($index + 1).Trim().ToUpper();
        switch ($propName) {
            'FREQ' {
                $valid = @(
                    'YEARLY',
                    'MONTHLY',
                    'DAILY',
                    'HOURLY',
                    'MINUTELY',
                    'SECONDLY' );
                if ($valid -contains $propValue) {
                    $retVal.Frequence = $propValue;
                    $retVal.Valid = $true; }
            }
            'INTERVAL' {
                [int] $intervalValue = 1;
                if ([int]::TryParse($propValue, [ref] $intervalValue)) {
                    $retVal.Interval = $intervalValue;
                    $retVal.Valid = $true; }
            }
            'COUNT' {
                if ($isUntilSet) {
                    continue; }
                [int] $countValue = 0;
                if ([int]::TryParse($propValue, [ref] $countValue)) {
                    $retVal.Count = $countValue;
                    $isCountSet = $true;
                    $retVal.Valid = $true; }
            }
            'UNTIL' {
                if ($isCountSet) {
                    continue; }
                $isUntilSet = $true;
                $retVal.Valid = $true;
            }
        }
    }
    return $retVal;
}

function Script:ConvertTo-BodyObject($inputObject) {
    [string] $typeName = $inputObject.GetType().Name;

    if ($typeName -eq 'DateTime') {
        $retVal = [PSCustomObject]@{
            dateTime = $inputObject
            timeZone = 'Europe/Berlin' };
        return $retVal;
    }
    Write-Warning "Cannot convert type '$($typeName)'.";
}

$oAuth = Script:New-GoogleAuthentication -scopes $apiScopes -clientId $GoogleApiClientId -clientSecret $GoogleApiClientSecret -apiKey $GoogleApiKey;
[string] $calendarId = Script:Get-CalendarId -calendarName $CalendarName -googleAuthentication $oAuth;
if ([string]::IsNullOrEmpty($calendarId)) {
    Write-Error "Unable to find a calendar named '$($CalendarName)'." -ErrorAction Stop; }
$bodyObject = [psobject]::new();
$startObject = Script:ConvertTo-BodyObject -inputObject $StartDate;
$endObject = Script:ConvertTo-BodyObject -inputObject $EndDate;
$bodyObject | Add-Member -MemberType NoteProperty -Name 'end' -Value $endObject;
$bodyObject | Add-Member -MemberType NoteProperty -Name 'start' -Value $startObject;
$bodyObject | Add-Member -MemberType NoteProperty -Name 'summary' -Value $Title;
if ([string]::IsNullOrEmpty($Type) -eq $false -and $Type -ne 'default') {
    $bodyObject | Add-Member -MemberType NoteProperty -Name 'eventType' -Value $Type; }
if (![string]::IsNullOrEmpty($Description)) {
    $bodyObject | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description;
}

if ($null -ne $RecurrenceRules -and $RecurrenceRules.Count -gt 0) {
    [string[]] $ruleArray = @();
    foreach($rule in $RecurrenceRules) {
        if ([string]::IsNullOrEmpty($rule)) {
            continue; }
        $ruleObject = Script:Get-RecuurenceInformation -definition $rule;
        if (!$ruleObject.Valid) {
            continue; }
        [string] $validatedRule = "RRULE:FREQ=$($ruleObject.Frequence);INTERVAL=$($ruleObject.Interval);COUNT=$($ruleObject.Count)";
        $ruleArray += $validatedRule; }
    if ($ruleArray.Count -gt 0) {
        $bodyObject | Add-Member -MemberType NoteProperty -Name 'recurrence' -Value $ruleArray; }
}

[string] $bodyContent = ConvertTo-Json -InputObject $bodyObject;
$headers = @{
    Authorization  = "Bearer $($oAuth.AccessToken)"
    Accept         = "application/json"
    "Content-Type" = "application/json" };
$uri = "https://www.googleapis.com/calendar/v3/calendars/$([System.Net.WebUtility]::UrlEncode($calendarId))/events?key=$([System.Net.WebUtility]::UrlEncode($oAuth.ApiKey))";
$result = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $bodyContent;
$result