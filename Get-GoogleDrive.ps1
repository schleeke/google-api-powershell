<#
#>
[CmdletBinding()]
PARAM (
    [Parameter(Position = 0)]
    [string] $GoogleApiClientId,

    [Parameter(Position = 1)]
    [string] $GoogleApiClientSecret,

    [Parameter(Position = 2)]
    [string] $GoogleApiKey,

    [Parameter(Position = 3)]
    [string] $FileName,

    [parameter(Position = 4)]
    [switch] $Download
)

#Requires -Version 5.0

$apiScopes = @('https://www.googleapis.com/auth/drive');
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12;
[string] $userAuthFilePath = [System.IO.Path]::Combine($env:USERPROFILE, '.gapi', 'get-google-drive.json');

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
    Accept        = "application/json"
};
if ([string]::IsNullOrEmpty($FileName)) {
    [string] $uri = "https://www.googleapis.com/drive/v3/files?q=mimeType%20!%3D%20%27application%2Fvnd.google-apps.folder%27&key=$($oAuth.ApiKey)";
    $result = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers;
    if (!$Download.IsPresent) {
        $result.files;
        exit;
    }
    $result.files | ForEach-Object {
        [string] $fileId = $_.id;
        $uri = "https://googleapis.com/drive/v3/files/$($fileId)?alt=media";
        $fileResult = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers;
        $fileResult;
    }
    exit;
}
[string] $uri = "https://www.googleapis.com/drive/v3/files?q=mimeType%20!%3D%20%27application%2Fvnd.google-apps.folder%27%20and%20name%20contains%20%27$([System.Net.WebUtility]::UrlEncode($FileName))%27&key=$($oAuth.ApiKey)";
$result = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers;
if (!$Download.IsPresent) {
    $result.files;
    exit;
}
$result.files | ForEach-Object {
    [string] $fileId = $_.id;
    $headers = @{
        Authorization = "Bearer $($oAuth.AccessToken)"
        Accept        = "application/json"
    };
        $uri = "https://www.googleapis.com/drive/v2/files/$([System.Net.WebUtility]::UrlEncode($fileId))?key=$($oAuth.ApiKey)";
    $fileResult = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers;
    $fileResult.webContentLink;
    [string] $fileName = $fileResult.title;
    Invoke-WebRequest -Uri $fileResult.webContentLink -OutFile $fileName;
}
