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

    [Parameter(Position = 3, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string] $FileName
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

$uri = 'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable';
$headers = @{
    Authorization = "Bearer $($oAuth.AccessToken)"
    Accept        = "application/json"
};
$uploadRequest = Invoke-WebRequest -Method Post -Uri $uri -Headers $headers;
[string] $uploadUri = [string]::Empty;
$uploadRequest.rawcontent -split [System.Environment]::NewLine | ForEach-Object {
    if ($_.Trim() -like 'Location: https://*') {
        $uploadUri = $_.Trim().Substring('Location: '.Length).Trim();
    }
}

[System.IO.FileInfo] $file = [System.IO.FileInfo]::new($FileName);
[byte[]] $fileContent = [System.IO.File]::ReadAllBytes($file.FullName);;
$headers = @{
    Authorization = "Bearer $($oAuth.AccessToken)"
    Accept        = "application/json"
    "Content-Length" = $file.Length.ToString()
    "Content-Type" = "application/octet-stream"
};
Invoke-WebRequest -Uri $uploadUri -Headers $headers -Body $fileContent -SkipHeaderValidation;