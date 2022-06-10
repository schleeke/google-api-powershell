<#
.SYNOPSIS
  Fetches mails from google mail.
.DESCRIPTION
  Uses the goggle mail web API to fetch mails.
.PARAMETER EmailAddress
  The address of the mail account to retrieve the mails from.
.PARAMETER GoogleApiClientId
  The google web API client id as retrieved from the google developer page.
.PARAMETER GoogleApiClientSecret
  The secret token for the web API as retrieved from the google developer page.
.PARAMETER IncludeSpamTrash
  Includes mails that are marked as spam/trash.
.PARAMETER Labels
  The labels for the mail that should be retrieved.
  The default is INBOX and UNREAD.
.PARAMETER MaximumResults
  The maximum amount of results to retrieve.
  The default is 100.
.NOTES
  The authentication credentials are stored in the user profile in /.gapi/get-gmail.json
  and are used in further calls so that the GoogleApiClientId and GoogleApiClientSecret
  don't need to be set.
#>
[CmdletBinding()]
PARAM (
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $EmailAddress,

    [Parameter(Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string] $GoogleApiClientId,

    [Parameter(Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string] $GoogleApiClientSecret,

    [Parameter(Position = 3)]
    [switch] $IncludeSpamTrash,

    [Parameter(Position = 5)]
    [ValidateNotNullOrEmpty()]
    [string[]] $Labels = @('INBOX','UNREAD'),

    [Parameter(Position = 6)]
    [int] $MaximumResults = 100
)

#Requires -Version 5.0
$apiScopes = @('https://mail.google.com/');
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12;
[string] $userAuthFilePath = [System.IO.Path]::Combine($env:USERPROFILE, '.gapi', 'get-gmail.json')

function Script:New-GoogleAuthentication([string[]] $scopes, [string] $clientId, [string] $clientSecret) {
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
            exit; }
        [string] $authCode = Get-ClipBoard;    
        $requestbody = @{
            "code"=$authcode
            "client_id"=$clientId
            "client_secret"=$clientSecret
            "redirect_uri"='urn:ietf:wg:oauth:2.0:oob'
            "grant_type"="authorization_code" };
        $webResult = Invoke-RestMethod 'https://www.googleapis.com/oauth2/v3/token' -Method Post -Body $requestbody -ErrorAction Stop;
        [datetime] $expirationDate = [datetime]::Now.AddSeconds($webResult.expires_in);
        $retVal = [PSCustomObject]@{
            RefreshToken = $webResult.refresh_token
            AccessToken = $webResult.access_token
            ClientId = $clientId
            Secret = $clientSecret
            ValidUntil = $expirationDate };
        [string] $jsonContent = ConvertTo-Json -InputObject $retVal;
        Set-Content -Path $fullTokenPath -Encoding utf8 -Force -Value $jsonContent;
    }
    if ([string]::IsNullOrEmpty($retVal.AccessToken) -or ($retVal.ValidUntil -lt [datetime]::Now)) {
        Write-Debug -Message 'Refreshing access token...';
        $requestbody = @{
            "refresh_token"=$retVal.RefreshToken
            "client_id"=$retVal.ClientId
            "client_secret"=$retVal.Secret
            "grant_type"="refresh_token" };
        $webResult = Invoke-RestMethod 'https://www.googleapis.com/oauth2/v3/token' -Method Post -Body $requestbody -ErrorAction Stop;
        $retVal.AccessToken = $webResult.access_token;
        [datetime] $expDate = [datetime]::Now.AddSeconds($webResult.expires_in);
        $retVal.ValidUntil = $expDate;
    }
    return $retVal;
}

function Script:Get-GoogleMail($authentication, $maxResults) {
    $param_spam = $(if($IncludeSpamTrash.IsPresent){'&includeSpamTrash=true'}else{'&includeSpamTrash=false'});
    $param_format = '&format=raw';
    $param_labels = $(if($Labels){'&labelIds=' + $($Labels -join '&labelIds=')});
    $uri = "https://www.googleapis.com/gmail/v1/users/$([System.Net.WebUtility]::UrlEncode($EmailAddress))/messages?access_token=$($authentication.AccessToken)$param_labels$param_spam&maxResults=$maxResults";
    $result = Invoke-RestMethod $uri -Method Get -ErrorAction Stop;
    foreach ($id in $result.messages.id) {
        $mail = Invoke-RestMethod -Uri "https://www.googleapis.com/gmail/v1/users/$($EmailAddress)/messages/$($id)?access_token=$($authentication.AccessToken)$param_format" -Method Get -ErrorAction Stop;
        [string] $b64data = $mail.raw.replace('-','+').replace('_','/');
        [string] $rawMailContent = ([System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($b64data)));
        $newMail = [PSCustomObject]@{
            DeliveredTo = [string]::Empty
            Received = [PSCustomObject]@{
                IpAddress = [string]::Empty
                SmtpId = [string]::Empty
                Date = [datetime]::MinValue
            }
            MimeVersion = [string]::Empty
            Date = [datetime]::MinValue
            MessageId = [string]::Empty
            Subject = [string]::Empty
            From = [string]::Empty
            To = [string]::Empty
            RawMessage = [string]::Empty
            HtmlMessage = [string]::Empty
            BoundaryMarker = [string]::Empty
        };
        [int] $counter = 0;
        [bool] $isInContentBlock = $false;
        [bool] $isInReceivedBlock = $false;
        [bool] $contentBlockType = 'unknown';
        [int] $contentStartLineNumber = 0;
        [System.Text.StringBuilder] $contentBuilder = $null;
        foreach($line in ($rawMailContent -split [System.Environment]::NewLine)) {
            $counter++;
            if (($isInContentBlock -eq $false) -and ($isInReceivedBlock) -eq $false) {
                if ($line.Trim().StartsWith('Delivered-To: ')) {
                    $newMail.DeliveredTo = $line.Substring('Delivered-To: '.Length).Trim();
                }
                if ($line.Trim().StartsWith('MIME-Version: ')) {
                    $newMail.MimeVersion = $line.Substring('MIME-Version: '.Length).Trim();
                }
                if ($line.Trim().StartsWith('Message-ID: ')) {
                    $newMail.MessageId = $line.Substring('Message-ID: '.Length).Trim();
                }
                if ($line.Trim().StartsWith('Subject: ')) {
                    $newMail.Subject = $line.Substring('Subject: '.Length).Trim();
                }
                if ($line.Trim().StartsWith('From: ')) {
                    $newMail.From = $line.Substring('From: '.Length).Trim();
                }
                if ($line.Trim().StartsWith('To: ')) {
                    $newMail.To = $line.Substring('To: '.Length).Trim();
                }
                if ($line.Trim().StartsWith('Content-Type: multipart/alternative; boundary=')) {
                    $boundary = $line.Substring('Content-Type: multipart/alternative; boundary='.Length + 1).Trim();
                    $boundary = $boundary.Substring(0, $boundary.Length - 1);
                    $newMail.BoundaryMarker = $boundary;
                }
                if (![string]::IsNullOrEmpty($newMail.BoundaryMarker)) {
                    if ($line.Trim().StartsWith("--$($newMail.BoundaryMarker)")) {
                        $isInContentBlock = $true;
                        continue;
                    }    
                }
                continue;
            }
            if ($isInContentBlock) {
                if ($line.Trim().StartsWith('Content-Type: text/plain; ')) {
                    $contentBlockType = 'raw';
                    continue;
                }
                elseif ($line.Trim().StartsWith('Content-Type: text/html; ')) {
                    $contentBlockType = 'html';
                    continue;
                }
                elseif ($line.Trim().StartsWith('Content-Transfer-Encoding: ')) {
                    $contentStartLineNumber = $counter + 2;
                    continue;
                }

                if (![string]::IsNullOrEmpty($newMail.BoundaryMarker)) {
                    if ($line.Trim().StartsWith("--$($newMail.BoundaryMarker)") -and $contentBlockType -eq 'raw') {
                        $newMail.RawMessage = $contentBuilder.ToString();
                    }
                    if ($line.Trim().StartsWith("--$($newMail.BoundaryMarker)")) {
                        $contentStartLineNumber = 0;
                    }
                }

                if ($contentStartLineNumber -ne 0 -and $counter -eq $contentStartLineNumber) {
                    $contentBuilder = [System.Text.StringBuilder]::new();
                    if ($contentBlockType -eq 'html') {
                        $contentBuilder.AppendLine($line.Trim()) | Out-Null;
                    }
                    elseif ($contentBlockType -eq 'raw') {
                        $contentBuilder.Append($line.Trim()) | Out-Null;
                    }
                }
                elseif ($contentStartLineNumber -ne 0 -and $counter -gt $contentStartLineNumber) {
                    if ($contentBlockType -eq 'html') {
                        $contentBuilder.AppendLine($line.Trim()) | Out-Null;
                    }
                    elseif ($contentBlockType -eq 'raw') {
                        $contentBuilder.Append($line.Trim()) | Out-Null;
                    }
                }
                if($contentStartLineNumber -ne 0 -and $contentBlockType -eq 'html' -and $line.Trim() -eq '</html>') {
                    $contentStartLineNumber = 0;
                    $isInContentBlock = $false;
                    if ($contentBlockType -eq 'html') {
                        $newMail.HtmlMessage = $contentBuilder.ToString().Trim();
                    }
                }

            }
        }
        $newMail.RawMessage = ([System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($newMail.RawMessage))).Trim();
        $newMail;
    }
}

$oAuth = Script:New-GoogleAuthentication -scopes $apiScopes -clientId $GoogleApiClientId -clientSecret $GoogleApiClientSecret;
Script:Get-GoogleMail -authentication $oAuth -maxResults $MaximumResults;
