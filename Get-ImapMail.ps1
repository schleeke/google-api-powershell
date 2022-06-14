<#
#>
[CmdletBinding()]
PARAM (
    [Parameter(Position = 0)]
    [string] $ImapServerName,

    [Parameter(Position = 1)]
    [int] $ImapServerPort = 993
)

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop;
[string] $mimeKitPath = [System.IO.Path]::Combine($PSScriptRoot, 'MimeKit.dll');
[string] $mailKitPath = [System.IO.Path]::Combine($PSScriptRoot, 'MailKit.dll');
[string] $userAuthFilePath = [System.IO.Path]::Combine($env:USERPROFILE, '.secrets', 'get-imap-mail.token');
[string] $Script:userName = [string]::Empty;
[string] $Script:passwd = [string]::Empty;

function Script:Get-UserInformation() {
    [string] $cfgPath = Split-Path -Path $userAuthFilePath;
    if (!(Test-Path -Path $cfgPath -PathType Container)) {
        [System.IO.Directory]::CreateDirectory($cfgPath) | Out-Null; }
    if (Test-Path -Path $userAuthFilePath -PathType Leaf) {
        [string] $fileContent = (Get-Content -Path $userAuthFilePath -Encoding utf8).Trim();
        $securePwd = $fileContent | ConvertTo-SecureString;
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd);
        [string] $decryptedContent = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr);
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr);
        [int] $seperatorIndex = $decryptedContent.IndexOf('<°))))><');
        if ($seperatorIndex -lt 2) {
            Write-Error -Message 'Cannot parse user information file content.'; }
        [string] $usr = $decryptedContent.Substring(0, $seperatorIndex);
        [string] $p = $decryptedContent.Substring($seperatorIndex + '<°))))><'.Length);
        $Script:userName = $usr;
        $Script:passwd = $p;
        $p = [string]::Empty; }
    else {
        Write-Host '************************************************************';
        Write-Host '* Please enter the credentials for your posteo account.    *';
        Write-Host '* Normally this is your email address and your password as *';
        Write-Host '* used in the web UI of posteo.                            *';
        Write-Host '* The credentials will be stored in your user''s directory  *';
        Write-Host '* for later reuse.                                         *';
        Write-Host '************************************************************';
        $Script:userName = Read-Host -Prompt 'Please enter your user name';
        $secStr = Read-Host -Prompt 'Please enter your password' -AsSecureString;
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secStr);
        $Script:passwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr);
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr);
        [string] $plainContent = "$($Script:userName)<°))))><$($Script:passwd)";
        $securePwd = $plainContent | ConvertTo-SecureString -AsPlainText -Force
        $encryptedPwd = $securePwd | ConvertFrom-SecureString;
        Set-Content -Path $userAuthFilePath -Value $encryptedPwd -Force -Encoding utf8; }
}

function Script:Get-ServerName([string] $emailAddress) {
    if ([string]::IsNullOrEmpty($emailAddress)) {
        return [string]::Empty; }
    [int] $index = $emailAddress.IndexOf('@');
    if ($index -lt 1) {
        return [string]::Empty; }
    [string] $retVal = $emailAddress.Substring($index + 1);
    return $retVal;
}

if (!(Test-Path -Path $mimeKitPath -PathType Leaf)) {
    Write-Error -Message 'Cannot find mimekit.dll in the script''s directory'; }
if (!(Test-Path -Path $mailKitPath -PathType Leaf)) {
    Write-Error -Message 'Cannot find mailkit.dll in the script''s directory'; }    
Add-Type -Path $mimeKitPath;
Add-Type -Path $mailKitPath;
Script:Get-UserInformation;
$imap = New-Object MailKit.Net.Imap.ImapClient;
if ([string]::IsNullOrEmpty($ImapServerName)) {
    $ImapServerName = Script:Get-ServerName -emailAddress $Script:userName; }
$imap.Connect($ImapServerName, $ImapServerPort);
$imap.Authenticate($Script:userName, $Script:passwd);
$Script:passwd = [string]::Empty;
$imap.Inbox.Open([MailKit.FolderAccess]::ReadWrite) | Out-Null;
$query = [MailKit.Search.SearchQuery]::NotDeleted;
$uids = $imap.Inbox.Search($query);
foreach ($item in $uids.GetEnumerator()) {
    [MimeKit.MimeMessage] $msg = $imap.Inbox.GetMessage($item);
    Write-Output -InputObject $msg; }
$imap.Disconnect($true);