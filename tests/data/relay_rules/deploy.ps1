# PowerShell deployment script
$securePassword = ConvertTo-SecureString "MySecureP@ssw0rd" -AsPlainText -Force
$cred = New-Object PSCredential("admin", $securePassword)
