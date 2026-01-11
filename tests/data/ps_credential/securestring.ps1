$Password = ConvertTo-SecureString "SuperSecret123!" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential("corp\\admin", $Password)
