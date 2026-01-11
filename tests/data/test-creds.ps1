# Plain PowerShell credential object
$Username = "corp\\svc-backup"
$Password = ConvertTo-SecureString "SuperSecretPassword123!" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($Username, $Password)
