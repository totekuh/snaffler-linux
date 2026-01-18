$password = ConvertTo-SecureString "MyP@ssword123" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ("domain\user", $password)

# Use the credential
Invoke-Command -ComputerName server01 -Credential $credential -ScriptBlock {
    Get-Service
}
