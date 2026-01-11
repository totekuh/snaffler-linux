"""
Default classification rules for Snaffler Linux
Ported from the original Snaffler default rules
"""

from typing import List

from snaffler.classifiers.rules import (
    ClassifierRule, EnumerationScope, MatchAction,
    MatchLocation, MatchListType, Triage
)


def get_default_rules() -> List[ClassifierRule]:
    """Get the default rule set"""
    rules = []

    # Add all rule categories in order of evaluation
    rules.extend(get_share_rules())
    rules.extend(get_discard_directory_rules())
    rules.extend(get_discard_file_rules())
    rules.extend(get_ssh_rules())
    rules.extend(get_password_file_rules())
    rules.extend(get_hash_file_rules())
    rules.extend(get_key_and_cert_rules())
    rules.extend(get_database_rules())
    rules.extend(get_config_rules())
    rules.extend(get_cloud_credential_rules())
    rules.extend(get_password_manager_rules())
    rules.extend(get_remote_access_rules())
    rules.extend(get_shell_history_rules())
    rules.extend(get_browser_credential_rules())
    rules.extend(get_relay_rules())
    rules.extend(get_code_and_script_rules())
    rules.extend(get_infrastructure_rules())
    rules.extend(get_network_config_rules())
    rules.extend(get_cyberark_rules())
    rules.extend(get_ftp_rules())
    rules.extend(get_kerberos_rules())
    rules.extend(get_deploy_image_rules())
    rules.extend(get_memory_dump_rules())
    rules.extend(get_pcap_rules())
    rules.extend(get_defender_rules())
    rules.extend(get_sccm_rules())
    rules.extend(get_content_grep_rules())
    rules.extend(get_postmatch_rules())

    return rules


# ==============================================================================
# SHARE ENUMERATION RULES
# ==============================================================================

def get_share_rules() -> List[ClassifierRule]:
    """Rules for share enumeration"""
    return [
        ClassifierRule(
            rule_name="DiscardNonFileShares",
            enumeration_scope=EnumerationScope.SHARE_ENUMERATION,
            match_action=MatchAction.DISCARD,
            match_location=MatchLocation.SHARE_NAME,
            wordlist_type=MatchListType.ENDS_WITH,
            wordlist=['/PRINT', '/IPC'],
            triage=Triage.GREEN,
            description="Skips scanning inside shares ending with these words."
        ),

        ClassifierRule(
            rule_name="KeepDollarShares",
            enumeration_scope=EnumerationScope.SHARE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.SHARE_NAME,
            wordlist_type=MatchListType.ENDS_WITH,
            wordlist=['/C', '/ADMIN'],
            triage=Triage.BLACK,
            description="Notifies the user that they can read C$ or ADMIN$."
        ),

        ClassifierRule(
            rule_name="KeepSCCMShares",
            enumeration_scope=EnumerationScope.SHARE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.SHARE_NAME,
            wordlist_type=MatchListType.ENDS_WITH,
            wordlist=['/SCCMContentLib'],
            triage=Triage.YELLOW,
            description="Notifies the user that they can read SCCMContentLib$ so they can take CMLoot for a spin."
        ),
    ]


# ==============================================================================
# DIRECTORY DISCARD RULES
# ==============================================================================

def get_discard_directory_rules() -> List[ClassifierRule]:
    """Rules to discard uninteresting directories"""
    return [
        ClassifierRule(
            rule_name="DiscardLargeFalsePosDirs",
            enumeration_scope=EnumerationScope.DIRECTORY_ENUMERATION,
            match_action=MatchAction.DISCARD,
            match_location=MatchLocation.FILE_PATH,
            wordlist_type=MatchListType.CONTAINS,
            wordlist=['/puppet/share/doc', '/lib/ruby', '/lib/site-packages', '/usr/share/doc',
                      'node_modules', 'vendor/bundle', 'vendor/cache', '/doc/openssl',
                      'Anaconda3/Lib/test', 'WindowsPowerShell/Modules', 'Python/d*/Lib',
                      'Reference Assemblies/Microsoft/Framework/.NETFramework', 'dotnet/sdk',
                      'dotnet/shared', 'Modules/Microsoft.PowerShell.Security',
                      'Windows/assembly'],
            triage=Triage.GREEN,
            description="File paths that will be skipped entirely."
        ),

        ClassifierRule(
            rule_name="DiscardWinSystemDirs",
            enumeration_scope=EnumerationScope.DIRECTORY_ENUMERATION,
            match_action=MatchAction.DISCARD,
            match_location=MatchLocation.FILE_PATH,
            wordlist_type=MatchListType.CONTAINS,
            wordlist=['/winsxs', '/syswow64', '/system32', '/systemapps', '/windows/servicing',
                      '/servicing', '/Microsoft.NET/Framework', '/windows/immersivecontrolpanel',
                      '/windows/diagnostics', '/windows/debug', '/locale', '/chocolatey/helpers',
                      '/sources/sxs', '/localization', '/AppData/Local/Microsoft',
                      '/AppData/Roaming/Microsoft/Windows', '/AppData/Roaming/Microsoft/Teams',
                      '/wsuscontent', '/Application Data/Microsoft/CLR Security Config',
                      '/servicing/LCU'],
            triage=Triage.GREEN,
            description="File paths that will be skipped entirely."
        ),
    ]


# ==============================================================================
# FILE DISCARD RULES
# ==============================================================================

def get_discard_file_rules() -> List[ClassifierRule]:
    """Rules to discard uninteresting files"""
    return [
        ClassifierRule(
            rule_name="DiscardByFileExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.DISCARD,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.bmp', '.eps', '.gif', '.ico', '.jfi', '.jfif', '.jif', '.jpe', '.jpeg', '.jpg',
                      '.png', '.psd', '.svg', '.tif', '.tiff', '.webp', '.xcf', '.ttf', '.otf', '.lock',
                      '.css', '.less', '.admx', '.adml', '.xsd', '.nse', '.xsl'],
            triage=Triage.GREEN,
            description="Skip any further scanning for files with these extensions."
        ),

        ClassifierRule(
            rule_name="DiscardByFileName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.DISCARD,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['jmxremote.password.template', 'sceregvl.inf'],
            triage=Triage.GREEN,
            description="Skip any further scanning for files with these names."
        ),
    ]


# ==============================================================================
# SSH AND KEY FILES
# ==============================================================================

def get_ssh_rules() -> List[ClassifierRule]:
    """Rules for SSH keys and config"""
    return [
        ClassifierRule(
            rule_name="KeepSSHKeysByFileName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'],
            triage=Triage.BLACK,
            description="SSHKeys"
        ),

        ClassifierRule(
            rule_name="KeepSSHFilesByPath",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_PATH,
            wordlist_type=MatchListType.CONTAINS,
            wordlist=['/.ssh/'],
            triage=Triage.BLACK,
            description="Files with a path containing these strings are very very interesting."
        ),

        ClassifierRule(
            rule_name="KeepSSHKeysByFileExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.ppk'],
            triage=Triage.BLACK,
            description="SSHKeys"
        ),
    ]


# ==============================================================================
# PASSWORD FILES
# ==============================================================================

def get_password_file_rules() -> List[ClassifierRule]:
    """Rules for files with 'password' in the name"""
    return [
        ClassifierRule(
            rule_name="KeepNameContainsGreen",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.CONTAINS,
            wordlist=['passw', 'secret', 'credential', 'thycotic', 'cyberark'],
            triage=Triage.GREEN,
            description="A description of what a rule does."
        ),

        ClassifierRule(
            rule_name="KeepPasswordFilesByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['passwords.txt', 'pass.txt', 'accounts.txt', 'passwords.doc', 'pass.doc',
                      'accounts.doc', 'passwords.xls', 'pass.xls', 'accounts.xls', 'passwords.docx',
                      'pass.docx', 'accounts.docx', 'passwords.xlsx', 'pass.xlsx', 'accounts.xlsx',
                      'secrets.txt', 'secrets.doc', 'secrets.xls', 'secrets.docx',
                      'BitlockerLAPSPasswords.csv', 'secrets.xlsx'],
            triage=Triage.RED,
            description="Files with these exact names are very interesting."
        ),
    ]


# ==============================================================================
# HASH FILES (Windows and Unix)
# ==============================================================================

def get_hash_file_rules() -> List[ClassifierRule]:
    """Rules for password hash files"""
    return [
        ClassifierRule(
            rule_name="KeepWinHashesByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['NTDS.DIT', 'SYSTEM', 'SAM', 'SECURITY'],
            triage=Triage.BLACK,
            description="Files with these exact names are very very interesting."
        ),

        ClassifierRule(
            rule_name="KeepNixLocalHashesByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['shadow', 'pwd.db', 'passwd'],
            triage=Triage.BLACK,
            description="Files with these exact names are very very interesting."
        ),
    ]


# ==============================================================================
# KEYS AND CERTIFICATES
# ==============================================================================

def get_key_and_cert_rules() -> List[ClassifierRule]:
    """Rules for various key and certificate files"""
    return [
        ClassifierRule(
            rule_name="RelayCertByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.CHECK_FOR_KEYS,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.pem', '.der', '.pfx', '.pk12', '.p12', '.pkcs12'],
            triage=Triage.RED,
            description="Files with these extensions will be parsed as x509 certificates to see if they have private keys."
        ),
    ]


# ==============================================================================
# DATABASE FILES
# ==============================================================================

def get_database_rules() -> List[ClassifierRule]:
    """Rules for database files and configs"""
    return [
        ClassifierRule(
            rule_name="KeepDatabaseByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.mdf', '.sdf', '.sqldump', '.bak'],
            triage=Triage.YELLOW,
            description="Files with these extensions are a little interesting."
        ),

        ClassifierRule(
            rule_name="KeepDbMgtConfigByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['SqlStudio.bin', '.mysql_history', '.psql_history', '.pgpass',
                      '.dbeaver-data-sources.xml', 'credentials-config.json', 'dbvis.xml',
                      'robomongo.json'],
            triage=Triage.RED,
            description="Files with these exact names are very interesting."
        ),
    ]


# ==============================================================================
# CONFIG FILES
# ==============================================================================

def get_config_rules() -> List[ClassifierRule]:
    """Rules for configuration files"""
    return [
        ClassifierRule(
            rule_name="KeepConfigByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.htpasswd', 'accounts.v4'],
            triage=Triage.RED,
            description="Files with these exact names are very interesting."
        ),

        ClassifierRule(
            rule_name="KeepPhpByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['LocalSettings.php'],
            triage=Triage.RED,
            description="Files with these exact names are very interesting."
        ),

        ClassifierRule(
            rule_name="KeepRubyByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['database.yml', '.secret_token.rb', 'knife.rb', 'carrierwave.rb', 'omniauth.rb'],
            triage=Triage.RED,
            description="Files with these exact names are very interesting."
        ),

        ClassifierRule(
            rule_name="KeepJenkinsByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml', 'credentials.xml'],
            triage=Triage.RED,
            description="Files with these exact names are very interesting."
        ),

        ClassifierRule(
            rule_name="KeepGitCredsByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.git-credentials'],
            triage=Triage.RED,
            description="Files with these exact names are very interesting."
        ),
    ]


# ==============================================================================
# CLOUD CREDENTIALS
# ==============================================================================

def get_cloud_credential_rules() -> List[ClassifierRule]:
    """Rules for cloud provider credentials"""
    return [
        ClassifierRule(
            rule_name="KeepCloudApiKeysByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.tugboat'],
            triage=Triage.BLACK,
            description="Files with these exact names are very interesting."
        ),

        ClassifierRule(
            rule_name="KeepCloudApiKeysByPath",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_PATH,
            wordlist_type=MatchListType.CONTAINS,
            wordlist=['/.aws/', 'doctl/config.yaml'],
            triage=Triage.BLACK,
            description="Files with a path containing these strings are very very interesting."
        ),
    ]


# ==============================================================================
# PASSWORD MANAGERS
# ==============================================================================

def get_password_manager_rules() -> List[ClassifierRule]:
    """Rules for password manager databases"""
    return [
        ClassifierRule(
            rule_name="KeepPassMgrsByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.kdbx', '.kdb', '.psafe3', '.kwallet', '.keychain', '.agilekeychain', '.cred'],
            triage=Triage.BLACK,
            description="Files with these extensions are very very interesting."
        ),
    ]


# ==============================================================================
# REMOTE ACCESS CONFIGS
# ==============================================================================

def get_remote_access_rules() -> List[ClassifierRule]:
    """Rules for remote access configuration files"""
    return [
        ClassifierRule(
            rule_name="KeepRemoteAccessConfByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.rdg', '.rtsz', '.rtsx', '.ovpn', '.tvopt', '.sdtid'],
            triage=Triage.YELLOW,
            description="Files with these extensions are a little interesting."
        ),

        ClassifierRule(
            rule_name="KeepRemoteAccessConfByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['mobaxterm.ini', 'mobaxterm backup.zip', 'confCons.xml'],
            triage=Triage.BLACK,
            description="Files with these exact names are very very interesting."
        ),
    ]


# ==============================================================================
# SHELL HISTORY AND RC FILES
# ==============================================================================

def get_shell_history_rules() -> List[ClassifierRule]:
    """Rules for shell history and rc files"""
    return [
        ClassifierRule(
            rule_name="KeepShellHistoryByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.bash_history', '.zsh_history', '.sh_history', 'zhistory', '.irb_history',
                      'ConsoleHost_History.txt'],
            triage=Triage.GREEN,
            description="Files with these exact names are very interesting."
        ),

        ClassifierRule(
            rule_name="KeepShellRcFilesByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.netrc', '_netrc', '.exports', '.functions', '.extra', '.npmrc', '.env', '.bashrc',
                      '.profile', '.zshrc'],
            triage=Triage.GREEN,
            description="Files with these exact names are very interesting."
        ),
    ]


# ==============================================================================
# BROWSER CREDENTIALS
# ==============================================================================

def get_browser_credential_rules() -> List[ClassifierRule]:
    """Rules for browser credential files"""
    return [
        # Note: This relay rule requires relay logic implementation in file_scanner.py
        ClassifierRule(
            rule_name="KeepFfLoginsJsonRelay",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepFFRegexRed"],
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['logins.json'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for Firefox/Thunderbird backups related strings."
        ),
    ]


# ==============================================================================
# CODE AND SCRIPT FILES
# ==============================================================================

def get_code_and_script_rules() -> List[ClassifierRule]:
    """Rules for code and script files - placeholder for future expansion"""
    return [
        # Placeholder for future code scanning rules
    ]


# ==============================================================================
# INFRASTRUCTURE AS CODE
# ==============================================================================

def get_infrastructure_rules() -> List[ClassifierRule]:
    """Rules for infrastructure as code files"""
    return [
        ClassifierRule(
            rule_name="KeepInfraAsCodeByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.cscfg', '.ucs', '.tfvars'],
            triage=Triage.RED,
            description="Files with these extensions are very very interesting."
        ),
    ]


# ==============================================================================
# NETWORK DEVICE CONFIGS
# ==============================================================================

def get_network_config_rules() -> List[ClassifierRule]:
    """Rules for network device configuration files"""
    return [
        ClassifierRule(
            rule_name="KeepNetConfigFileByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['running-config.cfg', 'startup-config.cfg', 'running-config', 'startup-config'],
            triage=Triage.BLACK,
            description="Files with these exact names are very very interesting."
        ),
    ]


# ==============================================================================
# CYBERARK FILES
# ==============================================================================

def get_cyberark_rules() -> List[ClassifierRule]:
    """Rules for CyberArk configuration and credential files"""
    return [
        ClassifierRule(
            rule_name="KeepCyberArkConfigsByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['Psmapp.cred', 'psmgw.cred', 'backup.key', 'MasterReplicationUser.pass', 'RecPrv.key',
                      'ReplicationUser.pass', 'Server.key', 'VaultEmergency.pass', 'VaultUser.pass',
                      'Vault.ini', 'PADR.ini', 'PARAgent.ini', 'CACPMScanner.exe.config',
                      'PVConfiguration.xml'],
            triage=Triage.BLACK,
            description="Files with these exact names are very very interesting."
        ),

        ClassifierRule(
            rule_name="KeepCyberArkByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.cred', '.pass'],
            triage=Triage.RED,
            description="Files with these extensions are QUITE interesting."
        ),
    ]


# ==============================================================================
# FTP SERVER/CLIENT CONFIGS
# ==============================================================================

def get_ftp_rules() -> List[ClassifierRule]:
    """Rules for FTP server and client configurations"""
    return [
        ClassifierRule(
            rule_name="KeepFtpServerConfigByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['proftpdpasswd', 'filezilla.xml'],
            triage=Triage.RED,
            description="Files with these exact names are very interesting."
        ),

        ClassifierRule(
            rule_name="KeepFtpClientConfigConfigByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['recentservers.xml', 'sftp-config.json'],
            triage=Triage.RED,
            description="Files with these exact names are very interesting."
        ),
    ]


# ==============================================================================
# KERBEROS CREDENTIALS
# ==============================================================================

def get_kerberos_rules() -> List[ClassifierRule]:
    """Rules for Kerberos credential files"""
    return [
        ClassifierRule(
            rule_name="KeepKerberosCredentialsByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.keytab', '.CCACHE'],
            triage=Triage.YELLOW,
            description="Files with these extensions are interesting."
        ),

        ClassifierRule(
            rule_name="KeepKerberosCredentialsByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.REGEX,
            wordlist=['krb5cc_.*'],
            triage=Triage.YELLOW,
            description="Files with these names are interesting."
        ),
    ]


# ==============================================================================
# DEPLOYMENT IMAGES
# ==============================================================================

def get_deploy_image_rules() -> List[ClassifierRule]:
    """Rules for deployment images"""
    return [
        ClassifierRule(
            rule_name="KeepDeployImageByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.wim', '.ova', '.ovf'],
            triage=Triage.YELLOW,
            description="Files with these extensions are a little interesting."
        ),
    ]


# ==============================================================================
# MEMORY DUMPS
# ==============================================================================

def get_memory_dump_rules() -> List[ClassifierRule]:
    """Rules for memory dump files"""
    return [
        ClassifierRule(
            rule_name="KeepMemDumpByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.dmp'],
            triage=Triage.RED,
            description="Files with these extensions are a little interesting."
        ),

        ClassifierRule(
            rule_name="KeepMemDumpByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['MEMORY.DMP', 'hiberfil.sys', 'lsass.dmp', 'lsass.exe.dmp'],
            triage=Triage.BLACK,
            description="Files with these exact names are very very interesting."
        ),
    ]


# ==============================================================================
# PCAP FILES
# ==============================================================================

def get_pcap_rules() -> List[ClassifierRule]:
    """Rules for packet capture files"""
    return [
        ClassifierRule(
            rule_name="KeepPcapByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.pcap', '.cap', '.pcapng'],
            triage=Triage.YELLOW,
            description="Files with these extensions are a little interesting."
        ),
    ]


# ==============================================================================
# DEFENDER CONFIGS
# ==============================================================================

def get_defender_rules() -> List[ClassifierRule]:
    """Rules for Microsoft Defender configuration files"""
    return [
        ClassifierRule(
            rule_name="KeepDefenderConfigByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['SensorConfiguration.json', 'mdatp_managed.json'],
            triage=Triage.YELLOW,
            description="Files containing Defender Configs are very interesting."
        ),
    ]


# ==============================================================================
# SCCM AND DOMAIN JOIN
# ==============================================================================

def get_sccm_rules() -> List[ClassifierRule]:
    """Rules for SCCM and domain join credential files"""
    return [
        ClassifierRule(
            rule_name="KeepDomainJoinCredsByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['customsettings.ini'],
            triage=Triage.YELLOW,
            description="Files containing Domain Join Credes are quite interesting."
        ),

        ClassifierRule(
            rule_name="KeepDomainJoinCredsByPath",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_PATH,
            wordlist_type=MatchListType.CONTAINS,
            wordlist=['control/customsettings.ini'],
            triage=Triage.RED,
            description="Files with a path containing these strings are very interesting."
        ),

        ClassifierRule(
            rule_name="KeepSCCMBootVarCredsByPath",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_PATH,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'/REMINST/SMSTemp/.*\.var',
                r'/SMS/data/Variables\.dat',
                r'/SMS/data/Policy\.xml',
            ],
            triage=Triage.RED,
            description="Files with a path containing these strings are very interesting."
        ),

    ]


# ==============================================================================
# CONTENT GREP RULES
# ==============================================================================

def get_content_grep_rules() -> List[ClassifierRule]:
    """Rules for grepping file contents"""
    return [
        # C# Database Connection Strings
        ClassifierRule(
            rule_name="KeepCSharpDbConnStringsYellow",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'Data Source=.+Integrated Security=(SSPI|true)',
                r'Integrated Security=(SSPI|true);.*Data Source=.+'
            ],
            triage=Triage.YELLOW,
            description="Match SQL connection strings that appear to use integrated security (so no passwords)."
        ),

        ClassifierRule(
            rule_name="KeepCSharpDbConnStringsRed",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'Data Source=.+(;|)Password=.+(;|)',
                r'Password=.+(;|)Data Source=.+(;|)'],
            triage=Triage.RED,
            description="Match SQL connection strings that appear to have a password."
        ),

        # ASP.NET Viewstate Keys
        ClassifierRule(
            rule_name="KeepCSharpViewstateKeys",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'validationkey\s*=\s*[\'"][^\'"]....',
                r'decryptionkey\s*=\s*[\'"][^\'"]....'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # Command Line Credentials
        ClassifierRule(
            rule_name="KeepCmdCredentials",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'passwo?r?d\s*=\s*[\'"][^\'"]{4,}',
                r'schtasks.{1,300}(/rp\s+|/p\s+)',
                r'\bnet user\b',
                r'psexec .{0,100} -p\s+',
                r'net use .{0,300} /user:',
                r'\bcmdkey\b'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # Java Database Connection Strings
        ClassifierRule(
            rule_name="KeepJavaDbConnStrings",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'\.getConnection\(\"jdbc\:',
                r'passwo?r?d\s*=\s*[\'"][^\'"]....'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # AWS Keys in Code
        ClassifierRule(
            rule_name="KeepAwsKeysInCode",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'aws[_\-\.]?key',
                r'(\s|\'|"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z2-7]{12,16}(\s|\'|"|$)'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # Database Connection String with Password
        ClassifierRule(
            rule_name="KeepDbConnStringPw",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'connectionstring.{1,200}passw'
            ],
            triage=Triage.YELLOW,
            description="Files with contents matching these regexen are very interesting."
        ),

        # Inline Private Keys
        ClassifierRule(
            rule_name="KeepInlinePrivateKey",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # Password or Key in Code
        ClassifierRule(
            rule_name="KeepPassOrKeyInCode",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'passw?o?r?d\s*=\s*[\'"][^\'"]....',
                r'api[Kk]ey\s*=\s*[\'"][^\'"]....',
                r'passw?o?r?d?>\s*[^\s<]+\s*<',
                r'passw?o?r?d?>.{3,2000}</pass',
                r'[\s]+-passw?o?r?d?',
                r'api[kK]ey>\s*[^\s<]+\s*<',
                r'[_\-\.]oauth\s*=\s*[\'"][^\'"]....',
                r'client_secret\s*=*\s*',
                r'<ExtendedMatchKey>ClientAuth',
                r'GIUserPassword'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # S3 URI Prefix in Code
        ClassifierRule(
            rule_name="KeepS3UriPrefixInCode",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r's3[a]?:\/\/[a-zA-Z0-9\-\+\/]{2,16}'
            ],
            triage=Triage.YELLOW,
            description="Files with content matching an AWS S3 or Apache Hadoop S3A URI Prefix"
        ),

        # Slack Tokens in Code
        ClassifierRule(
            rule_name="KeepSlackTokensInCode",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
                r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # SQL Account Creation
        ClassifierRule(
            rule_name="KeepSqlAccountCreation",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # PHP Database Connection Strings
        ClassifierRule(
            rule_name="KeepPhpDbConnStrings",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'mysql_connect\s*\(.*\$.*\)',
                r'mysql_pconnect\s*\(.*\$.*\)',
                r'mysql_change_user\s*\(.*\$.*\)',
                r'pg_connect\s*\(.*\$.*\)',
                r'pg_pconnect\s*\(.*\$.*\)'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # Perl Database Connection Strings
        ClassifierRule(
            rule_name="KeepPerlDbConnStrings",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'DBI\-\>connect\('
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # PowerShell Credentials
        ClassifierRule(
            rule_name="KeepPsCredentials",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'-SecureString',
                r'-AsPlainText',
                r'\[Net\.NetworkCredential\]::new\('
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # Python Database Connection Strings
        ClassifierRule(
            rule_name="KeepPyDbConnStrings",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'mysql\.connector\.connect\(',
                r'psycopg2\.connect\('
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # Ruby Database Connection Strings
        ClassifierRule(
            rule_name="KeepRubyDbConnStrings",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'DBI\.connect\('
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # Unattend.xml Passwords
        ClassifierRule(
            rule_name="KeepUnattendXmlRegexRed",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'(?s)<AdministratorPassword>.{0,30}<Value>.*<\/Value>',
                r'(?s)<AutoLogon>.{0,30}<Value>.*<\/Value>'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),

        # Network Config Credentials
        ClassifierRule(
            rule_name="KeepNetConfigCreds",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'NVRAM config last updated',
                r'enable password \.',
                r'simple-bind authenticated encrypt',
                r'pac key [0-7] ',
                r'snmp-server community\s.+\sRW'
            ],
            triage=Triage.RED,
            description="A description of what a rule does."
        ),

        # Firefox Encrypted Passwords
        ClassifierRule(
            rule_name="KeepFFRegexRed",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=[
                r'"encryptedPassword"\s*:\s*"[A-Za-z0-9+/=]+"'
            ],
            triage=Triage.RED,
            description="Files with contents matching these regexes are very interesting."
        ),

        # RDP Passwords
        ClassifierRule(
            rule_name="KeepRdpPasswords",
            enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.FILE_CONTENT_AS_STRING,
            wordlist_type=MatchListType.REGEX,
            wordlist=['password 51\\:b'],
            triage=Triage.RED,
            description="Files with contents matching these regexen are very interesting."
        ),
    ]


# ==============================================================================
# RELAY RULES (FILE EXTENSION -> CONTENT GREP)
# ==============================================================================

def get_relay_rules() -> List[ClassifierRule]:
    """Relay rules that trigger content grepping based on file type"""
    return [
        # C# and ASP.NET files
        ClassifierRule(
            rule_name="RelayCSharpByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepCSharpDbConnStringsYellow",
                                "KeepCSharpDbConnStringsRed",
                                "KeepCSharpViewstateKeys",
                                "KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation",
                                "KeepDbConnStringPw"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.aspx', '.ashx', '.asmx', '.asp', '.cshtml',
                      '.cs', '.ascx', '.config'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for CSharp and ASP.NET related strings."
        ),

        # PowerShell files
        ClassifierRule(
            rule_name="RelayPsByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepPsCredentials",
                                "KeepCmdCredentials",
                                "KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation",
                                "KeepDbConnStringPw"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.psd1', '.psm1', '.ps1'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for PowerShell related strings."
        ),

        # PowerShell history files
        ClassifierRule(
            rule_name="KeepPSHistoryByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepPsCredentials",
                                "KeepCmdCredentials",
                                "KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation",
                                "KeepDbConnStringPw"],
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['ConsoleHost_history.txt', 'Visual Studio Code Host_history.txt'],
            triage=Triage.GREEN,
            description="Files with these exact names will be searched for PowerShell related strings."
        ),

        # Python files
        ClassifierRule(
            rule_name="RelayPythonByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepPyDbConnStrings",
                                "KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation",
                                "KeepDbConnStringPw"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.py'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for python related strings."
        ),

        # Java files
        ClassifierRule(
            rule_name="RelayJavaByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepJavaDbConnStrings",
                                "KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation",
                                "KeepDbConnStringPw"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.jsp', '.do', '.java', '.cfm'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for Java and ColdFusion related strings."
        ),

        # PHP files
        ClassifierRule(
            rule_name="RelayPhpByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepPhpDbConnStrings",
                                "KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation",
                                "KeepDbConnStringPw"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.php', '.phtml', '.inc', '.php3', '.php5', '.php7'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for php related strings."
        ),

        # Ruby files
        ClassifierRule(
            rule_name="RelayRubyByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepRubyDbConnStrings",
                                "KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation",
                                "KeepDbConnStringPw"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.rb'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for Ruby related strings."
        ),

        # Perl files
        ClassifierRule(
            rule_name="RelayPerlByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepPerlDbConnStrings",
                                "KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation",
                                "KeepDbConnStringPw"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.pl'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for Perl related strings."
        ),

        # JavaScript/TypeScript files
        ClassifierRule(
            rule_name="RelayJsByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation",
                                "KeepDbConnStringPw"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.js', '.cjs', '.mjs', '.ts', '.tsx', '.ls', '.es6', '.es'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for JavaScript related strings."
        ),

        # VBScript files
        ClassifierRule(
            rule_name="RelayVBScriptByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepCmdCredentials",
                                "KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation",
                                "KeepDbConnStringPw",
                                "KeepCSharpDbConnStringsRed",
                                "KeepCSharpDbConnStringsYellow"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.vbs', '.vbe', '.wsf', '.wsc', '.asp', '.hta'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for VBScript related strings."
        ),

        # Batch/CMD files
        ClassifierRule(
            rule_name="RelayCmdByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepCmdCredentials",
                                "KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['.bat', '.cmd'],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for cmd.exe/batch file related strings."
        ),

        # Shell script files (by extension match on common dotfiles)
        ClassifierRule(
            rule_name="RelayShellScriptByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepAwsKeysInCode",
                                "KeepInlinePrivateKey",
                                "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode",
                                "KeepSqlAccountCreation"],
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=[
                '.netrc', '.exports', '.functions', '.extra', '.npmrc', '.env',
                '.bashrc', '.profile', '.zshrc',
                '.bash_history', '.zsh_history', '.sh_history',
                'zhistory', '.irb_history'
            ],
            triage=Triage.GREEN,
            description="Files with these extensions will be searched for Bash related strings."
        ),

        # Generic config files
        ClassifierRule(
            rule_name="RelayConfigByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepAwsKeysInCode", "KeepInlinePrivateKey", "KeepPassOrKeyInCode",
                                "KeepSlackTokensInCode", "KeepSqlAccountCreation", "KeepDbConnStringPw"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['\\.yaml', '\\.yml', '\\.toml', '\\.xml', '\\.json', '\\.config', '\\.ini',
                      '\\.inf', '\\.cnf', '\\.conf', '\\.properties', '\\.env', '\\.dist', '\\.txt',
                      '\\.sql', '\\.log', '\\.sqlite', '\\.sqlite3', '\\.fdb', '\\.tfvars'],
            triage=Triage.GREEN,
            description="Files with these extensions will be subjected to a generic search for keys and such."
        ),

        # Infrastructure config files
        ClassifierRule(
            rule_name="RelayInfraConfigByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepNetConfigCreds"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['\\.xml', '\\.json', '\\.config', '\\.ini', '\\.inf', '\\.cnf', '\\.conf', '\\.txt'],
            triage=Triage.GREEN,
            description="Files with these extensions will be subjected to a generic search for keys and such."
        ),

        # RDP files
        ClassifierRule(
            rule_name="RelayRdpByExtension",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepRdpPasswords"],
            match_location=MatchLocation.FILE_EXTENSION,
            wordlist_type=MatchListType.EXACT,
            wordlist=['\\.rdp'],
            triage=Triage.GREEN,
            description="Look inside .rdp files for actual values."
        ),

        # Unattend.xml files
        ClassifierRule(
            rule_name="RelayUnattendXml",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepUnattendXmlRegexRed"],
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['unattend\\.xml', 'Autounattend\\.xml'],
            triage=Triage.GREEN,
            description="Look inside unattend.xml files for actual values."
        ),

        # SSH private keys by filename ending
        ClassifierRule(
            rule_name="CertContentByEnding",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepInlinePrivateKey"],
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.ENDS_WITH,
            wordlist=['_rsa', '_dsa', '_ed25519', '_ecdsa'],
            triage=Triage.GREEN,
            description="Files ending like this will be grepped for private keys."
        ),

        # Network config files by name pattern
        ClassifierRule(
            rule_name="RelayNetConfigByName",
            enumeration_scope=EnumerationScope.FILE_ENUMERATION,
            match_action=MatchAction.RELAY,
            content_rule_names=["KeepNetConfigCreds"],
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.CONTAINS,
            wordlist=['cisco', 'router', 'firewall', 'switch'],
            triage=Triage.GREEN,
            description="Files with these name patterns will be searched for Cisco bits."
        ),
    ]


# ==============================================================================
# POST-MATCH DISCARD RULES
# ==============================================================================
# NOTE: These require PostMatch enumeration scope support in file_scanner.py
# ==============================================================================

def get_postmatch_rules() -> List[ClassifierRule]:
    """Post-match rules to filter out false positives after a match"""
    return [
        ClassifierRule(
            rule_name="DiscardPostMatchByName",
            enumeration_scope=EnumerationScope.POST_MATCH,
            match_action=MatchAction.DISCARD,
            match_location=MatchLocation.FILE_NAME,
            wordlist_type=MatchListType.EXACT,
            wordlist=['credentialprovider\\.idl', 'pspasswd64\\.exe', 'pspasswd\\.exe',
                      'psexec\\.exe', 'psexec64\\.exe'],
            triage=Triage.GREEN,
            description="Post-match check for specific filenames"
        ),

        ClassifierRule(
            rule_name="DiscardPostMatchByPath",
            enumeration_scope=EnumerationScope.POST_MATCH,
            match_action=MatchAction.DISCARD,
            match_location=MatchLocation.FILE_PATH,
            wordlist_type=MatchListType.CONTAINS,
            wordlist=['Windows Kits\\\\10', 'Git\\\\mingw64', 'Git\\\\usr\\\\lib',
                      'ProgramData\\\\Microsoft\\\\NetFramework\\\\BreadcrumbStore',
                      '\\.MSSQLSERVER\\\\MSSQL\\\\Binn\\\\Templates'],
            triage=Triage.GREEN,
            description="Post-match check for specific path elements"
        ),
    ]
