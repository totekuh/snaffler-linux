# Chef Knife Configuration File

current_dir = File.dirname(__FILE__)
log_level                :info
log_location             STDOUT
node_name                "admin"
client_key               "#{current_dir}/admin.pem"
chef_server_url          "https://chef.company.com/organizations/myorg"
cookbook_path            ["#{current_dir}/../cookbooks"]

# AWS Configuration
knife[:aws_access_key_id] = "AKIAIOSFODNN7EXAMPLE"
knife[:aws_secret_access_key] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
knife[:region] = "us-east-1"
knife[:availability_zone] = "us-east-1a"

# SSH Configuration
knife[:ssh_user] = "ubuntu"
knife[:ssh_key_name] = "production-key"
knife[:identity_file] = "#{current_dir}/keys/production-key.pem"

# Bootstrap settings
knife[:bootstrap_version] = "14.12.9"
knife[:use_sudo] = true
