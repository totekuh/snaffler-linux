# CarrierWave Configuration for File Uploads

CarrierWave.configure do |config|
  # Use AWS S3 for production
  if Rails.env.production?
    config.fog_provider = 'fog/aws'
    config.fog_credentials = {
      provider:              'AWS',
      aws_access_key_id:     'AKIAI44QH8DHBEXAMPLE',
      aws_secret_access_key: 'je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY',
      region:                'us-west-2'
    }
    config.fog_directory  = 'myapp-production-uploads'
    config.fog_public     = false
    config.fog_attributes = { cache_control: "public, max-age=#{365.days.to_i}" }
  else
    # Use local storage for development and test
    config.storage = :file
    config.enable_processing = false if Rails.env.test?
  end

  # Azure Blob Storage alternative configuration
  # config.azure_storage_account_name = 'mystorageaccount'
  # config.azure_storage_access_key = 'base64encodedkey=='
  # config.azure_storage_blob_host = 'https://mystorageaccount.blob.core.windows.net'

  config.cache_dir = "#{Rails.root}/tmp/uploads"
end
