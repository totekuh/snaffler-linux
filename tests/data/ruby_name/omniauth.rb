# OmniAuth Configuration for OAuth Providers

Rails.application.config.middleware.use OmniAuth::Builder do
  # GitHub OAuth
  provider :github,
           'a1b2c3d4e5f6g7h8i9j0',
           'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
           scope: 'user,repo,gist'

  # Google OAuth 2.0
  provider :google_oauth2,
           '123456789-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com',
           'GOCSPX-1234567890abcdefghijklmno',
           {
             scope: 'userinfo.email,userinfo.profile',
             prompt: 'select_account',
             image_aspect_ratio: 'square',
             image_size: 50
           }

  # Facebook OAuth
  provider :facebook,
           '1234567890123456',
           'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
           scope: 'email,public_profile',
           info_fields: 'email,name,first_name,last_name'

  # Twitter OAuth
  provider :twitter,
           'CONSUMER_KEY_FROM_TWITTER',
           'CONSUMER_SECRET_FROM_TWITTER'

  # LinkedIn OAuth 2.0
  provider :linkedin,
           'client_id_from_linkedin',
           'client_secret_from_linkedin',
           scope: 'r_liteprofile r_emailaddress'

  # Microsoft Azure AD
  provider :azure_activedirectory_v2,
           client_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
           client_secret: 'client-secret-value-here',
           tenant_id: 'common'
end

# Additional OmniAuth settings
OmniAuth.config.allowed_request_methods = [:post, :get]
OmniAuth.config.silence_get_warning = true
