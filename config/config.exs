import Config

config :aws_creds,
  default_region: "ca-central-1",
  locations: [:instance_role]
  # profiles: [
  #   default: %{access_key_id: "HI", secret_access_key: "SECRET_KEY", default_region: "a region"}
  # ]

#    locations: [:app_env],
#   #
