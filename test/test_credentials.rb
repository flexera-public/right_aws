class TestCredentials

  def self.aws_access_key_id
    ENV['RIGHT_AWS_TEST_ACCESS_KEY_ID']
  end
  def self.account_number
    ENV['RIGHT_AWS_TEST_ACCOUNT_NUMBER']
  end
  def self.aws_secret_access_key
    ENV['RIGHT_AWS_TEST_SECRET_ACCESS_KEY']
  end
end
