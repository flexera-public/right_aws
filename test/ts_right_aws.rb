require 'test/unit'
require 'test_credentials'
TestCredentials.get_credentials

require 'awsbase/test_right_awsbase.rb'
require 'ec2/test_right_ec2.rb'
require 's3/test_right_s3.rb'
require 'sqs/test_right_sqs.rb'

