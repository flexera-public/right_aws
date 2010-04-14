# -*- ruby -*-

require 'rubygems'
require "rake/testtask"
require 'rcov/rcovtask'
$: << File.dirname(__FILE__)
require 'lib/right_aws.rb'

testglobs =     ["test/ts_right_aws.rb"]

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "icehouse-right_aws"
    gem.summary = "Interface classes for the Amazon EC2, SQS, and S3 Web Services"
    gem.email = "support@rightscale.com"
    gem.homepage = "http://github.com/icehouse/right_aws"
    gem.authors = ["RightScale, Inc."]
    gem.files =  Dir["[A-Z]*", "lib/**/*"]
    
    gem.add_dependency('right_http_connection',  '>= 1.2.1')
  end
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end

desc "Analyze code coverage of the unit tests."
Rcov::RcovTask.new do |t|
  t.test_files = FileList[testglobs]
  #t.verbose = true     # uncomment to see the executed command
end
 
desc "Test just the SQS interface"
task :testsqs do
  require 'test/test_credentials'
  require 'test/http_connection'
  TestCredentials.get_credentials
  require 'test/sqs/test_right_sqs.rb'
end

desc "Test just the second generation SQS interface"
task :testsqs2 do
  require 'test/test_credentials'
  require 'test/http_connection'
  TestCredentials.get_credentials
  require 'test/sqs/test_right_sqs_gen2.rb'
end

desc "Test just the S3 interface"
task :tests3 do
  require 'test/test_credentials'
  require 'test/http_connection'
  TestCredentials.get_credentials
  require 'test/s3/test_right_s3.rb'
end

desc "Test just the S3 interface using local stubs"
task :tests3local do
  require 'test/test_credentials'
  require 'test/http_connection'
  TestCredentials.get_credentials
  require 'test/s3/test_right_s3_stubbed.rb'
end

desc "Test just the EC2 interface"
task :testec2 do
  require 'test/test_credentials'
  TestCredentials.get_credentials
  require 'test/ec2/test_right_ec2.rb'
end

desc "Test just the SDB interface"
task :testsdb do
  require 'test/test_credentials'
  TestCredentials.get_credentials
  require 'test/sdb/test_right_sdb.rb'
end

desc "Test active SDB interface"
task :testactivesdb do
  require 'test/test_credentials'
  TestCredentials.get_credentials
  require 'test/sdb/test_active_sdb.rb'
end

desc "Test CloudFront interface"
task :testacf do
  require 'test/test_credentials'
  TestCredentials.get_credentials
  require 'test/acf/test_right_acf.rb'
end

desc "Test RDS interface"
task :testrds do
  require 'test/test_credentials'
  TestCredentials.get_credentials
  require 'test/rds/test_right_rds.rb'
end

# vim: syntax=Ruby
