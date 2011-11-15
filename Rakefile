# -*- ruby -*-

require 'rubygems'
require "rake/testtask"
require 'rake/gempackagetask'
require 'rake/clean'
$: << File.dirname(__FILE__)
testglobs =     ["test/ts_right_aws.rb"]

begin
  require 'bundler'
rescue LoadError => e
  STDERR.puts("Bundler is not available, some rake tasks will not be defined: #{e.message}")
else
  Bundler::GemHelper.install_tasks :name => 'right_aws'
end

begin
  require 'rcov/rcovtask'
rescue LoadError => e
  STDERR.puts("RCov is not available, some rake tasks will not be defined: #{e.message}")
else
  desc "Analyze code coverage of the unit tests."
  Rcov::RcovTask.new do |t|
    t.test_files = FileList[testglobs]
    #t.verbose = true     # uncomment to see the executed command
  end
end

# == Gem == #

gemtask = Rake::GemPackageTask.new(Gem::Specification.load("right_aws.gemspec")) do |package|
  package.package_dir = ENV['PACKAGE_DIR'] || 'pkg'
  package.need_zip = true
  package.need_tar = true
end

directory gemtask.package_dir

CLEAN.include(gemtask.package_dir)

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

desc "Test just the SNS interface"
task :testsns do
  require 'test/test_credentials'
  TestCredentials.get_credentials
  require 'test/sns/test_right_sns.rb'
end

desc "Test Route 53 interface"
task :testroute53 do
  require 'test/test_credentials'
  TestCredentials.get_credentials
  require 'test/route_53/test_right_route_53'
end

desc "Test ELB interface"
task :testelb do
  require 'test/test_credentials'
  TestCredentials.get_credentials
  require 'test/elb/test_right_elb'
end

# vim: syntax=Ruby
