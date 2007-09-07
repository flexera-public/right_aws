# -*- ruby -*-

require 'rubygems'
require 'hoe'
require './lib/right_aws.rb'

Hoe.new('right_aws', RightAws::VERSION::STRING) do |p|
  p.rubyforge_name = 'rightaws'
  p.author = 'RightScale, Inc.'
  p.email = 'support@rightscale.com'
  p.summary = 'Interface classes for the Amazon EC2, SQS, and S3 Web Services'
  p.description = p.paragraphs_of('README.txt', 2..5).join("\n\n")
  p.url = p.paragraphs_of('README.txt', 0).first.split(/\n/)[1..-1]
  p.changes = p.paragraphs_of('History.txt', 0..1).join("\n\n")
  p.remote_rdoc_dir = "/right_aws_gem_doc"
  p.extra_deps = [['right_http_connection','>= 0.1.4']]
end

task :test do
  require './test/ts_right_aws'
end

# vim: syntax=Ruby
