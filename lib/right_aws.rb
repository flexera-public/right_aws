#
# Copyright (c) 2007-2011 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

require 'benchmark'
require 'net/https'
require 'uri'
require 'time'
require "cgi"
require "base64"
require "openssl"
require "digest/sha1"

require 'right_http_connection'

require 'awsbase/version'
require 'awsbase/support'
require 'awsbase/benchmark_fix'
require 'awsbase/right_awsbase'

module RightAws
  autoload :AcfInterface, 'acf/right_acf_interface'
  autoload :AcwInterface, 'acw/right_acw_interface'
  autoload :AsInterface, 'as/right_as_interface'
  autoload :Ec2, 'ec2/right_ec2'
  autoload :ElbInterface, 'elb/right_elb_interface'
  autoload :EmrInterface, 'emr/right_emr_interface'
  autoload :IamInterface, 'iam/right_iam_interface'
  autoload :RdsInterface, 'rds/right_rds_interface'
  autoload :Route53Interface, 'route_53/right_route_53_interface'
  autoload :S3, 's3/right_s3'
  autoload :S3Interface, 's3/right_s3_interface'
  autoload :SdbInterface, 'sdb/right_sdb_interface'
  autoload :SnsInterface, 'sns/right_sns_interface'
  autoload :Sqs, 'sqs/right_sqs'
  autoload :SqsGen2, 'sqs/right_sqs_gen2'
  autoload :SqsGen2Interface, 'sqs/right_sqs_gen2_interface'
  autoload :SqsInterface, 'sqs/right_sqs_interface'
end

#-

# We also want everything available in the Rightscale namespace for backward
# compatibility reasons.
module Rightscale #:nodoc:
  include RightAws
  extend RightAws
end
