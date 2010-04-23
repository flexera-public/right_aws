#
# Copyright (c) 2007-2008 RightScale Inc
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
require "rexml/document"
require "openssl"
require "digest/sha1"

require 'rubygems'
require 'right_http_connection'

$:.unshift(File.dirname(__FILE__))
require 'awsbase/benchmark_fix'
require 'awsbase/support'
require 'awsbase/right_awsbase'
require 'ec2/right_ec2'
require 'ec2/right_ec2_images'
require 'ec2/right_ec2_instances'
require 'ec2/right_ec2_security_groups'
require 'ec2/right_ec2_spot_instances'
require 'ec2/right_ec2_ebs'
require 'ec2/right_ec2_reserved_instances'
require 'ec2/right_ec2_vpc'
require 'ec2/right_ec2_monitoring'
require 'elb/right_elb_interface'
require 'acw/right_acw_interface'
require 'as/right_as_interface'
require 's3/right_s3_interface'
require 's3/right_s3'
require 'sqs/right_sqs_interface'
require 'sqs/right_sqs'
require 'sqs/right_sqs_gen2_interface'
require 'sqs/right_sqs_gen2'
require 'sdb/right_sdb_interface'
require 'acf/right_acf_interface'
require 'acf/right_acf_streaming_interface'
require 'acf/right_acf_origin_access_identities'
require 'rds/right_rds_interface'


module RightAws #:nodoc:
  module VERSION #:nodoc:
    MAJOR = 2  unless defined?(MAJOR)
    MINOR = 0 unless defined?(MINOR)
    TINY  = 0  unless defined?(TINY)

    STRING = [MAJOR, MINOR, TINY].join('.') unless defined?(STRING)
  end
end

#-

# We also want everything available in the Rightscale namespace for backward
# compatibility reasons.
module Rightscale #:nodoc:
  include RightAws
  extend RightAws
end
