# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{right_aws}
  s.version = "2.0.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["RightScale, Inc."]
  s.date = %q{2010-09-15}
  s.description = %q{== DESCRIPTION:

The RightScale AWS gems have been designed to provide a robust, fast, and secure interface to Amazon EC2, EBS, S3, SQS, SDB, and CloudFront. 
These gems have been used in production by RightScale since late 2006 and are being maintained to track enhancements made by Amazon. 
The RightScale AWS gems comprise:

- RightAws::Ec2 -- interface to Amazon EC2 (Elastic Compute Cloud), VPC (Virtual Private Cloud) and the associated EBS (Elastic Block Store)
- RightAws::S3 and RightAws::S3Interface -- interface to Amazon S3 (Simple Storage Service)
- RightAws::Sqs and RightAws::SqsInterface -- interface to first-generation Amazon SQS (Simple Queue Service)
- RightAws::SqsGen2 and RightAws::SqsGen2Interface -- interface to second-generation Amazon SQS (Simple Queue Service)
- RightAws::SdbInterface and RightAws::ActiveSdb -- interface to Amazon SDB (SimpleDB)
- RightAws::AcfInterface -- interface to Amazon CloudFront, a content distribution service
- RightAws::AsInterface  -- interface to Amazon Auto Scaling
- RightAws::AcwInterface -- interface to Amazon Cloud Watch
- RightAws::ElbInterface -- interface to Amazon Elastic Load Balancer
- RightAws::RdsInterface -- interface to Amazon RDS instances

== FEATURES:}
  s.email = %q{support@rightscale.com}
  s.extra_rdoc_files = ["History.txt", "Manifest.txt", "README.txt"]
  s.files = ["History.txt", "Manifest.txt", "README.txt", "Rakefile", "lib/awsbase/benchmark_fix.rb", "lib/awsbase/right_awsbase.rb", "lib/awsbase/support.rb", "lib/ec2/right_ec2.rb", "lib/ec2/right_ec2_images.rb", "lib/ec2/right_ec2_instances.rb", "lib/ec2/right_ec2_security_groups.rb", "lib/ec2/right_ec2_spot_instances.rb", "lib/ec2/right_ec2_ebs.rb", "lib/ec2/right_ec2_reserved_instances.rb", "lib/ec2/right_ec2_vpc.rb", "lib/ec2/right_ec2_monitoring.rb", "lib/right_aws.rb", "lib/s3/right_s3.rb", "lib/acw/right_acw_interface.rb", "lib/elb/right_elb_interface.rb", "lib/as/right_as_interface.rb", "lib/s3/right_s3_interface.rb", "lib/sdb/active_sdb.rb", "lib/sdb/right_sdb_interface.rb", "lib/sqs/right_sqs.rb", "lib/sqs/right_sqs_gen2.rb", "lib/sqs/right_sqs_gen2_interface.rb", "lib/sqs/right_sqs_interface.rb", "lib/acf/right_acf_interface.rb", "lib/acf/right_acf_streaming_interface.rb", "lib/acf/right_acf_origin_access_identities.rb", "lib/rds/right_rds_interface.rb", "test/ec2/test_helper.rb", "test/ec2/test_right_ec2.rb", "test/http_connection.rb", "test/s3/test_helper.rb", "test/s3/test_right_s3.rb", "test/s3/test_right_s3_stubbed.rb", "test/sdb/test_active_sdb.rb", "test/sdb/test_helper.rb", "test/sdb/test_right_sdb.rb", "test/sqs/test_helper.rb", "test/sqs/test_right_sqs.rb", "test/sqs/test_right_sqs_gen2.rb", "test/test_credentials.rb", "test/ts_right_aws.rb", "test/acf/test_helper.rb", "test/acf/test_right_acf.rb", "test/rds/test_helper.rb", "test/rds/test_right_rds.rb"]
  s.rdoc_options = ["--main", "README.txt"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{rightaws}
  s.rubygems_version = %q{1.3.7}
  s.summary = %q{Interface classes for the Amazon EC2, SQS, and S3 Web Services}
  s.test_files = ["test/ts_right_aws.rb"]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<right_http_connection>, [">= 1.2.1"])
      s.add_development_dependency(%q<rubyforge>, [">= 2.0.4"])
      s.add_development_dependency(%q<hoe>, [">= 2.6.2"])
    else
      s.add_dependency(%q<right_http_connection>, [">= 1.2.1"])
      s.add_dependency(%q<rubyforge>, [">= 2.0.4"])
      s.add_dependency(%q<hoe>, [">= 2.6.2"])
    end
  else
    s.add_dependency(%q<right_http_connection>, [">= 1.2.1"])
    s.add_dependency(%q<rubyforge>, [">= 2.0.4"])
    s.add_dependency(%q<hoe>, [">= 2.6.2"])
  end
end
