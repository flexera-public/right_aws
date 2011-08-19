require File.dirname(__FILE__) + '/test_helper.rb'

class TestElb < Test::Unit::TestCase

  STDOUT.sync = true
  BALANCER_NAME = 'right-aws-test-lb'

  def setup
    @elb = Rightscale::ElbInterface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key, :logger => Logger.new('/dev/null'))

    unless @elb.describe_load_balancers.detect { |lb| lb[:load_balancer_name] == BALANCER_NAME }
      @elb.create_load_balancer(BALANCER_NAME, %w[us-east-1b], [])
    end
    @lb = @elb.describe_load_balancers.detect { |lb| lb[:load_balancer_name] == BALANCER_NAME }
  end

  # At the end of the day when you want to shut down the test balancer:
  # * Uncomment this method.
  # * Comment out all test except one.
  # * Run this test file.
  #
  # def teardown
  #   @elb.delete_load_balancer BALANCER_NAME
  # end

  def test_00_describe_load_balancers
    items = @elb.describe_load_balancers
    assert items.is_a?(Array)
  end

  def test_description
    assert_match /^#{BALANCER_NAME}-\d+\.us-east-1\.elb\.amazonaws\.com$/, @lb[:dns_name]
  end

  def test_description_has_canonical_hosted_zone_name
    assert_match /^#{BALANCER_NAME}-\d+\.us-east-1\.elb\.amazonaws\.com$/, @lb[:canonical_hosted_zone_name]
  end

  def test_description_has_canonical_hosted_zone_name_id
    assert_match /^[A-Z0-9]+$/, @lb[:canonical_hosted_zone_name_id]
  end

end
