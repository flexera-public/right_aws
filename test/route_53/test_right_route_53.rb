require File.dirname(__FILE__) + '/test_helper.rb'

class TestRoute53 < Test::Unit::TestCase

  STDOUT.sync = true
  BALANCER_NAME = 'right-aws-test-lb'

  def setup
    @r53 = Rightscale::Route53Interface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key, :logger => Logger.new('/dev/null'))
    @zone_config = {:name => "right-aws.example.com.", :config => {:comment => 'a comment'}}

    @elb = Rightscale::ElbInterface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key, :logger => Logger.new('/dev/null'))
  end

  def teardown
    @r53.list_hosted_zones.each do |zone|
      next unless zone[:name] == @zone_config[:name]
      zone_id = zone[:aws_id]
      puts zone_id
      records = @r53.list_resource_record_sets(zone_id)
      # The NS and SOA records are provided by AWS and must not be deleted
      records.reject! { |rr| %w[NS SOA].include? rr[:type] }
      if records.any?
        response = @r53.delete_resource_record_sets(zone_id, records)
        puts response.inspect
      end
      puts @r53.delete_hosted_zone(zone_id).inspect
    end
    # Uncomment to shut down at the end of the day.
    # @elb.delete_load_balancer BALANCER_NAME
  end

  def test_00_list_hosted_zones
    items = @r53.list_hosted_zones
    assert items.is_a?(Array)
  end

  def test_create_and_delete_zone
    response = @r53.create_hosted_zone(@zone_config)
    assert_equal response[:name], @zone_config[:name]
    assert response[:aws_id].is_a?(String)
    assert response[:name_servers].is_a?(Array)

    response2 = @r53.delete_hosted_zone(response[:aws_id])
    assert_equal response2[:status], 'PENDING'
  end

  def test_add_and_remove_A_record
    zone = @r53.create_hosted_zone(@zone_config)
    zone_id = zone[:aws_id]
    # add
    a_record = { :name => 'host.right-aws.example.com.', :type => 'A', :ttl => 600, :resource_records => ['10.0.0.1'] }
    response = @r53.create_resource_record_sets(zone_id, [a_record.dup]) # .dup since it will get :action => :create
    assert_equal response[:status], 'PENDING'

    # It should be there now
    records = @r53.list_resource_record_sets(zone_id)
    assert records.is_a?(Array)
    assert records.detect { |rr| rr == a_record }, "Could not find '#{a_record.inspect}' in '#{records.inspect}'"

    # remove
    response = @r53.delete_resource_record_sets(zone_id, [a_record.dup])
    assert_equal response[:status], 'PENDING'

    # It should not be there anymore
    records = @r53.list_resource_record_sets(zone_id)
    assert records.is_a?(Array)
    assert ! records.detect { |rr| rr == a_record }, "Record '#{a_record.inspect}' is still in '#{records.inspect}'"

    @r53.delete_hosted_zone(zone_id)
  end

  def test_add_and_remove_Alias_record
    lb = find_or_create_load_balancer

    zone = @r53.create_hosted_zone(@zone_config)
    zone_id = zone[:aws_id]

    # add
    alias_target = { :hosted_zone_id => lb[:canonical_hosted_zone_name_id], :dns_name => lb[:dns_name] }
    alias_record = { :name => 'right-aws.example.com', :type => 'A', :alias_target => alias_target }
    response = @r53.create_resource_record_sets(zone_id, [alias_record.dup]) # .dup since it will get :action => :create
    assert_equal response[:status], 'PENDING'

    # It should be there now
    records = @r53.list_resource_record_sets(zone_id)
    assert records.is_a?(Array)
    record = records.detect { |rr| rr[:alias_target] }
    assert record, "Could not find '#{alias_record.inspect}' in '#{records.inspect}'"
    # AWS adds final dots to names
    assert_equal "#{alias_record[:name]}.", record[:name]
    assert_equal "#{alias_target[:dns_name]}.", record[:alias_target][:dns_name]

    # remove
    response = @r53.delete_resource_record_sets(zone_id, [alias_record.dup])
    assert_equal response[:status], 'PENDING'

    # It should not be there anymore
    records = @r53.list_resource_record_sets(zone_id)
    assert records.is_a?(Array)
    record = records.detect { |rr| rr[:alias_target] }
    assert ! record, "Record '#{alias_record.inspect}' is still in '#{records.inspect}'"

    @r53.delete_hosted_zone(zone_id)
  end

  def find_or_create_load_balancer
    unless @elb.describe_load_balancers.detect { |lb| lb[:load_balancer_name] == BALANCER_NAME }
      @elb.create_load_balancer(BALANCER_NAME, %w[us-east-1b], [])
      puts "WARNING: Started load balancer.  Remember to shut it down (see teardown)."
      puts "NOTE: Tests might not pass during first few seconds after load balancer is created."
    end
    @elb.describe_load_balancers.detect { |lb| lb[:load_balancer_name] == BALANCER_NAME }
  end

  def test_rr_sets_to_xml
    a_record = { :name => 'host.right-aws.example.com.', :type => 'A', :ttl => 600, :resource_records => ['10.0.0.1'], :action => :create }
    expected = load_fixture('a_record.xml')
    assert_equal expected, @r53.resource_record_sets_to_xml([a_record], '')

    # Note final full stop
    alias_target = { :hosted_zone_id => 'Z1234567890123', :dns_name => 'example-load-balancer-1111111111.us-east-1.elb.amazonaws.com.' }
    alias_record = { :name => 'right-aws.example.com.', :type => 'A', :alias_target => alias_target, :action => :create }
    expected = load_fixture('alias_record.xml')
    assert_same_lines expected, @r53.resource_record_sets_to_xml([alias_record], '')
  end

  def load_fixture (name)
    File.read(File.join(File.dirname(__FILE__), 'fixtures', name))
  end

  def assert_same_lines (expected, actual)
    expected = expected.split "\n"
    actual   = actual.split "\n"
    previous = []
    while e = expected.shift and a = actual.shift
      assert_equal e, a, "After:\n#{previous.join("\n")}"
      previous << e
    end
  end
end
