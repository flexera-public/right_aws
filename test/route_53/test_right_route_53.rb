require File.dirname(__FILE__) + '/test_helper.rb'

class TestRoute53 < Test::Unit::TestCase

  STDOUT.sync = true

  def setup
    @r53 = Rightscale::Route53Interface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key, :logger => Logger.new('/dev/null'))
    @zone_config = {:name => "right-aws.example.com.", :config => {:comment => 'a comment'}}
  end

  def teardown
    @r53.list_hosted_zones.each do |zone|
      next unless zone[:name] == @zone_config[:name]
      zone_id = zone[:aws_id]
      puts zone_id
      records = @r53.list_resource_record_sets(zone_id)[2..-1]
      unless records.empty?
        response = @r53.delete_resource_record_sets(zone_id, records)
        puts response.inspect
      end
      puts @r53.delete_hosted_zone(zone_id).inspect
    end
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
end
