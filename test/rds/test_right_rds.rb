require File.dirname(__FILE__) + '/test_helper.rb'

class TestRds < Test::Unit::TestCase

  STDOUT.sync = true

  TEST_SG_NAME = 'RightRdsSGTest0123456789'

  def setup
    @rds = Rightscale::RdsInterface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key, :logger => Logger.new('/dev/null'))
  end

  def test_00_instances
    assert_nothing_raised do
      items = @rds.describe_db_instances
      assert items.is_a?(Array)
    end
    #
    assert_nothing_raised do
      @rds.describe_db_instances do |response|
        assert response.is_a?(Hash)
        assert response[:db_instances].is_a?(Array)
      end
    end
  end

  def test_10_security_groups
    assert_nothing_raised do
      items = @rds.describe_db_security_groups
      assert items.is_a?(Array)
    end
    #
    assert_nothing_raised do
      @rds.describe_db_security_groups do |response|
        assert response.is_a?(Hash)
        assert response[:db_security_groups].is_a?(Array)
      end
    end
  end

  def test_11_remove_security_group
    @rds.delete_db_security_group rescue nil
  end

  def test_12_create_security_group
    sg = nil
    assert_nothing_raised do
      sg = @rds.create_db_security_group(TEST_SG_NAME, 'sg-description')
    end
    assert sg.is_a?(Hash)
  end

  def test_13_authorize
    assert_nothing_raised do
      sg = @rds.authorize_db_security_group_ingress(TEST_SG_NAME, :cidrip => '131.0.0.1/8')
      assert sg.is_a?(Hash)
      assert_equal 1, sg[:ip_ranges].size
    end
    assert_nothing_raised do
      sg = @rds.authorize_db_security_group_ingress(TEST_SG_NAME, :ec2_security_group_owner => '826693181925',
                                                                  :ec2_security_group_name  => 'default' )
      assert sg.is_a?(Hash)
      assert_equal 1, sg[:ec2_security_groups].size
    end
    sleep 30
  end

  def test_14_revoke
    assert_nothing_raised do
      sg = @rds.revoke_db_security_group_ingress(TEST_SG_NAME, :cidrip => '131.0.0.1/8')
      assert sg.is_a?(Hash)
    end
    assert_nothing_raised do
      sg = @rds.revoke_db_security_group_ingress(TEST_SG_NAME, :ec2_security_group_owner => '826693181925',
                                                               :ec2_security_group_name  => 'default' )
      assert sg.is_a?(Hash)
    end
    sleep 30
    #
    sg = @rds.describe_db_security_groups(TEST_SG_NAME).first
    assert_equal 0, sg[:ip_ranges].size
    assert_equal 0, sg[:ec2_security_groups].size
  end

  def test_15_delete_security_group
    assert_nothing_raised do
      @rds.delete_db_security_group(TEST_SG_NAME)
    end
  end


  def test_20_db_snapshots
    assert_nothing_raised do
      items = @rds.describe_db_snapshots
      assert items.is_a?(Array)
    end
    #
    assert_nothing_raised do
      @rds.describe_db_snapshots do |response|
        assert response.is_a?(Hash)
        assert response[:db_snapshots].is_a?(Array)
      end
    end
  end

  def test_30_events
    assert_nothing_raised do
      items = @rds.describe_events
      assert items.is_a?(Array)
    end
    #
    assert_nothing_raised do
      @rds.describe_events do |response|
        assert response.is_a?(Hash)
        assert response[:events].is_a?(Array)
      end
    end
  end

end
