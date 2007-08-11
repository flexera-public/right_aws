require File.dirname(__FILE__) + '/test_helper.rb'
require 'pp'

class TestT < Test::Unit::TestCase

    # Please, change the constants below to your own AWS credentials
  
  USER_AWS_ID           = 'xxxxxxxxxxxx'
  AWS_ACCESS_KEY_ID     = 'xxxxxxxxxxxxxxxxxxxx'
  AWS_SECRET_ACCESS_KEY = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
  
    # Some of RightEc2 instance methods concerning instance launching and image registration
    # are not tested here due to their potentially risk.
  
  def setup
    @ec2   = Rightscale::Ec2.new(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    @key   = 'right_ec2_awesome_test_key'
    @group = 'right_ec2_awesome_test_security_group'
  end
  
  def test_01_create_describe_key_pairs
    new_key = @ec2.create_key_pair(@key)
    assert new_key[:aws_material][/BEGIN RSA PRIVATE KEY/], "New key material is abcent"
    keys = @ec2.describe_key_pairs
    assert keys.map{|key| key[:aws_key_name] }.include?(@key), "#{@key} must exist"
  end
  
  def test_02_create_security_group
    assert @ec2.create_security_group(@group,'My awesone test group'), 'Create_security_group fail'
    group = @ec2.describe_security_groups([@group])[0]
    assert_equal @group, group[:aws_group_name], 'Group must be created but does not exist'
  end
  
  def test_03_perms_add
    assert @ec2.authorize_security_group_named_ingress(@group, USER_AWS_ID, 'default')
    assert @ec2.authorize_security_group_IP_ingress(@group, 80,80,'udp','192.168.1.0/8')
  end
  
  def test_04_check_new_perms_exist
    assert_equal 2, @ec2.describe_security_groups([@group])[0][:aws_perms].size
  end

  def test_05_perms_remove
    assert @ec2.revoke_security_group_IP_ingress(@group, 80,80,'udp','192.168.1.0/8')
    assert @ec2.revoke_security_group_named_ingress(@group, USER_AWS_ID, 'default')
  end

  def test_06_describe_images
    images = @ec2.describe_images
    assert images.size>0, 'Amazon must have at least some public images'
      # unknown image
    assert_raise(Rightscale::AwsError){ @ec2.describe_images(['ami-ABCDEFGH'])}
  end

  def test_07_describe_instanses
    assert @ec2.describe_instances
      # unknown image
    assert_raise(Rightscale::AwsError){ @ec2.describe_instances(['i-ABCDEFGH'])}
  end

  def test_08_delete_securiry_group
    assert @ec2.delete_security_group(@group), 'Delete_security_group fail'
  end
  
  def test_09_delete_key_pair
    assert @ec2.delete_key_pair(@key), 'Delete_key_pair fail'
      # key must be deleted already
    assert_raise(Rightscale::AwsError) { @ec2.delete_key_pair(@key) }
  end
  
end
