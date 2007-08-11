require File.dirname(__FILE__) + '/test_helper.rb'

class TestT < Test::Unit::TestCase

    # Please, change the constants below to your own AWS credentials

  RIGHT_OBJECT_TEXT     = 'Right test message'
  AWS_ACCESS_KEY_ID     = 'XXXXXXXXXXXXXXXXXXXX'
  AWS_SECRET_ACCESS_KEY = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
  
  def setup
    @s3     = Rightscale::S3Interface.new(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    @bucket = 'right_s3_awesome_test_bucket'
    @key1   = 'test/woohoo1'
    @key2   = 'test1/key/woohoo2'
    @s      = Rightscale::S3.new(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
  end

  #---------------------------
  # Rightscale::S3Interface
  #---------------------------
  
  def test_01_create_bucket
    assert @s3.create_bucket(@bucket), 'Create_bucket fail'
  end

  def test_02_list_all_my_buckets
    assert @s3.list_all_my_buckets.map{|bucket| bucket[:name]}.include?(@bucket), "#{@bucket} must exist in bucket list"
  end

  def test_03_list_empty_bucket
    assert_equal 0, @s3.list_bucket(@bucket).size, "#{@queue_name} must exist!"
  end
  
  def test_04_put
    assert @s3.put(@bucket, @key1, RIGHT_OBJECT_TEXT, 'x-amz-meta-family'=>'Woohoo1!'), 'Put bucket fail'
    assert @s3.put(@bucket, @key2, RIGHT_OBJECT_TEXT, 'x-amz-meta-family'=>'Woohoo2!'), 'Put bucket fail'
  end
  
  def test_05_get_and_get_object
    assert_raise(Rightscale::AwsError) { @s3.get(@bucket, 'undefined/key') }
    data1 = @s3.get(@bucket, @key1)
    assert_equal RIGHT_OBJECT_TEXT, data1[:object], "Object text must be equal to '#{RIGHT_OBJECT_TEXT}'"
    assert_equal RIGHT_OBJECT_TEXT, @s3.get_object(@bucket, @key1), "Get_object text must return '#{RIGHT_OBJECT_TEXT}'"
    assert_equal 'Woohoo1!', data1[:headers]['x-amz-meta-family'], "x-amz-meta-family header must be equal to 'Woohoo1!'"
  end
  
  def test_06_head
    assert_equal 'Woohoo1!', @s3.head(@bucket,@key1)['x-amz-meta-family'], "x-amz-meta-family header must be equal to 'Woohoo1!'"
  end
  
  def test_07_delete_folder
    assert_equal 1, @s3.delete_folder(@bucket, 'test').size, "Only one key(#{@key1}) must be deleted!"
  end

  def test_08_delete_bucket
    assert_raise(Rightscale::AwsError) { @s3.delete_bucket(@bucket) }
    assert @s3.clear_bucket(@bucket), 'Clear_bucket fail'
    assert_equal 0, @s3.list_bucket(@bucket).size, 'Bucket must be empty'
    assert @s3.delete_bucket(@bucket)
    assert !@s3.list_all_my_buckets.map{|bucket| bucket[:name]}.include?(@bucket), "#{@bucket} must not exist"
  end

  #---------------------------
  # Rightscale::S3 classes
  #---------------------------

  def test_20_s3
      # create bucket
    bucket = @s.bucket(@bucket, true)
    assert bucket
      # check that the bucket exists
    assert @s.buckets.map{|b| b.name}.include?(@bucket)
      # delete bucket
    assert bucket.clear
    assert bucket.delete
  end

  def test_21_bucket_create_put_get_key
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, true)
      # check that the bucket exists
    assert @s.buckets.map{|b| b.name}.include?(@bucket)
    assert bucket.keys.empty?
      # put data
    assert bucket.put(@key1, RIGHT_OBJECT_TEXT, {'family'=>'123456'})
      # get data and compare
    assert_equal RIGHT_OBJECT_TEXT, bucket.get(@key1)
      # get key object
    key = bucket.key(@key1, true)
    assert_equal Rightscale::S3::Key, key.class
    assert       key.exists?
    assert_equal '123456', key.meta_headers['family']
  end

  def test_22_keys
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
      # create first key
    key1 = Rightscale::S3::Key.create(bucket, @key1)
    key1.refresh
    assert key1.exists?
    assert_equal '123456', key1.meta_headers['family']
      # create second key
    key2 = Rightscale::S3::Key.create(bucket, @key2)
    assert !key2.refresh
    assert !key2.exists?
    assert_raise(Rightscale::AwsError) { key2.head }
      # store key
    key2.meta_headers = {'family'=>'111222333'}
    assert key2.put(RIGHT_OBJECT_TEXT)
      # make sure that the key exists
    assert key2.refresh
    assert key2.exists?
    assert key2.head
      # get its data
    assert_equal RIGHT_OBJECT_TEXT, key2.get
      # drop key
    assert key2.delete
    assert !key2.exists?
  end
  
  def test_23_clear_delete
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
      # add another key
    bucket.put(@key2, RIGHT_OBJECT_TEXT)
      # delete 'folder'
    assert_equal 1, bucket.delete_folder(@key1).size
      # delete
    assert_raise(Rightscale::AwsError) { bucket.delete }
    bucket.delete(true)
  end

    # Grantees
    
  def test_30_create_bucket
    bucket = @s.bucket(@bucket, true, 'public-read')
    assert bucket
  end
  
  def test_31_list_grantees
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
      # get grantees list
    grantees = bucket.grantees
      # check that the grantees count equal to 2 (root, AllUsers)
    assert_equal 2, grantees.size
  end
  
  def test_32_grant_revoke_drop
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
    grantees = bucket.grantees
      # Take one of grantees
    grantee = grantees[0]
      # Add grant as String
    assert grantee.grant('WRITE')
      # Add grants as Array
    assert grantee.grant(['READ_ACP', 'WRITE_ACP'])
      # Check perms count
    assert_equal 4, grantee.perms.size
      # revoke 'WRITE_ACP'
    assert grantee.revoke('WRITE_ACP')
      # Check manual perm removal method
    grantee.perms -= ['READ_ACP']
    grantee.apply
    assert_equal 2, grantee.perms.size
      # check 'Drop' method
    assert grantee.drop
    assert_equal 1, bucket.grantees.size
      # Delete bucket
    bucket.delete(true)
  end
  
  def test_33_key_grantees
      # Create bucket
    bucket = @s.bucket(@bucket, true)
      # Create key
    key = bucket.key(@key1)
    assert key.put(RIGHT_OBJECT_TEXT, 'public-read')
      # Get grantees list (must be == 2)
    grantees = key.grantees
    assert grantees
    assert_equal 2, grantees.size
      # Take one of grantees and give him 'Write' perms
    grantee = grantees[0]
    assert grantee.grant('WRITE')
      # Drop grantee
    assert grantee.drop
      # Drop bucket
    bucket.delete(true)
  end

  def test_34_bucket_create_put_with_perms
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, true)
      # check that the bucket exists
    assert @s.buckets.map{|b| b.name}.include?(@bucket)
    assert bucket.keys.empty?
      # put data (with canned ACL)
    assert bucket.put(@key1, RIGHT_OBJECT_TEXT, {'family'=>'123456'}, "public-read")
      # get data and compare
    assert_equal RIGHT_OBJECT_TEXT, bucket.get(@key1)
      # get key object
    key = bucket.key(@key1, true)
    assert_equal Rightscale::S3::Key, key.class
    assert       key.exists?
    assert_equal '123456', key.meta_headers['family']
  end

  def test_35_key_put_with_perms
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
      # create first key
    key1 = Rightscale::S3::Key.create(bucket, @key1)
    key1.refresh
    assert key1.exists?
    assert key1.put(RIGHT_OBJECT_TEXT, "public-read")
      # get its data
    assert_equal RIGHT_OBJECT_TEXT, key1.get
      # drop key
    assert key1.delete
    assert !key1.exists?
  end
  

end
