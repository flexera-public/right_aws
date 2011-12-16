require File.dirname(__FILE__) + '/test_helper.rb'

class TestS3 < Test::Unit::TestCase

  RIGHT_OBJECT_TEXT     = 'Right test message'
  INTERFACE = Rightscale::S3Interface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
  CONNECTION = Rightscale::S3.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)

  def setup
    @s3     = INTERFACE
    @bucket = 'right_s3_awesome_test_bucket_000B1_officedrop'
    @bucket2 = 'right_s3_awesome_test_bucket_000B2_officedrop'
    @key1   = 'test/woohoo1/'
    @key2   = 'test1/key/woohoo2'
    @key3   = 'test2/A%B@C_D&E?F+G=H"I'
    @key1_copy =     'test/woohoo1_2'
    @key1_new_name = 'test/woohoo1_3'
    @key2_new_name = 'test1/key/woohoo2_new'
    @s      = CONNECTION
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
    assert_equal 0, @s3.list_bucket(@bucket).size, "#{@bucket} isn't empty, arrgh!"
  end

  def test_04_put
    assert @s3.put(@bucket, @key1, RIGHT_OBJECT_TEXT, 'x-amz-meta-family'=>'Woohoo1!'), 'Put bucket fail'
    assert @s3.put(@bucket, @key2, RIGHT_OBJECT_TEXT, 'x-amz-meta-family'=>'Woohoo2!'), 'Put bucket fail'
    assert @s3.put(@bucket, @key3, RIGHT_OBJECT_TEXT, 'x-amz-meta-family'=>'Woohoo3!'), 'Put bucket fail'
  end

  def test_05_get_and_get_object
    assert_raise(Rightscale::AwsError) { @s3.get(@bucket, 'undefined/key') }
    data1 = @s3.get(@bucket, @key1)
    assert_equal RIGHT_OBJECT_TEXT, data1[:object], "Object text must be equal to '#{RIGHT_OBJECT_TEXT}'"
    assert_equal RIGHT_OBJECT_TEXT, @s3.get_object(@bucket, @key1), "Get_object text must return '#{RIGHT_OBJECT_TEXT}'"
    assert_equal 'Woohoo1!', data1[:headers]['x-amz-meta-family'], "x-amz-meta-family header must be equal to 'Woohoo1!'"
    assert_equal RIGHT_OBJECT_TEXT, @s3.get_object(@bucket, @key3), "Get_object text must return '#{RIGHT_OBJECT_TEXT}'"
  end

  def test_06_head
    assert_equal 'Woohoo1!', @s3.head(@bucket,@key1)['x-amz-meta-family'], "x-amz-meta-family header must be equal to 'Woohoo1!'"
  end


  def test_07_streaming_get
    resp = String.new
    assert_raise(Rightscale::AwsError) do
      @s3.get(@bucket, 'undefined/key') do |chunk|
        resp += chunk
      end
    end

    resp = String.new
    data1 = @s3.get(@bucket, @key1) do |chunk|
      resp += chunk
    end
    assert_equal RIGHT_OBJECT_TEXT, resp, "Object text must be equal to '#{RIGHT_OBJECT_TEXT}'"
    assert_equal @s3.get_object(@bucket, @key1), resp, "Streaming iface must return same as non-streaming"
    assert_equal 'Woohoo1!', data1[:headers]['x-amz-meta-family'], "x-amz-meta-family header must be equal to 'Woohoo1!'"
  end

  def test_08_keys
    keys = @s3.list_bucket(@bucket).map{|b| b[:key]}
    assert_equal keys.size, 3, "There should be 3 keys"
    assert(keys.include?(@key1))
    assert(keys.include?(@key2))
    assert(keys.include?(@key3))
  end

  def test_09_copy_key
    #--- test COPY
    # copy a key
    assert @s3.copy(@bucket, @key1, @bucket, @key1_copy)
    # check it was copied well
    assert_equal RIGHT_OBJECT_TEXT, @s3.get_object(@bucket, @key1_copy), "copied object must have the same data"
    # check meta-headers were copied
    headers = @s3.head(@bucket, @key1_copy)
    assert_equal 'Woohoo1!', headers['x-amz-meta-family'], "x-amz-meta-family header must be equal to 'Woohoo1!'"
    #--- test REPLACE
    assert @s3.copy(@bucket, @key1, @bucket, @key1_copy, :replace, 'x-amz-meta-family' => 'oooops!')
    # check it was copied well
    assert_equal RIGHT_OBJECT_TEXT, @s3.get_object(@bucket, @key1_copy), "copied object must have the same data"
    # check meta-headers were overwrittenn
    headers = @s3.head(@bucket, @key1_copy)
    assert_equal 'oooops!', headers['x-amz-meta-family'], "x-amz-meta-family header must be equal to 'oooops!'"
  end

  def test_10_move_key
    # move a key
    assert @s3.move(@bucket, @key1, @bucket, @key1_new_name)
    # check it's data was moved correctly
    assert_equal RIGHT_OBJECT_TEXT, @s3.get_object(@bucket, @key1_new_name), "moved object must have the same data"
    # check meta-headers were moved
    headers = @s3.head(@bucket, @key1_new_name)
    assert_equal 'Woohoo1!', headers['x-amz-meta-family'], "x-amz-meta-family header must be equal to 'Woohoo1!'"
    # check the original key is not exists any more
    keys = @s3.list_bucket(@bucket).map{|b| b[:key]}
    assert(!keys.include?(@key1))
  end

  def test_11_rename_key
    # rename a key
    assert @s3.rename(@bucket, @key2, @key2_new_name)
    # check the new key data
    assert_equal RIGHT_OBJECT_TEXT, @s3.get_object(@bucket, @key2_new_name), "moved object must have the same data"
    # check meta-headers
    headers = @s3.head(@bucket, @key2_new_name)
    assert_equal 'Woohoo2!', headers['x-amz-meta-family'], "x-amz-meta-family header must be equal to 'Woohoo2!'"
    # check the original key is not exists any more
    keys = @s3.list_bucket(@bucket).map{|b| b[:key]}
    assert(!keys.include?(@key2))
  end
  def test_12_retrieve_object
    assert_raise(Rightscale::AwsError) { @s3.retrieve_object(:bucket => @bucket, :key => 'undefined/key') }
    data1 = @s3.retrieve_object(:bucket => @bucket, :key => @key1_new_name)
    assert_equal RIGHT_OBJECT_TEXT, data1[:object], "Object text must be equal to '#{RIGHT_OBJECT_TEXT}'"
    assert_equal 'Woohoo1!', data1[:headers]['x-amz-meta-family'], "x-amz-meta-family header must be equal to 'Woohoo1!'"
  end
  def test_13_delete_folder
    assert_equal 1, @s3.delete_folder(@bucket, 'test').size, "Only one key(#{@key1}) must be deleted!"
  end

  def test_14_delete_bucket
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
    assert bucket.put(@key3, RIGHT_OBJECT_TEXT, {'family'=>'123456'})
      # get data and compare
    assert_equal RIGHT_OBJECT_TEXT, bucket.get(@key3)
      # get key object
    key = bucket.key(@key3, true)
    assert_equal Rightscale::S3::Key, key.class
    assert       key.exists?
    assert_equal '123456', key.meta_headers['family']
  end

  def test_22_keys
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
      # create first key
    key3 = Rightscale::S3::Key.create(bucket, @key3)
    key3.refresh
    assert key3.exists?
    assert_equal '123456', key3.meta_headers['family']
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

  def test_23_rename_key
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
    # -- 1 -- (key based rename)
    # create a key
    key = bucket.key('test/copy/1')
    key.put(RIGHT_OBJECT_TEXT)
    original_key = key.clone
    assert key.exists?, "'test/copy/1' should exist"
    # rename it
    key.rename('test/copy/2')
    assert_equal 'test/copy/2', key.name
    assert key.exists?, "'test/copy/2' should exist"
    # the original key should not exist
    assert !original_key.exists?, "'test/copy/1' should not exist"
    # -- 2 -- (bucket based rename)
    bucket.rename_key('test/copy/2', 'test/copy/3')
    assert  bucket.key('test/copy/3').exists?, "'test/copy/3' should exist"
    assert !bucket.key('test/copy/2').exists?, "'test/copy/2' should not exist"
  end

  def test_24_copy_key
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
    # -- 1 -- (key based copy)
    # create a key
    key = bucket.key('test/copy/10')
    key.put(RIGHT_OBJECT_TEXT)
    # make copy
    new_key = key.copy('test/copy/11')
    # make sure both the keys exist and have a correct data
    assert key.exists?,     "'test/copy/10' should exist"
    assert new_key.exists?, "'test/copy/11' should exist"
    assert_equal RIGHT_OBJECT_TEXT, key.get
    assert_equal RIGHT_OBJECT_TEXT, new_key.get
    # -- 2 -- (bucket based copy)
    bucket.copy_key('test/copy/11', 'test/copy/12')
    assert bucket.key('test/copy/11').exists?, "'test/copy/11' should exist"
    assert bucket.key('test/copy/12').exists?, "'test/copy/12' should exist"
    assert_equal RIGHT_OBJECT_TEXT, bucket.key('test/copy/11').get
    assert_equal RIGHT_OBJECT_TEXT, bucket.key('test/copy/12').get
  end

  def test_25_move_key
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
    # -- 1 -- (key based copy)
    # create a key
    key = bucket.key('test/copy/20')
    key.put(RIGHT_OBJECT_TEXT)
    # move
    new_key = key.move('test/copy/21')
    # make sure both the keys exist and have a correct data
    assert !key.exists?,    "'test/copy/20' should not exist"
    assert new_key.exists?, "'test/copy/21' should exist"
    assert_equal RIGHT_OBJECT_TEXT, new_key.get
    # -- 2 -- (bucket based copy)
    bucket.copy_key('test/copy/21', 'test/copy/22')
    assert bucket.key('test/copy/21').exists?, "'test/copy/21' should not exist"
    assert bucket.key('test/copy/22').exists?, "'test/copy/22' should exist"
    assert_equal RIGHT_OBJECT_TEXT, bucket.key('test/copy/22').get
  end

  def test_26_save_meta
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
    # create a key
    key = bucket.key('test/copy/30')
    key.put(RIGHT_OBJECT_TEXT)
    assert key.meta_headers.right_blank?
    # store some meta keys
    meta = {'family' => 'oops','race' => 'troll'}
    assert_equal meta, key.save_meta(meta)
    # reload meta
    assert_equal meta, key.reload_meta
  end

  def test_27_clear_delete
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
      # add another key
    bucket.put(@key2, RIGHT_OBJECT_TEXT)
      # delete 'folder'
    assert_equal 1, bucket.delete_folder(@key1).size
      # delete
    assert_raise(Rightscale::AwsError) { bucket.delete }
    bucket.delete(:force => true)
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
      # Take 'AllUsers' grantee
    grantee = Rightscale::S3::Grantee.new(bucket,'http://acs.amazonaws.com/groups/global/AllUsers')
      # Check exists?
    assert grantee.exists?
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
      # Check grantee removal if it has no permissions
    assert grantee.perms = []
    assert grantee.apply
    assert !grantee.exists?
      # Check multiple perms assignment
    assert grantee.grant('FULL_CONTROL', 'READ', 'WRITE')
    assert_equal ['FULL_CONTROL','READ','WRITE'].sort, grantee.perms.sort
      # Check multiple perms removal
    assert grantee.revoke('FULL_CONTROL', 'WRITE')
    assert_equal ['READ'], grantee.perms
      # check 'Drop' method
    assert grantee.drop
    assert !grantee.exists?
    assert_equal 1, bucket.grantees.size
      # Delete bucket
    bucket.delete(:force => true)
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
    bucket.delete(:force => true)
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

  def test_36_set_amazon_problems
    original_problems = RightAws::S3Interface.amazon_problems
    assert(original_problems.length > 0)
    RightAws::S3Interface.amazon_problems= original_problems << "A New Problem"
    new_problems = RightAws::S3Interface.amazon_problems
    assert_equal(new_problems, original_problems)

    RightAws::S3Interface.amazon_problems= nil
    assert_nil(RightAws::S3Interface.amazon_problems)
  end

  def test_37_access_logging
    bucket = Rightscale::S3::Bucket.create(@s, @bucket, false)
    targetbucket = Rightscale::S3::Bucket.create(@s, @bucket2, true)
      # Take 'AllUsers' grantee
    grantee = Rightscale::S3::Grantee.new(targetbucket,'http://acs.amazonaws.com/groups/s3/LogDelivery')

    assert grantee.grant(['READ_ACP', 'WRITE'])

    assert bucket.enable_logging(:targetbucket => targetbucket, :targetprefix => "loggylogs/")
    sleep 10

    assert_equal({:enabled => true, :targetbucket => @bucket2, :targetprefix => "loggylogs/"}, bucket.logging_info)

    assert bucket.disable_logging

      # check 'Drop' method
    assert grantee.drop
  end

  def test_40_delete_buckets
    Rightscale::S3::Bucket.create(@s, @bucket,  false).delete(:force => true)
    Rightscale::S3::Bucket.create(@s, @bucket2, false).delete(:force => true)
  end

  def test_41_add_cache_control_response_parameter
    @cache_control = 'max-age=3600'
    perform_request( 'response-cache-control' => @cache_control ) do |response|
       assert_equal response['Cache-Control'], @cache_control
    end
  end

  def test_42_add_cache_control_and_content_type_and_content_disposition
    @cache_control = 'max-age=3600'
    @content_type = 'text/plain'
    @content_disposition = 'attachment; filename=sample.txt'
    perform_request(
        'response-cache-control' => @cache_control,
        'response-content-type' => @content_type,
        'response-content-disposition' => @content_disposition
    ) do |response|
      assert_equal response['Cache-Control'], @cache_control
      assert_equal response['Content-Type'], @content_type
      assert_equal response['Content-Disposition'], @content_disposition
    end
  end

  def test_43_add_expires_and_content_type_and_content_disposition
    @expires = 'Sun, 26 Jun 2011 02:58:26 GMT'
    @content_type = 'text/plain'
    @content_disposition = 'attachment; filename=sample.txt'
    perform_request(
        'response-expires' => @expires,
        'response-content-type' => @content_type,
        'response-content-disposition' => @content_disposition
    ) do |response|
      assert_equal response['Expires'], @expires
      assert_equal response['Content-Type'], @content_type
      assert_equal response['Content-Disposition'], @content_disposition
    end
  end

  def test_44_delete_multiple
    bucket = RightAws::S3::Bucket.create(@s, @bucket, true)

    key1 = Rightscale::S3::Key.create(bucket, @key1)
    key2 = Rightscale::S3::Key.create(bucket, @key2)
    key3 = Rightscale::S3::Key.create(bucket, @key3)

    assert @s3.put(@bucket, @key1, RIGHT_OBJECT_TEXT), 'Put bucket fail'
    assert @s3.put(@bucket, @key2, RIGHT_OBJECT_TEXT), 'Put bucket fail'
    assert @s3.put(@bucket, @key3, RIGHT_OBJECT_TEXT), 'Put bucket fail'

    key1.refresh
    key2.refresh
    key3.refresh

    assert key1.exists?
    assert key2.exists?
    assert key3.exists?

    result = @s3.delete_multiple(@bucket, [@key1, @key2, @key3])
    assert result.empty?

    key1.refresh
    key2.refresh
    key3.refresh

    assert !key1.exists?
    assert !key2.exists?
    assert !key3.exists?
  end

  def test_45_delete_multiple_more_than_1000_objects
    n = 1200
    keys = (1..n).map { |i| "key-#{i}"}

    keys.each do |key|
      assert @s3.put(@bucket, key, RIGHT_OBJECT_TEXT), 'Put bucket fail'
    end

    result = @s3.delete_multiple(@bucket, keys)
    assert result.empty?

    keys_after = @s3.list_bucket(@bucket).map { |obj| obj[:key] }

    keys.each do |key|
      keys_after.include?(key)
    end
  end

  private

  def request( uri )
    url = URI.parse( uri )

    http = Net::HTTP.new(url.host, 443)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.request(Net::HTTP::Get.new( url.request_uri ))
  end

  def perform_request( headers, &block )
    @s3.create_bucket( @bucket )
    @s3.put( @bucket, @key2, RIGHT_OBJECT_TEXT )
    response = request( @s3.get_link( @bucket, @key2, nil, {}, headers ) )
    block.call( response )
    @s3.force_delete_bucket(@bucket)
  end

end
