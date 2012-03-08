require File.dirname(__FILE__) + '/test_helper.rb'

class TestAcf < Test::Unit::TestCase

  RIGHT_OBJECT_TEXT     = 'Right test message'

  STDOUT.sync = true

  def setup
    @acf= Rightscale::AcfInterface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
    @s3 = Rightscale::S3.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
    @bucket_name   = "right-acf-awesome-test-bucket-xxx1"
    @bucket_domain = "#{@bucket_name}.s3.amazonaws.com"
  end

  def test_01_list_distributions_part1
    distributions = nil
    assert_nothing_raised(Rightscale::AwsError) do
      distributions = @acf.list_distributions
    end
    assert distributions.is_a?(Array)
  end

  def test_02_try_to_create_for_bad_bucket
    # a bucket does not exist
    assert_raise(Rightscale::AwsError) do
      @acf.create_distribution("right-cloudfront-awesome-test-bucket-not-exist", "Mustn't to be born", true)
    end
    # a bucket is not a domain naming complied guy
    bucket_name = 'right_cloudfront_awesome_test_bucket_BAD_XXX'
    @s3.bucket(bucket_name, :create)
    assert_raise(Rightscale::AwsError) do
      @acf.create_distribution(bucket_name, "Mustn't to be born", true)
    end
  end

  def test_02_x_delete_bad_bucket
    bucket_name = 'right_cloudfront_awesome_test_bucket_BAD_XXX'
    @s3.bucket(bucket_name, false).delete
  end

  def test_03_create
    comment = 'WooHoo!!!'
    # create a test bucket
    @s3.bucket(@bucket_name, :create)
    # create a distribution
    distribution = @acf.create_distribution(@bucket_domain, comment, true)
    assert_equal comment, distribution[:comment]
    assert       distribution[:cnames].size == 0
    assert       distribution[:enabled]
  end

  def test_04_list_distributions_part2
    distributions = @acf.list_distributions
    assert distributions.size > 0
  end

  def get_test_distribution
    @acf.list_distributions.select{ |d| d[:origin] == @bucket_domain }.first
  end

  def test_05_get_distribution
    old = get_test_distribution
    assert_nothing_raised do
      @acf.get_distribution(old[:aws_id])
    end
  end

  def test_06_get_and_set_config
    config = nil
    old = get_test_distribution
    assert_nothing_raised do
      config = @acf.get_distribution_config(old[:aws_id])
    end
    # change a config
    config[:enabled] = false
    config[:cnames] << 'xxx1.myawesomesite.com'
    config[:cnames] << 'xxx2.myawesomesite.com'
    # set config
    set_config_result = nil
    assert_nothing_raised do
      set_config_result = @acf.set_distribution_config(old[:aws_id], config)
    end
    assert set_config_result
    # reget the config and check
    new_config = nil
    assert_nothing_raised do
      new_config = @acf.get_distribution_config(old[:aws_id])
    end
    assert           !new_config[:enabled]
    assert_equal     new_config[:cnames].sort, ['xxx1.myawesomesite.com', 'xxx2.myawesomesite.com']
    assert_not_equal config[:e_tag], new_config[:e_tag]

    # try to update the old config again (must fail because ETAG has changed)
    assert_raise(Rightscale::AwsError) do
      @acf.set_distribution_config(old[:aws_id], config)
    end
  end

  def test_08_delete_distribution
    # we need ETAG so use get_distribution
    distribution = @acf.get_distribution(get_test_distribution[:aws_id])
    # try to delete a distribution
    # should fail because
    if distribution[:status] == 'InProgress'
      # should fail because the distribution is not deployed yet
      assert_raise(Rightscale::AwsError) do
        @acf.delete_distribution(distribution[:aws_id], distribution[:e_tag])
      end
      # wait for a deployed state
      print "waiting up to 5 min while the distribution is being deployed: "
      100.times do
        print '.'
        distribution = @acf.get_distribution(distribution[:aws_id])
        if distribution[:status] == 'Deployed'
          print ' done'
          break
        end
        sleep 3
      end
      puts
    end

    # only disabled and deployed distribution can be deleted
    assert_equal 'Deployed', distribution[:status]
    assert       !distribution[:enabled]

    # delete the distribution
    assert_nothing_raised do
      @acf.delete_distribution(distribution[:aws_id], distribution[:e_tag])
    end
  end

  def test_09_drop_bucket
    assert @s3.bucket(@bucket_name).delete
  end

end
