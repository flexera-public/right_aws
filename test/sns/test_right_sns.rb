require File.dirname(__FILE__) + '/test_helper.rb'

class TestSns < Test::Unit::TestCase

  # You can change these things to whatever you like
  @@subscriber_email  = 'me@ryangeyer.com'
  @@topic_name        = 'RightTestTopic'

  # These are placeholders for values that get set, and consumed during the course of testing.
  @@topic_arn         = ''
  @@subscription_arn  = ''


  def setup
    @sns = Rightscale::SnsInterface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
  end

  def test_01_create_topic
    response = @sns.create_topic(@@topic_name)
    assert_not_nil(response)
    @@topic_arn = response
  end

  def test_02_list_topics
    sleep(1)
    assert(@sns.list_topics.collect{|topic| topic[:arn] }.include?(@@topic_arn))
  end

  def test_03_subscribe
    response = @sns.subscribe(@@topic_arn, 'email', @@subscriber_email)
    assert_not_nil(response)
    @@subscription_arn = response
  end

  def test_04_publish
    response = @sns.publish(@@topic_arn, 'Message to publish', 'Message Subject')
    assert_not_nil(response)
  end
# TODO: Cannot easily test unsubscribing because subscriber has to confirm their subscription before the subscription
# arn becomes available, presumably by the "ListSubscriptions" call(s)
#
#  def test_05_unsubscribe
#    puts "About to unsubscribe subscription arn - #{@@subscription_arn}"
#    response = @sns.unsubscribe(@@subscription_arn)
#    assert_not_null(response)
#  end

  def test_30_delete_topic
    response = @sns.delete_topic(@@topic_arn)
    assert_not_nil(response)
    sleep(1)
    assert(!@sns.list_topics.collect{|topic| topic[:arn] }.include?(@@topic_arn))
  end
end