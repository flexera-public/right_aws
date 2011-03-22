require File.dirname(__FILE__) + '/test_helper.rb'

class TestSns < Test::Unit::TestCase

  # You can change these things to whatever you like
  @@subscriber_email  = 'me@ryangeyer.com'
  @@topic_name        = 'RightTestTopic'

  # These are placeholders for values that get set, and consumed during the course of testing.
  @@topic_arn           = ''
  @@subscription_arn    = ''
  @@topic_display_name  = 'right_aws test notification topic'

  @@policy_template     = <<-EOF
{
  "Id": "Policy1300753700208",
  "Statement": [
    {
      "Sid": "Stmt1300753696680",
      "Action": [
        "SNS:Publish",
        "SNS:RemovePermission",
        "SNS:SetTopicAttributes",
        "SNS:DeleteTopic",
        "SNS:ListSubscriptionsByTopic",
        "SNS:GetTopicAttributes",
        "SNS:Receive",
        "SNS:AddPermission",
        "SNS:Subscribe"
      ],
      "Effect": "Allow",
      "Resource": "@@topic_arn@@",
      "Principal": {
        "AWS": [
          "*"
        ]
      }
    }
  ]
}
    EOF

  def policy_text
    @@policy_template.gsub('@@topic_arn@@', @@topic_arn)
  end

  def setup
    @sns = Rightscale::SnsInterface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
  end

  def test_01_create_topic
    response = @sns.create_topic(@@topic_name)
    assert_not_nil(response)
    @@topic_arn = response
  end

  def test_02_set_topic_attributes
    response = @sns.set_topic_attribute(@@topic_arn, 'Policy', policy_text())
    assert_not_nil(response)

    response = @sns.set_topic_attribute(@@topic_arn, 'DisplayName', @@topic_display_name)
    assert_not_nil(response)

    assert_raise ArgumentError do
      @sns.set_topic_attribute(@@topic_arn, 'Foo', 'val')
    end
  end

  def test_03_get_topic_attributes
    response = @sns.get_topic_attributes(@@topic_arn)
    assert_not_nil(response)
    assert(response['DisplayName'] == @@topic_display_name)
    assert(response['Policy'] =~ /Policy1300753700208/)
  end

  def test_04_list_topics
    sleep(1)
    assert(@sns.list_topics.collect{|topic| topic[:arn] }.include?(@@topic_arn))
  end

  def test_05_subscribe
    response = @sns.subscribe(@@topic_arn, 'email', @@subscriber_email)
    assert_not_nil(response)
    @@subscription_arn = response
  end

  def test_06_list_subscriptions
    # TODO: Create an SQS queue, somehow get (or more likely parse) it's ARN, and create some subscriptions to it for us to find
    response = @sns.list_subscriptions()
    assert_not_nil(response)
    puts response.to_yaml
  end

  def test_07_publish
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