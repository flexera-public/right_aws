require File.dirname(__FILE__) + '/test_helper.rb'

class TestSns < Test::Unit::TestCase

  # You can change these things to whatever you like
  @@subscriber_email    = 'foo@bar.baz'
  @@topic_name          = 'RightTestTopic'
  @@topic_display_name  = 'right_aws test notification topic'
  @@queue_name          = "sns_subscribe_queue_#{Time.now.utc.to_i}"

  # These are placeholders for values that get set, and consumed during the course of testing.
  @@topic_arn           = ''
  @@subscription_arn    = ''
  @@queue_url           = ''
  @@queue_arn           = ''

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
    @sqs = Rightscale::SqsGen2Interface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
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

  def test_05_subscribe_email
    response = @sns.subscribe(@@topic_arn, 'email', @@subscriber_email)
    assert_not_nil(response)
    @@subscription_arn = response
  end

  def test_06_list_subscriptions
    sleep(1)

    response = @sns.list_subscriptions()
    assert_not_nil(response)
    assert(response.count == 1)
    assert(response[0][:endpoint] == @@subscriber_email)
    assert(response[0][:protocol] == 'email')
    assert(response[0][:subscription_arn] == 'PendingConfirmation')
    assert(response[0][:topic_arn] == @@topic_arn)
  end

  def test_07_list_subscriptions_by_topic
    response = @sns.list_subscriptions(@@topic_arn)
    assert_not_nil(response)
    assert(response.count == 1)
    assert(response[0][:endpoint] == @@subscriber_email)
    assert(response[0][:protocol] == 'email')
    assert(response[0][:subscription_arn] == 'PendingConfirmation')
    assert(response[0][:topic_arn] == @@topic_arn)
  end

  def test_08_unsubscribe
    @@queue_url = @sqs.create_queue(@@queue_name)
    @@queue_arn = "arn:aws:sqs:us-east-1:#{TestCredentials.account_number.gsub('-','')}:#{@@queue_name}"
    sub_response = @sns.subscribe(@@topic_arn, 'sqs', @@queue_arn)
    assert_not_nil(sub_response)
    unsub_response = @sns.unsubscribe(sub_response)
    @sqs.delete_queue(@@queue_url)
  end

  def test_09_publish
    response = @sns.publish(@@topic_arn, 'Message to publish', 'Message Subject')
    assert_not_nil(response)
  end

  def test_10_add_and_remove_permission
    acct_num = TestCredentials.account_number.gsub('-','')

    add_response = @sns.add_permission(@@topic_arn, 'PermissionLbl', [
      {:aws_account_id => acct_num, :action => "GetTopicAttributes"},
      {:aws_account_id => acct_num, :action => "Publish"}
    ])
    assert_not_nil(add_response)

    remove_response = @sns.remove_permission(@@topic_arn, 'PermissionLbl')
    assert_not_nil(remove_response)
  end

# TODO: Cannot easily test confirming subscription because it's only valid for http(s) and email subscriptions.
# Since we don't want to setup an email box or HTTP server to recive the token, we can't really simulate this
#  def test_10_confirm_subscription
#    response = @sns.confirm_subscription(@@topic_arn, 'SomeToken')
#    assert_not_null(response)
#  end

  def test_30_delete_topic
    response = @sns.delete_topic(@@topic_arn)
    assert_not_nil(response)
    sleep(1)
    assert(!@sns.list_topics.collect{|topic| topic[:arn] }.include?(@@topic_arn))
  end
end