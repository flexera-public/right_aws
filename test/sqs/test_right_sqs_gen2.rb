require File.dirname(__FILE__) + '/test_helper.rb'

class TestSqsGen2 < Test::Unit::TestCase

  GRANTEE_EMAIL_ADDRESS = 'fester@example.com'
  RIGHT_MESSAGE_TEXT    = 'Right test message'

  
  def setup
    $stdout.sync = true
    @grantee_aws_id = '100000000001'
    @sqs = Rightscale::SqsGen2Interface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
    @queue_name  = 'right_sqs_test_gen2_queue'
    @queue2_name = @queue_name + '_2'
    @queue3_name = @queue_name + '_3'
    @queue4_name = @queue_name + '_4'
      # for classes
    @s = Rightscale::SqsGen2.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
  end
  
  # Wait for the queue to appear in the queues list.
  # Amazon needs some time to after the queue creation to place
  # it to the accessible queues list. If we dont want to get
  # the additional faults then wait a bit...
  def wait_for_queue_url(queue_name)
    queue_url = nil
    do_sleep(180) do
      queue_url = @sqs.queue_url_by_name(queue_name)
    end
    sleep 30
    queue_url
  end

  def do_sleep(delay, &block)
    puts "sleeping #{block ? 'up to ' : ''}#{delay} seconds:"
    wake_up_at = Time.now+delay
    while Time.now < wake_up_at do
      sleep 1
      print '.'
      break if block && block.call
    end
    puts
  end
    
  #---------------------------
  # Rightscale::SqsInterface
  #---------------------------

  def test_01_create_queue
    queue_url = @sqs.create_queue @queue_name
    assert queue_url[/http.*#{@queue_name}/], 'New queue creation failed'
  end

  def test_02_list_queues
    wait_for_queue_url(@queue_name)
    queues = @sqs.list_queues('right_')
    assert queues.size>0, 'Must more that 0 queues in list'
  end

  def test_03_set_and_get_queue_attributes
    queue_url = @sqs.queue_url_by_name(@queue_name)
    assert queue_url[/https.*#{@queue_name}/], "#{@queue_name} must exist!"
    assert @sqs.set_queue_attributes(queue_url, 'VisibilityTimeout', 111), 'Set_queue_attributes fail'
    do_sleep 60 # Amazon needs some time to change attribute
    assert_equal '111', @sqs.get_queue_attributes(queue_url)['VisibilityTimeout'], 'New VisibilityTimeout must be equal to 111'
  end

  def test_04_get_queue_attributes_forms
    queue_url = @sqs.queue_url_by_name(@queue_name)
    all = nil
    assert_nothing_raised do
      all = @sqs.get_queue_attributes(queue_url, 'All')
    end
    assert_nothing_raised do
      assert all, @sqs.get_queue_attributes(queue_url)
    end
    assert_nothing_raised do
      attributes = @sqs.get_queue_attributes(queue_url, 'ApproximateNumberOfMessages', 'VisibilityTimeout')
      assert_equal 2, attributes.size
    end
    assert_nothing_raised do
      attributes = @sqs.get_queue_attributes(queue_url, ['ApproximateNumberOfMessages', 'VisibilityTimeout'])
      assert_equal 2, attributes.size
    end
  end

  def test_05_add_permissions
    queue_url = @sqs.queue_url_by_name(@queue_name)
    assert @sqs.add_permissions(queue_url, 'test01', @grantee_aws_id, 'SendMessage')
    assert @sqs.add_permissions(queue_url, 'test02', @grantee_aws_id, ['DeleteMessage','ReceiveMessage'])
    do_sleep 60
  end

  def test_06_test_permissions
    queue_url = @sqs.queue_url_by_name(@queue_name)
    permissions = @sqs.get_queue_attributes(queue_url, 'Policy')
    assert !permissions.blank?
  end

  def test_07_revoke_permissions
    queue_url = @sqs.queue_url_by_name(@queue_name)
    assert @sqs.remove_permissions(queue_url, 'test01')
    assert @sqs.remove_permissions(queue_url, 'test02')
  end

  def test_14_send_message
    queue_url = @sqs.queue_url_by_name(@queue_name)
      # send 5 messages for the tests below
    assert @sqs.send_message(queue_url, RIGHT_MESSAGE_TEXT)
    assert @sqs.send_message(queue_url, RIGHT_MESSAGE_TEXT)
    assert @sqs.send_message(queue_url, RIGHT_MESSAGE_TEXT)
    assert @sqs.send_message(queue_url, RIGHT_MESSAGE_TEXT)
    assert @sqs.send_message(queue_url, RIGHT_MESSAGE_TEXT)
    do_sleep 60
  end
  
  def test_15_get_queue_length
    queue_url = @sqs.queue_url_by_name(@queue_name)
    assert_equal 5, @sqs.get_queue_length(queue_url), 'Queue must have 5 messages'
  end

  def test_16_receive_message
    queue_url = @sqs.queue_url_by_name(@queue_name)
    r_message = @sqs.receive_message(queue_url, 1)[0]
    assert r_message, "Receive returned no message(s), but this is not necessarily incorrect"
    assert_equal RIGHT_MESSAGE_TEXT, r_message['Body'], 'Receive message got wrong message text'
  end
  
  def test_17_delete_message
    queue_url = @sqs.queue_url_by_name(@queue_name)
    message = @sqs.receive_message(queue_url)[0]
    assert @sqs.delete_message(queue_url, message['ReceiptHandle']), 'Delete_message fail'
    assert @sqs.pop_message(queue_url), 'Pop_message fail'
  end
  
  def test_18_clear_and_delete_queue
    queue_url = @sqs.queue_url_by_name(@queue_name)
    assert @sqs.delete_queue(queue_url) 
  end
  
  #---------------------------
  # Rightscale::Sqs classes
  #---------------------------

  def test_20_sqs_create_queue
    assert @s, 'Rightscale::SqsGen2 must exist'
      # get queues list
    queues_size = @s.queues.size
      # create new queue
    queue = @s.queue(@queue2_name, true)
      # check that it is created
    assert queue.is_a?(Rightscale::SqsGen2::Queue)
    wait_for_queue_url(queue.name)
      # check that amount of queues has increased
    assert_equal queues_size + 1, @s.queues.size
    do_sleep 10
  end

  def test_21_sqs_delete_queue
    queue = @s.queue(@queue2_name, false)
    assert queue.delete
  end
  
  def test_22_queue_create
      # create new queue
    queue = Rightscale::SqsGen2::Queue.create(@s, @queue3_name, true)
      # check that it is created
    assert queue.is_a?(Rightscale::SqsGen2::Queue)
    wait_for_queue_url("#{@queue_name}_21")
    do_sleep 10
  end
  
  def test_23_queue_attributes
    queue = Rightscale::SqsGen2::Queue.create(@s, @queue3_name, false)
      # get a list of attrinutes
    attributes = queue.get_attribute
    assert attributes.is_a?(Hash) && attributes.size>0
      # get attribute value and increase it by 10
    v = (queue.get_attribute('VisibilityTimeout').to_i + 10).to_s
      # set attribute
    assert queue.set_attribute('VisibilityTimeout', v)
      # wait a bit
    do_sleep 60
      # check that attribute has changed
    assert_equal v, queue.get_attribute('VisibilityTimeout')
      # get queue visibility timeout
    assert_equal v, queue.visibility
      # change it 
    queue.visibility = queue.visibility.to_i + 10
      # make sure that it is changed
    assert v.to_i + 10, queue.visibility
  end

  def test_24
    queue = Rightscale::SqsGen2::Queue.create(@s, @queue3_name, false)
    assert queue.delete
  end
  
  def test_25_send_size
    queue = Rightscale::SqsGen2::Queue.create(@s, @queue4_name, true)
      # send 5 messages
    assert queue.push('a1')
    assert queue.push('a2')
    assert queue.push('a3')
    assert queue.push('a4')
    assert queue.push('a5')
      #
    do_sleep(300){ queue.size == 5 }
      # check queue size
    assert_equal 5, queue.size
      # send one more
    assert queue.push('a6')
      #
    do_sleep(300){ queue.size == 6 }
      # check queue size again
    assert_equal 6, queue.size
  end
  
  def test_26_message_receive_pop_delete
    queue = Rightscale::SqsGen2::Queue.create(@s,  @queue4_name, false)
      # get queue size
    size = queue.size
      # get first message
    m1 = queue.receive(10)
    assert m1.is_a?(Rightscale::SqsGen2::Message)
      # pop second message
    m2 = queue.pop
    assert m2.is_a?(Rightscale::SqsGen2::Message)
      #
    do_sleep 30
      # make sure that queue size has decreased
    assert_equal size-1, queue.size
      # delete messsage
    assert m1.delete
      #
    do_sleep 15
      # make sure that queue size has decreased again
    assert_equal size-2, queue.size
  end
 
  def test_27
    queue = Rightscale::SqsGen2::Queue.create(@s, @queue4_name, false)
      # lock message 
    queue.receive(100)
      # clear queue
    assert queue.clear 
      # queue size is greater than zero
    assert queue.size>0
      # delete queue
    assert queue.delete
  end

  def test_28_set_amazon_problems
    original_problems = Rightscale::SqsGen2Interface.amazon_problems
    assert(original_problems.length > 0)
    Rightscale::SqsGen2Interface.amazon_problems= original_problems << "A New Problem"
    new_problems = Rightscale::SqsGen2Interface.amazon_problems
    assert_equal(new_problems, original_problems)

    Rightscale::SqsGen2Interface.amazon_problems= nil
    assert_nil(Rightscale::SqsGen2Interface.amazon_problems)
  end
  
end
