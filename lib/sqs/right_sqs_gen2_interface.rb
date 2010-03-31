#
# Copyright (c) 2007-2008 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

module RightAws

  #
  # Right::Aws::SqsGen2Interface - RightScale's low-level Amazon SQS interface
  # for API version 2008-01-01 and later.
  # For explanations of the semantics
  # of each call, please refer to Amazon's documentation at
  # http://developer.amazonwebservices.com/connect/kbcategory.jspa?categoryID=31
  #
  # This class provides a procedural interface to SQS.  Conceptually it is
  # mostly a pass-through interface to SQS and its API is very similar to the
  # bare SQS API.  For a somewhat higher-level and object-oriented interface, see
  # RightAws::SqsGen2. 

  class SqsGen2Interface < RightAwsBase
    include RightAwsBaseInterface
    
    API_VERSION       = "2009-02-01"
    DEFAULT_HOST      = "queue.amazonaws.com"
    DEFAULT_PORT      = 443
    DEFAULT_PROTOCOL  = 'https'
    REQUEST_TTL       = 30
    DEFAULT_VISIBILITY_TIMEOUT = 30


    @@bench = AwsBenchmarkingBlock.new
    def self.bench_xml
      @@bench.xml
    end
    def self.bench_sqs
      @@bench.service
    end

    @@api = API_VERSION
    def self.api 
      @@api
    end

    # Creates a new SqsInterface instance. This instance is limited to
    # operations on SQS objects created with Amazon's 2008-01-01 API version.  This
    # interface will not work on objects created with prior API versions.  See
    # Amazon's article "Migrating to Amazon SQS API version 2008-01-01" at:
    # http://developer.amazonwebservices.com/connect/entry.jspa?externalID=1148
    #
    #  sqs = RightAws::SqsGen2Interface.new('1E3GDYEOGFJPIT75KDT40','hgTHt68JY07JKUY08ftHYtERkjgtfERn57DFE379', {:multi_thread => true, :logger => Logger.new('/tmp/x.log')}) 
    #  
    # Params is a hash:
    #
    #    {:server       => 'queue.amazonaws.com' # Amazon service host: 'queue.amazonaws.com' (default)
    #     :port         => 443                   # Amazon service port: 80 or 443 (default)
    #     :multi_thread => true|false            # Multi-threaded (connection per each thread): true or false (default)
    #     :signature_version => '0'              # The signature version : '0', '1' or '2'(default)
    #     :logger       => Logger Object}        # Logger instance: logs to STDOUT if omitted }
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name             => 'SQS', 
             :default_host     => ENV['SQS_URL'] ? URI.parse(ENV['SQS_URL']).host   : DEFAULT_HOST, 
             :default_port     => ENV['SQS_URL'] ? URI.parse(ENV['SQS_URL']).port   : DEFAULT_PORT, 
             :default_protocol => ENV['SQS_URL'] ? URI.parse(ENV['SQS_URL']).scheme : DEFAULT_PROTOCOL }, 
           aws_access_key_id     || ENV['AWS_ACCESS_KEY_ID'], 
           aws_secret_access_key || ENV['AWS_SECRET_ACCESS_KEY'], 
           params)
    end


  #-----------------------------------------------------------------
  #      Requests
  #-----------------------------------------------------------------

    # Generates a request hash for the query API
    def generate_request(action, param={})  # :nodoc:
      # For operation requests on a queue, the queue URI will be a parameter,
      # so we first extract it from the call parameters.  Next we remove any
      # parameters with no value or with symbolic keys.  We add the header
      # fields required in all requests, and then the headers passed in as
      # params.  We sort the header fields alphabetically and then generate the
      # signature before URL escaping the resulting query and sending it.
      service = param[:queue_url] ? URI(param[:queue_url]).path : '/'
      param.each{ |key, value| param.delete(key) if (value.nil? || key.is_a?(Symbol)) }
      service_hash = { "Action"           => action,
                       "Expires"          => (Time.now + REQUEST_TTL).utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "AWSAccessKeyId"   => @aws_access_key_id,
                       "Version"          => API_VERSION }
      service_hash.update(param)
      service_params = signed_service_params(@aws_secret_access_key, service_hash, :get, @params[:server], service)
      request        = Net::HTTP::Get.new("#{AwsUtils.URLencode(service)}?#{service_params}")
        # prepare output hash
      { :request  => request, 
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol] }
    end

    def generate_post_request(action, param={})  # :nodoc:
      service = param[:queue_url] ? URI(param[:queue_url]).path : '/'
      message   = param[:message]                # extract message body if nesessary
      param.each{ |key, value| param.delete(key) if (value.nil? || key.is_a?(Symbol)) }
      service_hash = { "Action"           => action,
                       "Expires"          => (Time.now + REQUEST_TTL).utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "AWSAccessKeyId"   => @aws_access_key_id,
                       "MessageBody"      => message,
                       "Version"          => API_VERSION }
      service_hash.update(param)
      #
      service_params = signed_service_params(@aws_secret_access_key, service_hash, :post, @params[:server], service)
      request        = Net::HTTP::Post.new(AwsUtils::URLencode(service))
      request['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8'
      request.body = service_params
        # prepare output hash
      { :request  => request, 
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol] }
    end


      # Sends request to Amazon and parses the response
      # Raises AwsError if any banana happened
    def request_info(request, parser) # :nodoc:
      request_info_impl(:sqs_connection, @@bench, request, parser)
    end

      # Creates a new queue, returning its URI.
      #
      #  sqs.create_queue('my_awesome_queue') #=> 'https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue'
      #
    def create_queue(queue_name, default_visibility_timeout=nil)
      req_hash = generate_request('CreateQueue', 'QueueName' => queue_name,
                                  'DefaultVisibilityTimeout' => default_visibility_timeout || DEFAULT_VISIBILITY_TIMEOUT )
      request_info(req_hash, SqsCreateQueueParser.new(:logger => @logger))
    rescue
      on_exception
    end

     # Lists all queues owned by this user that have names beginning with +queue_name_prefix+. 
     # If +queue_name_prefix+ is omitted then retrieves a list of all queues.
     # Queue creation is an eventual operation and created queues may not show up in immediately subsequent list_queues calls.
     #
     #  sqs.create_queue('my_awesome_queue')
     #  sqs.create_queue('my_awesome_queue_2')
     #  sqs.list_queues('my_awesome') #=> ['https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue','https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue_2']
     #
    def list_queues(queue_name_prefix=nil)
      req_hash = generate_request('ListQueues', 'QueueNamePrefix' => queue_name_prefix)
      request_info(req_hash, SqsListQueuesParser.new(:logger => @logger))
    rescue
      on_exception
    end
      
      # Deletes queue. Any messages in the queue are permanently lost. 
      # Returns +true+ or an exception.
      # Queue deletion can take up to 60 s to propagate through SQS.  Thus, after a deletion, subsequent list_queues calls
      # may still show the deleted queue.  It is not unusual within the 60 s window to see the deleted queue absent from 
      # one list_queues call but present in the subsequent one.  Deletion is eventual.
      #
      #  sqs.delete_queue('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue_2') #=> true
      # 
    def delete_queue(queue_url)
      req_hash = generate_request('DeleteQueue', :queue_url => queue_url)
      request_info(req_hash, SqsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end

      # Retrieves the queue attribute(s). Returns a hash of attribute(s) or an exception.
      #
      #  sqs.get_queue_attributes('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue') #=>
      #    {"ApproximateNumberOfMessages" => "0",
      #     "LastModifiedTimestamp"       => "1240946032",
      #     "CreatedTimestamp"            => "1240816887",
      #     "VisibilityTimeout"           => "30",
      #     "Policy"                      => "{"Version":"2008-10-17","Id":...}"}
      #     
      #  queue.get_queue_attributes('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue', "LastModifiedTimestamp", "VisibilityTimeout") #=>
      #    {"LastModifiedTimestamp" => "1240946032",
      #     "VisibilityTimeout"     => "30"}
      #
      # http://docs.amazonwebservices.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/index.html?Query_QueryGetQueueAttributes.html
    def get_queue_attributes(queue_url, *attributes)
      attributes.flatten!
      attributes << 'All' if attributes.blank?
      params = amazonize_list('AttributeName', attributes)
      params.merge!(:queue_url  => queue_url)
      req_hash = generate_request('GetQueueAttributes', params)
      request_info(req_hash, SqsGetQueueAttributesParser.new(:logger => @logger))
    rescue
      on_exception
    end

      # Sets queue attribute. Returns +true+ or an exception.
      #
      #  sqs.set_queue_attributes('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue', "VisibilityTimeout", 10) #=> true
      #
      # From the SQS Dev Guide:
      # "When you change a queue's attributes, the change can take up to 60 seconds to propagate 
      # throughout the SQS system."
      #
      # NB: Attribute values may not be immediately available to other queries
      # for some time after an update. See the SQS documentation for
      # semantics, but in general propagation can take up to 60 s.
      # 
      #  see http://docs.amazonwebservices.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/index.html?Query_QuerySetQueueAttributes.html
    def set_queue_attributes(queue_url, attribute, value)
      req_hash = generate_request('SetQueueAttributes', 
                                  'Attribute.Name'  => attribute,
                                  'Attribute.Value' => value,
                                  :queue_url        => queue_url)
      request_info(req_hash, SqsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end

    # Add permissions to a queue.
    #
    #  sqs.add_permissions('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue',
    #                     'testLabel', ['125074342641','125074342642'],
    #                     ['SendMessage','SendMessage','ReceiveMessage']) #=> true
    #
    #  +permissions+ is a hash of: AccountId => ActionName
    #  (valid ActionNames: * | SendMessage | ReceiveMessage | DeleteMessage | ChangeMessageVisibility | GetQueueAttributes )
    #
    #  see http://docs.amazonwebservices.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/index.html?Query_QueryAddPermission.html
    #      http://docs.amazonwebservices.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/index.html?acp-overview.html
    def add_permissions(queue_url, label, grantees, actions)
      params      = amazonize_list('AWSAccountId', Array(grantees))
      params.merge!(amazonize_list('ActionName', Array(actions)))
      params.merge!('Label'    => label,
                    :queue_url => queue_url )
      req_hash = generate_request('AddPermission', params)
      request_info(req_hash, SqsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end

    # Revoke any permissions in the queue policy that matches the +label+ parameter.
    #
    #  sqs.remove_permissions('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue',
    #                        'testLabel') # => true
    #
    #  see http://docs.amazonwebservices.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/index.html?Query_QueryRemovePermission.html
    def remove_permissions(queue_url, label)
      req_hash = generate_request('RemovePermission',
                                  'Label'    => label,
                                  :queue_url => queue_url )
      request_info(req_hash, SqsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end

      # Retrieves a list of messages from queue. Returns an array of hashes in format: <tt>{:id=>'message_id', :body=>'message_body'}</tt>
      #
      #   sqs.receive_message('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue',10, 5) #=>
      #    [{"ReceiptHandle"=>"Euvo62...kw==", "MD5OfBody"=>"16af2171b5b83cfa35ce254966ba81e3", 
      #      "Body"=>"Goodbyte World!", "MessageId"=>"MUM4WlAyR...pYOTA="}, ..., {}]
      #
      # Normally this call returns fewer messages than the maximum specified,
      # even if they are available.
      #
    def receive_message(queue_url, max_number_of_messages=1, visibility_timeout=nil, attributes=nil)
      return [] if max_number_of_messages == 0
      params = {}
      params.merge!(amazonize_list('AttributeName', Array(attributes))) unless attributes.blank?
      params.merge!('MaxNumberOfMessages' => max_number_of_messages,
                    'VisibilityTimeout'   => visibility_timeout,
                    :queue_url            => queue_url )
      req_hash = generate_post_request('ReceiveMessage', params)
      request_info(req_hash, SqsReceiveMessageParser.new(:logger => @logger))
    rescue
      on_exception
    end

    # Change the visibility timeout of a specified message in a queue.
    #
    #  sqs.change_message_visibility('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue', 'Euvo62...kw==', 33) #=> true
    #
    #  see http://docs.amazonwebservices.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/index.html?Query_QueryChangeMessageVisibility.html
    def change_message_visibility(queue_url, receipt_handle, visibility_timeout)
      req_hash = generate_request('ChangeMessageVisibility',
                                  'ReceiptHandle'     => receipt_handle,
                                  'VisibilityTimeout' => visibility_timeout,
                                  :queue_url          => queue_url )
      request_info(req_hash, SqsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end
    
      # Sends a new message to a queue.  Message size is limited to 8 KB.
      # If successful, this call returns a hash containing key/value pairs for
      # "MessageId" and "MD5OfMessageBody":
      #
      #  sqs.send_message('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue', 'message_1') #=> 
      #    {"MessageId"=>"MEs4M0JKNlRCRTBBSENaMjROTk58QVFRNzNEREhDVFlFOVJDQ1JKNjF8UTdBRllCUlJUMjhKMUI1WDJSWDE=",
      #     "MD5OfMessageBody"=>"16af2171b5b83cfa35ce254966ba81e3"}
      #
      # On failure, send_message raises an exception.
      #
      #
    def send_message(queue_url, message)
      req_hash = generate_post_request('SendMessage', :message  => message, :queue_url => queue_url)
      request_info(req_hash, SqsSendMessagesParser.new(:logger => @logger))
    rescue
      on_exception
    end

      # Same as send_message
    alias_method :push_message, :send_message
    
    
      # Deletes message from queue. Returns +true+ or an exception.  Amazon
      # returns +true+ on deletion of non-existent messages.  You must use the
      # receipt handle for a message to delete it, not the message ID.  
      #
      # From the SQS Developer Guide:
      # "It is possible you will receive a message even after you have deleted it. This might happen 
      # on rare occasions if one of the servers storing a copy of the message is unavailable when 
      # you request to delete the message. The copy remains on the server and might be returned to 
      # you again on a subsequent receive request. You should create your system to be 
      # idempotent so that receiving a particular message more than once is not a problem. "
      #
      #  sqs.delete_message('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue', 'Euvo62/1nlIet...ao03hd9Sa0w==') #=> true
      #
    def delete_message(queue_url, receipt_handle)
      req_hash = generate_request('DeleteMessage', 'ReceiptHandle' => receipt_handle, :queue_url  => queue_url)
      request_info(req_hash, SqsStatusParser.new(:logger => @logger))
    rescue
      on_exception
    end
    
      # Given the queue's short name, this call returns the queue URL or +nil+ if queue is not found
      #  sqs.queue_url_by_name('my_awesome_queue') #=> 'https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue'
      #
    def queue_url_by_name(queue_name)
      return queue_name if queue_name.include?('/')
      queue_urls = list_queues(queue_name)
      queue_urls.each do |queue_url|
        return queue_url if queue_name_by_url(queue_url) == queue_name
      end
      nil
    rescue
      on_exception
    end

      # Returns short queue name by url.
      #
      #  RightSqs.queue_name_by_url('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue') #=> 'my_awesome_queue'
      #
    def self.queue_name_by_url(queue_url)
      queue_url[/[^\/]*$/]
    rescue
      on_exception
    end
    
      # Returns short queue name by url.
      #
      #  sqs.queue_name_by_url('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue') #=> 'my_awesome_queue'
      #
    def queue_name_by_url(queue_url)
      self.class.queue_name_by_url(queue_url)
    rescue
      on_exception
    end

      # Returns approximate number of messages in queue.
      #
      #  sqs.get_queue_length('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue') #=> 3
      #
    def get_queue_length(queue_url)
      attrs = get_queue_attributes(queue_url)
      attrs['ApproximateNumberOfMessages'].to_i +
      attrs['ApproximateNumberOfMessagesNotVisible'].to_i
    rescue
      on_exception
    end

      # Removes all visible messages from queue. Return +true+ or an exception.
      #
      #  sqs.clear_queue('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue') #=> true
      #
    def clear_queue(queue_url)
      while (pop_messages(queue_url, 10).length > 0) ; end   # delete all messages in queue
      true
    rescue
      on_exception
    end

      # Pops (retrieves and deletes) up to 'number_of_messages' from queue. Returns an array of retrieved messages in format: <tt>[{:id=>'message_id', :body=>'message_body'}]</tt>.
      #
      #   sqs.pop_messages('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue', 3) #=>
      #   [{"ReceiptHandle"=>"Euvo62/...+Zw==", "MD5OfBody"=>"16af2...81e3", "Body"=>"Goodbyte World!", 
      #   "MessageId"=>"MEZI...JSWDE="}, {...}, ... , {...} ]
      #
    def pop_messages(queue_url, number_of_messages=1, attributes=nil)
      messages = receive_message(queue_url, number_of_messages, nil, attributes)
      messages.each do |message|
        delete_message(queue_url, message['ReceiptHandle'])
      end
      messages
    rescue
      on_exception
    end

      # Pops (retrieves and  deletes) first accessible message from queue. Returns the message in format <tt>{:id=>'message_id', :body=>'message_body'}</tt> or +nil+.
      #
      #  sqs.pop_message('https://queue.amazonaws.com/ZZ7XXXYYYBINS/my_awesome_queue') #=>
      #    {:id=>"12345678904GEZX9746N|0N9ED344VK5Z3SV1DTM0|1RVYH4X3TJ0987654321", :body=>"message_1"}
      #
    def pop_message(queue_url, attributes=nil)
      messages = pop_messages(queue_url, 1, attributes)
      messages.blank? ? nil : messages[0]
    rescue
      on_exception
    end

    #-----------------------------------------------------------------
    #      PARSERS: Status Response Parser
    #-----------------------------------------------------------------

    class SqsStatusParser < RightAWSParser # :nodoc:
      def tagend(name)
        if name == 'ResponseMetadata'
          @result = true
        end
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Queue
    #-----------------------------------------------------------------

    class SqsCreateQueueParser < RightAWSParser # :nodoc:
      def tagend(name)
        @result = @text if name == 'QueueUrl'
      end
    end

    class SqsListQueuesParser < RightAWSParser # :nodoc:
      def reset
        @result = []
      end
      def tagend(name)
        @result << @text if name == 'QueueUrl'
      end
    end

    class SqsGetQueueAttributesParser < RightAWSParser # :nodoc:
      def reset
        @result = {}
      end
      def tagend(name)
        case name 
          when 'Name'  then @current_attribute          = @text
          when 'Value' then @result[@current_attribute] = @text
        end
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Messages
    #-----------------------------------------------------------------

    class SqsReceiveMessageParser < RightAWSParser # :nodoc:
      def reset
        @result = []
      end
      def tagstart(name, attributes)
        case name
        when 'Message' then @current_message = { }
        when 'Attribute' then
          @current_message['Attributes'] ||= {}
          @current_attribute_name  = ''
          @current_attribute_value = ''
        end
      end
      def tagend(name)
        case name
        when 'MessageId'     then @current_message['MessageId']     = @text
        when 'ReceiptHandle' then @current_message['ReceiptHandle'] = @text
        when 'MD5OfBody'     then @current_message['MD5OfBody']     = @text
        when 'Name'          then @current_attribute_name  = @text
        when 'Value'         then @current_attribute_value = @text
        when 'Attribute'     then @current_message['Attributes'][@current_attribute_name] = @current_attribute_value
        when 'Body'          then @current_message['Body'] = @text; @result << @current_message
        end
      end
    end

    class SqsSendMessagesParser < RightAWSParser # :nodoc:
      def reset
        @result = {}
      end
      def tagend(name)
        case name
          when 'MessageId'        then @result['MessageId']        = @text
          when 'MD5OfMessageBody' then @result['MD5OfMessageBody'] = @text
        end
      end
    end
    
  end

end
