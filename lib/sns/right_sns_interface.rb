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
  class SnsInterface < RightAwsBase
    include RightAwsBaseInterface

    DEFAULT_HOST        = 'sns.us-east-1.amazonaws.com'
    DEFAULT_PORT        = 443
    DEFAULT_PROTOCOL    = 'https'
    DEFAULT_SERVICE     = '/'
    REQUEST_TTL         = 30

    # Apparently boilerplate stuff
    @@bench = AwsBenchmarkingBlock.new
    def self.bench_xml
      @@bench.xml
    end
    def self.bench_service
      @@bench.service
    end

    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      if params[:region]
        server = "sns.#{params[:region]}.amazonaws.com"
        params.delete(:region)
      else
        server = DEFAULT_HOST
      end
      init({  :name               => 'SNS',
              :default_host       => ENV['SNS_URL'] ? URI.parse(ENV['SNS_URL']).host    : server,
              :default_port       => ENV['SNS_URL'] ? URI.parse(ENV['SNS_URL']).port    : DEFAULT_PORT,
              :default_service    => ENV['SNS_URL'] ? URI.parse(ENV['SNS_URL']).path    : DEFAULT_SERVICE,
              :default_protocol   => ENV['SNS_URL'] ? URI.parse(ENV['SNS_URL']).scheme  : DEFAULT_PROTOCOL},
           aws_access_key_id     || ENV['AWS_ACCESS_KEY_ID'],
           aws_secret_access_key || ENV['AWS_SECRET_ACCESS_KEY'],
           params)
    end

    # TODO: RJG - Seems like generate_request and generate_rest_request could be in a sub class?
    # Generates a request hash for the sns API
    def generate_request(action, params={})  # :nodoc:
        # Sometimes we need to use queue uri (delete queue etc)
        # In that case we will use Symbol key: 'param[:queue_url]'
      service = params[:sns_url] ? URI(params[:sns_url]).path : '/'
        # remove unset(=optional) and symbolyc keys
      params.each{ |key, value| params.delete(key) if (value.nil? || key.is_a?(Symbol)) }
        # prepare output hash
      service_hash = { "Action"           => action,
                       "Expires"          => (Time.now + REQUEST_TTL).utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "AWSAccessKeyId"   => @aws_access_key_id }
                       #"Version"          => API_VERSION }
      service_hash.update(params)
      service_params = signed_service_params(@aws_secret_access_key, service_hash, :get, @params[:server], service)
      request        = Net::HTTP::Get.new("#{AwsUtils::URLencode(service)}?#{service_params}")
        # prepare output hash
      { :request  => request,
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol] }
    end

    # Generates a request hash for the REST API
    def generate_rest_request(method, param) # :nodoc:
      sns_uri = param[:sns_url] ? URI(param[:sns_url]).path : '/'
      message   = param[:message]                # extract message body if nesessary
        # remove unset(=optional) and symbolyc keys
      param.each{ |key, value| param.delete(key) if (value.nil? || key.is_a?(Symbol)) }
        # created request
      param_to_str = param.to_a.collect{|key,val| key.to_s + "=" + CGI::escape(val.to_s) }.join("&")
      param_to_str = "?#{param_to_str}" unless param_to_str.right_blank?
      request = "Net::HTTP::#{method.capitalize}".right_constantize.new("#{sns_uri}#{param_to_str}")
      request.body = message if message
        # set main headers
      request['content-md5']  = ''
      request['Content-Type'] = 'text/plain'
      request['Date']         = Time.now.httpdate
        # generate authorization string
      auth_string = "#{method.upcase}\n#{request['content-md5']}\n#{request['Content-Type']}\n#{request['Date']}\n#{CGI::unescape(sns_uri)}"
      signature   = AwsUtils::sign(@aws_secret_access_key, auth_string)
        # set other headers
      request['Authorization'] = "AWS #{@aws_access_key_id}:#{signature}"
      #request['AWS-Version']   = API_VERSION
        # prepare output hash
      { :request  => request,
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol] }
    end

    # Sends request to Amazon and parses the response
      # Raises AwsError if any banana happened
    def request_info(request, parser) # :nodoc:
      request_info_impl(:sns_connection, @@bench, request, parser)
    end

    def create_topic(topic_name)
      req_hash = generate_request('CreateTopic', 'Name' => topic_name)
      request_info(req_hash, SnsCreateTopicParser.new)
    end

    def list_topics()
      req_hash = generate_request('ListTopics')
      request_info(req_hash, SnsListTopicsParser.new)
    end

    def delete_topic(topic_arn)
      req_hash = generate_request('DeleteTopic', 'TopicArn' => topic_arn)
      request_info(req_hash, RightHttp2xxParser.new)
    end

    def subscribe(topic_arn, protocol, endpoint)
      req_hash = generate_request('Subscribe', 'TopicArn' => topic_arn, 'Protocol' => protocol, 'Endpoint' => endpoint)
      request_info(req_hash, SnsSubscribeParser.new)
    end

    def unsubscribe(subscription_arn)
      req_hash = generate_request('Unsubscribe', 'SubscriptionArn' => subscription_arn)
      request_info(req_hash, RightHttp2xxParser.new)
    end

    def publish(topic_arn, message, subject)
      req_hash = generate_request('Publish', 'TopicArn' => topic_arn, 'Message' => message, 'Subject' => subject)
      request_info(req_hash, SnsPublishParser.new)
    end

    def set_topic_attribute(topic_arn, attribute_name, attribute_value)
      if attribute_name != 'Policy' && attribute_name != 'DisplayName'
        raise(ArgumentError, "The only values accepted for the attribute_name parameter are (Policy, DisplayName)")
      end
      req_hash = generate_request('SetTopicAttributes', 'TopicArn' => topic_arn, 'AttributeName' => attribute_name, 'AttributeValue' => attribute_value)
      request_info(req_hash, RightHttp2xxParser.new)
    end

    def get_topic_attributes(topic_arn)
      req_hash = generate_request('GetTopicAttributes', 'TopicArn' => topic_arn)
      request_info(req_hash, SnsGetTopicAttributesParser.new)
    end

    # Calls either the ListSubscriptions or ListSubscriptionsByTopic depending on whether or not the topic_arn parameter is provided.
    def list_subscriptions(topic_arn = nil)
      req_hash = topic_arn ? generate_request('ListSubscriptionsByTopic', 'TopicArn' => topic_arn) : generate_request('ListSubscriptions')
      request_info(req_hash, SnsListSubscriptionsParser.new)
    end

    def confirm_subscription(topic_arn, token, authenticate_on_unsubscribe=false)
      req_hash = generate_request('ConfirmSubscription', 'AuthenticateOnUnsubscribe' => authenticate_on_unsubscribe.to_s, 'Token' => token, 'TopicArn' => topic_arn)
      request_info(req_hash, SnsConfirmSubscriptionParser.new)
    end

    def add_permission(topic_arn, label, acct_action_hash_ary)
      n_hash = {
        'TopicArn'  => topic_arn,
        'Label'     => label
      }

      acct_action_hash_ary.each_with_index do |hash_val, idx|
        n_hash["AWSAccountId.member.#{idx+1}"]  = hash_val[:aws_account_id]
        n_hash["ActionName.member.#{idx+1}"]    = hash_val[:action]
      end

      req_hash = generate_request('AddPermission', n_hash)
      request_info(req_hash, RightHttp2xxParser.new)
    end

    def remove_permission(topic_arn, label)
      req_hash = generate_request('RemovePermission', 'TopicArn' => topic_arn, 'Label' => label)
      request_info(req_hash, RightHttp2xxParser.new)
    end

    class SnsCreateTopicParser < RightAWSParser # :nodoc:
      def reset
        @result  = ''
        @request_id = ''
      end
      def tagend(name)
        case name
          when 'RequestId'  then @result_id = @text
          when 'TopicArn'   then @result = @text
        end
      end
    end

    class SnsListTopicsParser < RightAWSParser # :nodoc:
      def reset
        @result     = []
        @request_id = ''
      end
      def tagstart(name, attributes)
        @current_key = {} if name == 'member'
      end
      def tagend(name)
        case name
          when 'RequestId'  then @result_id         = @text
          when 'TopicArn'   then @current_key[:arn] = @text
          when 'member'     then @result << @current_key
        end
      end
    end

    class SnsSubscribeParser < RightAWSParser # :nodoc:
      def reset
        @result = ''
      end
      def tagend(name)
        case name
          when 'SubscriptionArn' then @result = @text
        end
      end
    end

    class SnsPublishParser < RightAWSParser # :nodoc:
      def reset
        @result = ''
      end
      def tagend(name)
        case name
          when 'MessageId' then @result = @text
        end
      end
    end

    class SnsGetTopicAttributesParser < RightAWSParser # :nodoc:
      def reset
        @result = {}
      end
      def tagend(name)
        case name
          when 'key' then @current_attr = @text
          when 'value' then @result[@current_attr] = @text
        end
      end
    end

    class SnsListSubscriptionsParser < RightAWSParser # :nodoc:
      def reset
        @result = []
      end
      def tagstart(name, attributes)
        @current_key = {} if name == 'member'
      end
      def tagend(name)
        case name
          when 'TopicArn'         then @current_key[:topic_arn]         = @text
          when 'Protocol'         then @current_key[:protocol]          = @text
          when 'SubscriptionArn'  then @current_key[:subscription_arn]  = @text
          when 'Owner'            then @current_key[:owner]             = @text
          when 'Endpoint'         then @current_key[:endpoint]          = @text
          when 'member'     then @result << @current_key
        end
      end
    end

    class SnsConfirmSubscriptionParser < RightAWSParser # :nodoc:
      def reset
        @result = ''
      end
      def tagend(name)
        case name
          when 'SubscriptionArn' then @result = @text
        end
      end
    end

  end
end
