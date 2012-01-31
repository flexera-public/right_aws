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

# Test
module RightAws
  require 'digest/md5'
  
  class AwsUtils #:nodoc:
    @@digest1   = OpenSSL::Digest::Digest.new("sha1")
    @@digest256 = nil
    if OpenSSL::OPENSSL_VERSION_NUMBER > 0x00908000
      @@digest256 = OpenSSL::Digest::Digest.new("sha256") rescue nil # Some installation may not support sha256
    end

    def self.utc_iso8601(time)
      if    time.is_a?(Fixnum) then time = Time::at(time)
      elsif time.is_a?(String) then time = Time::parse(time)
      end
      time.utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end
    
    def self.sign(aws_secret_access_key, auth_string)
      Base64.encode64(OpenSSL::HMAC.digest(@@digest1, aws_secret_access_key, auth_string)).strip
    end

    # Calculates 'Content-MD5' header value for some content
    def self.content_md5(content)
      Base64.encode64(Digest::MD5::new.update(content).digest).strip
    end

    # Escape a string accordingly Amazon rulles
    # http://docs.amazonwebservices.com/AmazonSimpleDB/2007-11-07/DeveloperGuide/index.html?REST_RESTAuth.html
    def self.amz_escape(param)
      param.to_s.gsub(/([^a-zA-Z0-9._~-]+)/n) do
        '%' + $1.unpack('H2' * $1.size).join('%').upcase
      end
    end

    def self.xml_escape(text) # :nodoc:
      REXML::Text::normalize(text)
    end

    def self.xml_unescape(text) # :nodoc:
      REXML::Text::unnormalize(text)
    end

    # Set a timestamp and a signature version
    def self.fix_service_params(service_hash, signature)
      service_hash["Timestamp"] ||= utc_iso8601(Time.now) unless service_hash["Expires"]
      service_hash["SignatureVersion"] = signature
      service_hash
    end

    # Signature Version 0
    # A deprecated guy (should work till septemper 2009)
    def self.sign_request_v0(aws_secret_access_key, service_hash)
      fix_service_params(service_hash, '0')
      string_to_sign = "#{service_hash['Action']}#{service_hash['Timestamp'] || service_hash['Expires']}"
      service_hash['Signature'] = AwsUtils::sign(aws_secret_access_key, string_to_sign)
      service_hash.to_a.collect{|key,val| "#{amz_escape(key)}=#{amz_escape(val.to_s)}" }.join("&")
    end

    # Signature Version 1
    # Another deprecated guy (should work till septemper 2009)
    def self.sign_request_v1(aws_secret_access_key, service_hash)
      fix_service_params(service_hash, '1')
      string_to_sign = service_hash.sort{|a,b| (a[0].to_s.downcase)<=>(b[0].to_s.downcase)}.to_s
      service_hash['Signature'] = AwsUtils::sign(aws_secret_access_key, string_to_sign)
      service_hash.to_a.collect{|key,val| "#{amz_escape(key)}=#{amz_escape(val.to_s)}" }.join("&")
    end

    # Signature Version 2
    # EC2, SQS and SDB requests must be signed by this guy.
    # See:  http://docs.amazonwebservices.com/AmazonSimpleDB/2007-11-07/DeveloperGuide/index.html?REST_RESTAuth.html
    #       http://developer.amazonwebservices.com/connect/entry.jspa?externalID=1928
    def self.sign_request_v2(aws_secret_access_key, service_hash, http_verb, host, uri)
      fix_service_params(service_hash, '2')
      # select a signing method (make an old openssl working with sha1)
      # make 'HmacSHA256' to be a default one
      service_hash['SignatureMethod'] = 'HmacSHA256' unless ['HmacSHA256', 'HmacSHA1'].include?(service_hash['SignatureMethod'])
      service_hash['SignatureMethod'] = 'HmacSHA1'   unless @@digest256
      # select a digest
      digest = (service_hash['SignatureMethod'] == 'HmacSHA256' ? @@digest256 : @@digest1)
      # form string to sign
      canonical_string = service_hash.keys.sort.map do |key|
        "#{amz_escape(key)}=#{amz_escape(service_hash[key])}"
      end.join('&')
      string_to_sign = "#{http_verb.to_s.upcase}\n#{host.downcase}\n#{uri}\n#{canonical_string}"
      # sign the string
      signature      = amz_escape(Base64.encode64(OpenSSL::HMAC.digest(digest, aws_secret_access_key, string_to_sign)).strip)
      "#{canonical_string}&Signature=#{signature}"
    end

    # From Amazon's SQS Dev Guide, a brief description of how to escape:
    # "URL encode the computed signature and other query parameters as specified in 
    # RFC1738, section 2.2. In addition, because the + character is interpreted as a blank space 
    # by Sun Java classes that perform URL decoding, make sure to encode the + character 
    # although it is not required by RFC1738."
    # Avoid using CGI::escape to escape URIs. 
    # CGI::escape will escape characters in the protocol, host, and port
    # sections of the URI.  Only target chars in the query
    # string should be escaped.
    def self.URLencode(raw)
      e = URI.escape(raw)
      e.gsub(/\+/, "%2b")
    end
    
    def self.allow_only(allowed_keys, params)
      bogus_args = []
      params.keys.each {|p| bogus_args.push(p) unless allowed_keys.include?(p) }
      raise AwsError.new("The following arguments were given but are not legal for the function call #{caller_method}: #{bogus_args.inspect}") if bogus_args.length > 0
    end
    
    def self.mandatory_arguments(required_args, params)
      rargs = required_args.dup
      params.keys.each {|p| rargs.delete(p)}
      raise AwsError.new("The following mandatory arguments were not provided to #{caller_method}: #{rargs.inspect}") if rargs.length > 0
    end
    
    def self.caller_method
      caller[1]=~/`(.*?)'/
      $1
    end

    def self.split_items_and_params(array)
      items  = Array(array).flatten.compact
      params = items.last.kind_of?(Hash) ? items.pop : {}
      [items, params]
    end

    # Generates a token in format of:
    #  1. "1dd8d4e4-db6b-11df-b31d-0025b37efad0 (if UUID gem is loaded)
    #  2. "1287483761-855215-zSv2z-bWGj2-31M5t-ags9m" (if UUID gem is not loaded)
    TOKEN_GENERATOR_CHARSET = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a
    def self.generate_unique_token
      time  = Time.now
      token = "%d-%06d" % [time.to_i, time.usec]
      4.times do
        token << "-"
        5.times { token << TOKEN_GENERATOR_CHARSET[rand(TOKEN_GENERATOR_CHARSET.size)] }
      end
      token
    end
  end

  class AwsBenchmarkingBlock #:nodoc:
    attr_accessor :xml, :service
    def initialize
      # Benchmark::Tms instance for service (Ec2, S3, or SQS) access benchmarking.
      @service = Benchmark::Tms.new()
      # Benchmark::Tms instance for XML parsing benchmarking.
      @xml = Benchmark::Tms.new()
    end
  end

  class AwsNoChange < RuntimeError
  end
  
  class RightAwsBase

    # Amazon HTTP Error handling

    # Text, if found in an error message returned by AWS, indicates that this may be a transient
    # error. Transient errors are automatically retried with exponential back-off.
    AMAZON_PROBLEMS = [ 'internal service error', 
                        'is currently unavailable',
                        'no response from',
                        'Please try again',
                        'InternalError',
                        'Internal Server Error',
                        'ServiceUnavailable', #from SQS docs
                        'Unavailable',
                        'This application is not currently available',
                        'InsufficientInstanceCapacity'
                      ]
    @@amazon_problems = AMAZON_PROBLEMS
      # Returns a list of Amazon service responses which are known to be transient problems. 
      # We have to re-request if we get any of them, because the problem will probably disappear. 
      # By default this method returns the same value as the AMAZON_PROBLEMS const.
    def self.amazon_problems
      @@amazon_problems
    end
    
      # Sets the list of Amazon side problems.  Use in conjunction with the
      # getter to append problems.
    def self.amazon_problems=(problems_list)
      @@amazon_problems = problems_list
    end

    # Raise an exception if a timeout occures while an API call is in progress.
    # This helps to avoid a duplicate resources creation when Amazon hangs for some time and
    # RightHttpConnection is forced to use retries to get a response from it.
    #
    # If an API call action is in the list then no attempts to retry are performed.
    #
    RAISE_ON_TIMEOUT_ON_ACTIONS = %w{ 
      AllocateAddress
      CreateSnapshot
      CreateVolume
      PurchaseReservedInstancesOffering
      RequestSpotInstances
      RunInstances
    }
    @@raise_on_timeout_on_actions = RAISE_ON_TIMEOUT_ON_ACTIONS.dup

    def self.raise_on_timeout_on_actions
      @@raise_on_timeout_on_actions
    end

    def self.raise_on_timeout_on_actions=(actions_list)
      @@raise_on_timeout_on_actions = actions_list
    end

  end

  module RightAwsBaseInterface
    DEFAULT_SIGNATURE_VERSION = '2'
    
    @@caching = false
    def self.caching
      @@caching
    end
    def self.caching=(caching)
      @@caching = caching
    end

      # Current aws_access_key_id
    attr_reader :aws_access_key_id
      # Current aws_secret_access_key
    attr_reader :aws_secret_access_key
      # Last HTTP request object
    attr_reader :last_request
      # Last HTTP response object
    attr_reader :last_response
      # Last AWS errors list (used by AWSErrorHandler)
    attr_accessor :last_errors
      # Last AWS request id (used by AWSErrorHandler)
    attr_accessor :last_request_id
      # Logger object
    attr_accessor :logger
      # Initial params hash
    attr_accessor :params
      # RightHttpConnection instance
    attr_reader :connection
      # Cache
    attr_reader :cache
      # Signature version (all services except s3)
    attr_reader :signature_version

    def init(service_info, aws_access_key_id, aws_secret_access_key, params={}) #:nodoc:
      @params = params
      # If one defines EC2_URL he may forget to use a single slash as an "empty service" path.
      # Amazon does not like this therefore add this bad boy if he is missing...
      service_info[:default_service] = '/' if service_info[:default_service].right_blank?
      raise AwsError.new("AWS access keys are required to operate on #{service_info[:name]}") \
        if aws_access_key_id.right_blank? || aws_secret_access_key.right_blank?
      @aws_access_key_id     = aws_access_key_id
      @aws_secret_access_key = aws_secret_access_key
      # if the endpoint was explicitly defined - then use it
      if @params[:endpoint_url]
        uri = URI.parse(@params[:endpoint_url])
        @params[:server]   = uri.host
        @params[:port]     = uri.port
        @params[:service]  = uri.path
        @params[:protocol] = uri.scheme
        # make sure the 'service' path is not empty
        @params[:service]  = service_info[:default_service] if @params[:service].right_blank?
        @params[:region]   = nil
        default_port       = uri.default_port
      else
        @params[:server]   ||= service_info[:default_host]
        @params[:server]     = "#{@params[:region]}.#{@params[:server]}" if @params[:region]
        @params[:port]     ||= service_info[:default_port]
        @params[:service]  ||= service_info[:default_service]
        @params[:protocol] ||= service_info[:default_protocol]
        default_port         = @params[:protocol] == 'https' ? 443 : 80
      end
      # build a host name to sign
      @params[:host_to_sign]  = @params[:server].dup
      @params[:host_to_sign] << ":#{@params[:port]}" unless default_port == @params[:port].to_i
      # a set of options to be passed to RightHttpConnection object
      @params[:connection_options] = {} unless @params[:connection_options].is_a?(Hash) 
      @with_connection_options = {}
      @params[:connections] ||= :shared # || :dedicated
      @params[:max_connections] ||= 10
      @params[:connection_lifetime] ||= 20*60
      @params[:api_version]  ||= service_info[:default_api_version]
      @logger = @params[:logger]
      @logger = ::Rails.logger       if !@logger && defined?(::Rails) && ::Rails.respond_to?(:logger)
      @logger = RAILS_DEFAULT_LOGGER if !@logger && defined?(RAILS_DEFAULT_LOGGER)
      @logger = Logger.new(STDOUT)   if !@logger
      @logger.info "New #{self.class.name} using #{@params[:connections]} connections mode"
      @error_handler = nil
      @cache = {}
      @signature_version = (params[:signature_version] || DEFAULT_SIGNATURE_VERSION).to_s
    end

    def signed_service_params(aws_secret_access_key, service_hash, http_verb=nil, host=nil, service=nil )
      case signature_version.to_s
      when '0' then AwsUtils::sign_request_v0(aws_secret_access_key, service_hash)
      when '1' then AwsUtils::sign_request_v1(aws_secret_access_key, service_hash)
      when '2' then AwsUtils::sign_request_v2(aws_secret_access_key, service_hash, http_verb, host, service)
      else raise AwsError.new("Unknown signature version (#{signature_version.to_s}) requested")
      end
    end

    # Returns +true+ if the describe_xxx responses are being cached 
    def caching?
      @params.key?(:cache) ? @params[:cache] : @@caching
    end
    
    # Check if the aws function response hits the cache or not.
    # If the cache hits:
    # - raises an +AwsNoChange+ exception if +do_raise+ == +:raise+.
    # - returnes parsed response from the cache if it exists or +true+ otherwise.
    # If the cache miss or the caching is off then returns +false+.
    def cache_hits?(function, response, do_raise=:raise)
      result = false
      if caching?
        function = function.to_sym
        # get rid of requestId (this bad boy was added for API 2008-08-08+ and it is uniq for every response)
        # feb 04, 2009 (load balancer uses 'RequestId' hence use 'i' modifier to hit it also)
        response = response.sub(%r{<requestId>.+?</requestId>}i, '')
        # this should work for both ruby 1.8.x and 1.9.x
        response_md5 = Digest::MD5::new.update(response).to_s
        # check for changes
        unless @cache[function] && @cache[function][:response_md5] == response_md5
          # well, the response is new, reset cache data
          update_cache(function, {:response_md5 => response_md5, 
                                  :timestamp    => Time.now, 
                                  :hits         => 0, 
                                  :parsed       => nil})
        else
          # aha, cache hits, update the data and throw an exception if needed
          @cache[function][:hits] += 1
          if do_raise == :raise
            raise(AwsNoChange, "Cache hit: #{function} response has not changed since "+
                               "#{@cache[function][:timestamp].strftime('%Y-%m-%d %H:%M:%S')}, "+
                               "hits: #{@cache[function][:hits]}.")
          else
            result = @cache[function][:parsed] || true
          end
        end
      end
      result
    end
    
    def update_cache(function, hash)
      (@cache[function.to_sym] ||= {}).merge!(hash) if caching?
    end
    
    def on_exception(options={:raise=>true, :log=>true}) # :nodoc:
      raise if $!.is_a?(AwsNoChange)
      AwsError::on_aws_exception(self, options)
    end

    #----------------------------
    # HTTP Connections handling
    #----------------------------

    def get_server_url(request) # :nodoc:
      "#{request[:protocol]}://#{request[:server]}:#{request[:port]}"
    end

    def get_connections_storage(aws_service) # :nodoc:
      case @params[:connections].to_s
      when 'dedicated' then @connections_storage        ||= {}
      else                  Thread.current[aws_service] ||= {}
      end
    end

    def destroy_connection(request, reason) # :nodoc:
      connections = get_connections_storage(request[:aws_service])
      server_url  = get_server_url(request)
      if connections[server_url]
        connections[server_url][:connection].finish(reason)
        connections.delete(server_url)
      end
    end

    # Expire the connection if it has expired.
    def get_connection(request) # :nodoc:
      server_url         = get_server_url(request)
      connection_storage = get_connections_storage(request[:aws_service])
      life_time_scratch  = Time.now-@params[:connection_lifetime]
      # Delete out-of-dated connections
      connections_in_list = 0
      connection_storage.to_a.sort{|conn1, conn2| conn2[1][:last_used_at] <=> conn1[1][:last_used_at]}.each do |serv_url, conn_opts|
        if    @params[:max_connections] <= connections_in_list
          conn_opts[:connection].finish('out-of-limit')
          connection_storage.delete(server_url)
        elsif conn_opts[:last_used_at] < life_time_scratch
          conn_opts[:connection].finish('out-of-date')
          connection_storage.delete(server_url)
        else
          connections_in_list += 1
        end
      end
      connection = (connection_storage[server_url] ||= {})
      connection[:last_used_at] = Time.now
      connection[:connection] ||= Rightscale::HttpConnection.new(:exception => RightAws::AwsError, :logger => @logger)
    end

    #----------------------------
    # HTTP Requests handling
    #----------------------------

    # ACF, AMS, EC2, LBS and SDB uses this guy
    # SQS and S3 use their own methods
    def generate_request_impl(verb, action, options={}, custom_options={}) #:nodoc:
      # Form a valid http verb: 'GET' or 'POST' (all the other are not supported now)
      http_verb = verb.to_s.upcase
      # remove empty keys from request options
      options.delete_if { |key, value| value.nil? }
      # prepare service data
      service_hash = {"Action"         => action,
                      "AWSAccessKeyId" => @aws_access_key_id,
                      "Version"        => custom_options[:api_version] || @params[:api_version] }
      service_hash.merge!(options)
      # Sign request options
      service_params = signed_service_params(@aws_secret_access_key, service_hash, http_verb, @params[:host_to_sign], @params[:service])
      # Use POST if the length of the query string is too large
      # see http://docs.amazonwebservices.com/AmazonSimpleDB/2007-11-07/DeveloperGuide/MakingRESTRequests.html
      if http_verb != 'POST' && service_params.size > 2000
        http_verb = 'POST'
        if signature_version == '2'
          service_params = signed_service_params(@aws_secret_access_key, service_hash, http_verb, @params[:host_to_sign], @params[:service])
        end
      end
      # create a request
      case http_verb
      when 'GET'
        request = Net::HTTP::Get.new("#{@params[:service]}?#{service_params}")
      when 'POST'
        request      = Net::HTTP::Post.new(@params[:service])
        request.body = service_params
        request['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8'
      else
        raise "Unsupported HTTP verb #{verb.inspect}!"
      end
      # prepare output hash
      request_hash = { :request  => request,
                       :server   => @params[:server],
                       :port     => @params[:port],
                       :protocol => @params[:protocol] }
      request_hash.merge!(@params[:connection_options])
      request_hash.merge!(@with_connection_options)
      
      # If an action is marked as "non-retryable" and there was no :raise_on_timeout option set
      # explicitly then do set that option
      if Array(RightAwsBase::raise_on_timeout_on_actions).include?(action) && !request_hash.has_key?(:raise_on_timeout)
        request_hash.merge!(:raise_on_timeout => true)
      end

      request_hash
    end

    # All services uses this guy.
    def request_info_impl(aws_service, benchblock, request, parser, &block) #:nodoc:
      request[:aws_service] = aws_service
      @connection    = get_connection(request)
      @last_request  = request[:request]
      @last_response = nil
      response = nil
      blockexception = nil

      if(block != nil)
        # TRB 9/17/07 Careful - because we are passing in blocks, we get a situation where
        # an exception may get thrown in the block body (which is high-level
        # code either here or in the application) but gets caught in the
        # low-level code of HttpConnection.  The solution is not to let any
        # exception escape the block that we pass to HttpConnection::request.
        # Exceptions can originate from code directly in the block, or from user
        # code called in the other block which is passed to response.read_body.
        benchblock.service.add! do
          begin
            responsehdr = @connection.request(request) do |response|
            #########
              begin
                @last_response = response
                if response.is_a?(Net::HTTPSuccess)
                  @error_handler = nil
                  response.read_body(&block)
                else
                  @error_handler = AWSErrorHandler.new(self, parser, :errors_list => self.class.amazon_problems) unless @error_handler
                  check_result   = @error_handler.check(request)
                  if check_result
                    @error_handler = nil
                    return check_result
                  end
                  raise AwsError.new(@last_errors, @last_response.code, @last_request_id)
                end
              rescue Exception => e
                blockexception = e
              end
            end
          rescue Exception => e
            # Kill a connection if we run into a low level connection error
            destroy_connection(request, "error: #{e.message}")
            raise e
          end
          #########

          #OK, now we are out of the block passed to the lower level
          if(blockexception)
            raise blockexception
          end
          benchblock.xml.add! do
            parser.parse(responsehdr)
          end
          return parser.result
        end
      else
        benchblock.service.add! do
          begin
            response = @connection.request(request)
          rescue Exception => e
            # Kill a connection if we run into a low level connection error
            destroy_connection(request, "error: #{e.message}")
            raise e
          end
        end
          # check response for errors...
        @last_response = response
        if response.is_a?(Net::HTTPSuccess)
          @error_handler = nil
          benchblock.xml.add! { parser.parse(response) }
          return parser.result
        else
          @error_handler = AWSErrorHandler.new(self, parser, :errors_list => self.class.amazon_problems) unless @error_handler
          check_result   = @error_handler.check(request)
          if check_result
            @error_handler = nil
            return check_result 
          end
          raise AwsError.new(@last_errors, @last_response.code, @last_request_id)
        end
      end
    rescue
      @error_handler = nil
      raise
    end

    def request_cache_or_info(method, link, parser_class, benchblock, use_cache=true, &block) #:nodoc:
      # We do not want to break the logic of parsing hence will use a dummy parser to process all the standard
      # steps (errors checking etc). The dummy parser does nothig - just returns back the params it received.
      # If the caching is enabled and hit then throw  AwsNoChange.
      # P.S. caching works for the whole images list only! (when the list param is blank)
      # check cache
      response, params = request_info(link, RightDummyParser.new)
      cache_hits?(method.to_sym, response.body) if use_cache
      parser = parser_class.new(:logger => @logger)
      benchblock.xml.add!{ parser.parse(response, params) }
      result = block ? block.call(parser) : parser.result
      # update parsed data
      update_cache(method.to_sym, :parsed => result) if use_cache
      result
    end

    # Returns Amazons request ID for the latest request
    def last_request_id
      @last_response && @last_response.body.to_s[%r{<requestId>(.+?)</requestId>}i] && $1
    end

    # Incrementally lists something.
    def incrementally_list_items(action, parser_class, params={}, &block) # :nodoc:
      params = params.dup
      params['MaxItems'] = params.delete(:max_items) if params[:max_items]
      params['Marker']   = params.delete(:marker)    if params[:marker]
      last_response = nil
      loop do
        last_response    = request_info( generate_request(action, params), parser_class.new(:logger => @logger))
        params['Marker'] = last_response[:marker]
        break unless block && block.call(last_response) && !last_response[:marker].right_blank?
      end
      last_response
    end

    # Format array of items into Amazons handy hash ('?' is a place holder):
    # Options:
    #   :default => "something"   : Set a value to "something" when it is nil
    #   :default => :skip_nils    : Skip nil values
    #
    #  amazonize_list('Item', ['a', 'b', 'c']) =>
    #    { 'Item.1' => 'a', 'Item.2' => 'b', 'Item.3' => 'c' }
    #
    #  amazonize_list('Item.?.instance', ['a', 'c']) #=>
    #    { 'Item.1.instance' => 'a', 'Item.2.instance' => 'c' }
    #
    #  amazonize_list(['Item.?.Name', 'Item.?.Value'], {'A' => 'a', 'B' => 'b'}) #=>
    #    { 'Item.1.Name' => 'A', 'Item.1.Value' => 'a',
    #      'Item.2.Name' => 'B', 'Item.2.Value' => 'b'  }
    #
    #  amazonize_list(['Item.?.Name', 'Item.?.Value'], [['A','a'], ['B','b']]) #=>
    #    { 'Item.1.Name' => 'A', 'Item.1.Value' => 'a',
    #      'Item.2.Name' => 'B', 'Item.2.Value' => 'b'  }
    #
    #  amazonize_list(['Filter.?.Key', 'Filter.?.Value.?'], {'A' => ['aa','ab'], 'B' => ['ba','bb']}) #=>
    #  amazonize_list(['Filter.?.Key', 'Filter.?.Value.?'], [['A',['aa','ab']], ['B',['ba','bb']]])   #=>
    #    {"Filter.1.Key"=>"A",
    #     "Filter.1.Value.1"=>"aa",
    #     "Filter.1.Value.2"=>"ab",
    #     "Filter.2.Key"=>"B",
    #     "Filter.2.Value.1"=>"ba",
    #     "Filter.2.Value.2"=>"bb"}
    def amazonize_list(masks, list, options={}) #:nodoc:
      groups = {}
      list_idx = options[:index] || 1
      Array(list).each do |list_item|
        Array(masks).each_with_index do |mask, mask_idx|
          key = mask[/\?/] ? mask.dup : mask.dup + '.?'
          key.sub!('?', list_idx.to_s)
          value = Array(list_item)[mask_idx]
          if value.is_a?(Array)
            groups.merge!(amazonize_list(key, value, options))
          else
            if value.nil?
              next if options[:default] == :skip_nils
              value = options[:default]
            end
            # Hack to avoid having unhandled '?' in keys : do replace them all with '1':
            #  bad:  ec2.amazonize_list(['Filter.?.Key', 'Filter.?.Value.?'], { a: => :b }) => {"Filter.1.Key"=>:a, "Filter.1.Value.?"=>1}
            #  good: ec2.amazonize_list(['Filter.?.Key', 'Filter.?.Value.?'], { a: => :b }) => {"Filter.1.Key"=>:a, "Filter.1.Value.1"=>1}
            key.gsub!('?', '1')
            groups[key] = value
          end
        end
        list_idx += 1
      end
      groups
    end

    BLOCK_DEVICE_KEY_MAPPING = {                                                           # :nodoc:
      :device_name               => 'DeviceName',
      :virtual_name              => 'VirtualName',
      :no_device                 => 'NoDevice',
      :ebs_snapshot_id           => 'Ebs.SnapshotId',
      :ebs_volume_size           => 'Ebs.VolumeSize',
      :ebs_delete_on_termination => 'Ebs.DeleteOnTermination' }

    def amazonize_block_device_mappings(block_device_mappings, key = 'BlockDeviceMapping') # :nodoc:
      result = {}
      unless block_device_mappings.right_blank?
        block_device_mappings = [block_device_mappings] unless block_device_mappings.is_a?(Array)
        block_device_mappings.each_with_index do |b, idx|
          BLOCK_DEVICE_KEY_MAPPING.each do |local_name, remote_name|
            value = b[local_name]
            case local_name
            when :no_device then value = value ? '' : nil   # allow to pass :no_device as boolean
            end
            result["#{key}.#{idx+1}.#{remote_name}"] = value unless value.nil?
          end
        end
      end
      result
    end

    # Build API request keys set.
    #
    # Options is a hash, expectations is a set of keys [and rules] how to represent options.
    # Mappings is an Array (may include hashes) or a Hash.
    #
    #  Example:
    #
    #  options = { :valid_from              => Time.now - 10,
    #              :instance_count          => 3,
    #              :image_id                => 'ami-08f41161',
    #              :spot_price              => 0.059,
    #              :instance_type           => 'c1.medium',
    #              :instance_count          => 1,
    #              :key_name                => 'tim',
    #              :availability_zone       => 'us-east-1a',
    #              :monitoring_enabled      => true,
    #              :launch_group            => 'lg1',
    #              :availability_zone_group => 'azg1',
    #              :groups                  => ['a', 'b', 'c'],
    #              :group_ids               => 'sg-1',
    #              :user_data               => 'konstantin',
    #              :block_device_mappings   => [ { :device_name     => '/dev/sdk',
    #                                              :ebs_snapshot_id => 'snap-145cbc7d',
    #                                              :ebs_delete_on_termination => true,
    #                                              :ebs_volume_size => 3,
    #                                              :virtual_name => 'ephemeral2' }]}
    #  mappings = { :spot_price,
    #               :availability_zone_group,
    #               :launch_group,
    #               :type,
    #               :instance_count,
    #               :image_id              => 'LaunchSpecification.ImageId',
    #               :instance_type         => 'LaunchSpecification.InstanceType',
    #               :key_name              => 'LaunchSpecification.KeyName',
    #               :addressing_type       => 'LaunchSpecification.AddressingType',
    #               :kernel_id             => 'LaunchSpecification.KernelId',
    #               :ramdisk_id            => 'LaunchSpecification.RamdiskId',
    #               :subnet_id             => 'LaunchSpecification.SubnetId',
    #               :availability_zone     => 'LaunchSpecification.Placement.AvailabilityZone',
    #               :monitoring_enabled    => 'LaunchSpecification.Monitoring.Enabled',
    #               :valid_from            => { :value => Proc.new { !options[:valid_from].right_blank?  && AwsUtils::utc_iso8601(options[:valid_from]) }},
    #               :valid_until           => { :value => Proc.new { !options[:valid_until].right_blank? && AwsUtils::utc_iso8601(options[:valid_until]) }},
    #               :user_data             => { :name  => 'LaunchSpecification.UserData',
    #                                           :value => Proc.new { !options[:user_data].right_blank? && Base64.encode64(options[:user_data]).delete("\n") }},
    #               :groups                => { :amazonize_list => 'LaunchSpecification.SecurityGroup'},
    #               :group_ids             => { :amazonize_list => 'LaunchSpecification.SecurityGroupId'},
    #               :block_device_mappings => { :amazonize_bdm  => 'LaunchSpecification.BlockDeviceMapping'})
    #
    #  map_api_keys_and_values( options, mappings) #=>
    #    {"LaunchSpecification.BlockDeviceMapping.1.Ebs.DeleteOnTermination" => true,
    #     "LaunchSpecification.BlockDeviceMapping.1.VirtualName"             => "ephemeral2",
    #     "LaunchSpecification.BlockDeviceMapping.1.Ebs.VolumeSize"          => 3,
    #     "LaunchSpecification.BlockDeviceMapping.1.Ebs.SnapshotId"          => "snap-145cbc7d",
    #     "LaunchSpecification.BlockDeviceMapping.1.DeviceName"              => "/dev/sdk",
    #     "LaunchSpecification.SecurityGroupId.1"                            => "sg-1",
    #     "LaunchSpecification.InstanceType"                                 => "c1.medium",
    #     "LaunchSpecification.KeyName"                                      => "tim",
    #     "LaunchSpecification.ImageId"                                      => "ami-08f41161",
    #     "LaunchSpecification.SecurityGroup.1"                              => "a",
    #     "LaunchSpecification.SecurityGroup.2"                              => "b",
    #     "LaunchSpecification.SecurityGroup.3"                              => "c",
    #     "LaunchSpecification.Placement.AvailabilityZone"                   => "us-east-1a",
    #     "LaunchSpecification.Monitoring.Enabled"                           => true,
    #     "LaunchGroup"                                                      => "lg1",
    #     "InstanceCount"                                                    => 1,
    #     "SpotPrice"                                                        => 0.059,
    #     "AvailabilityZoneGroup"                                            => "azg1",
    #     "ValidFrom"                                                        => "2011-06-30T08:06:30.000Z",
    #     "LaunchSpecification.UserData"                                     => "a29uc3RhbnRpbg=="}
    #
    def map_api_keys_and_values(options, *mappings) # :nodoc:
      result = {}
      vars   = {}
      # Fix inputs and make them all to be hashes
      mappings.flatten.each do |mapping|
        unless mapping.is_a?(Hash)
          # mapping is just a :key_name
          mapping = { mapping => { :name  => mapping.to_s.right_camelize, :value => options[mapping] }}
        else
          mapping.each do |local_key, api_opts|
            unless api_opts.is_a?(Hash)
              # mapping is a { :key_name => 'ApiKeyName' }
              mapping[local_key] = { :name  => api_opts.to_s, :value => options[local_key]}
            else
              # mapping is a { :key_name => { :name => 'ApiKeyName', :value => 'Value', ... etc}  }
              api_opts[:name]  = local_key.to_s.right_camelize if (api_opts.keys & [:name, :amazonize_list, :amazonize_bdm]).right_blank?
              api_opts[:value] = options[local_key] unless api_opts.has_key?(:value)
            end
          end
        end
        vars.merge! mapping
      end
      # Build API keys set
      #  vars now is a Hash:
      #    { :key1 => { :name           => 'ApiKey1',   :value => 'BlahBlah'},
      #      :key2 => { :amazonize_list => 'ApiKey2.?', :value => [1, ...] },
      #      :key3 => { :amazonize_bdm  => 'BDM',       :value => [{..}, ...] }, ... }
      #
      vars.each do |local_key, api_opts|
        if api_opts[:amazonize_list]
          result.merge!(amazonize_list( api_opts[:amazonize_list], api_opts[:value] )) unless api_opts[:value].right_blank?
        elsif api_opts[:amazonize_bdm]
          result.merge!(amazonize_block_device_mappings( api_opts[:value], api_opts[:amazonize_bdm] )) unless api_opts[:value].right_blank?
        else
          api_key = api_opts[:name]
          value   = api_opts[:value]
          value   = value.call if value.is_a?(Proc)
          next if value.right_blank?
          result[api_key] = value
        end
      end
      #
      result
    end

    # Transform a hash of parameters into a hash suitable for sending
    # to Amazon using a key mapping.
    #
    #  amazonize_hash_with_key_mapping('Group.Filter',
    #    {:some_param => 'SomeParam'},
    #    {:some_param => 'value'}) #=> {'Group.Filter.SomeParam' => 'value'}
    #
    def amazonize_hash_with_key_mapping(key, mapping, hash, options={})
      result = {}
      unless hash.right_blank?
        mapping.each do |local_name, remote_name|
          value = hash[local_name]
          next if value.nil?
          result["#{key}.#{remote_name}"] = value
        end
      end
      result
    end

    # Transform a list of hashes of parameters into a hash suitable for sending
    # to Amazon using a key mapping.
    #
    #  amazonize_list_with_key_mapping('Group.Filter',
    #    [{:some_param => 'SomeParam'}, {:some_param => 'SomeParam'}],
    #    {:some_param => 'value'}) #=>
    #      {'Group.Filter.1.SomeParam' => 'value',
    #       'Group.Filter.2.SomeParam' => 'value'}
    #
    def amazonize_list_with_key_mapping(key, mapping, list, options={})
      result = {}
      unless list.right_blank?
        list.each_with_index do |item, index|
          mapping.each do |local_name, remote_name|
            value = item[local_name]
            next if value.nil?
            result["#{key}.#{index+1}.#{remote_name}"] = value
          end
        end
      end
    end
    
    # Execute a block of code with custom set of settings for right_http_connection.
    # Accepts next options (see Rightscale::HttpConnection for explanation):
    #  :raise_on_timeout
    #  :http_connection_retry_count
    #  :http_connection_open_timeout
    #  :http_connection_read_timeout
    #  :http_connection_retry_delay
    #  :user_agent
    #  :exception
    #
    #  Example #1:
    #
    #  # Try to create a snapshot but stop with exception if timeout is received
    #  # to avoid having a duplicate API calls that create duplicate snapshots.
    #  ec2 = Rightscale::Ec2::new(aws_access_key_id, aws_secret_access_key)
    #  ec2.with_connection_options(:raise_on_timeout => true) do
    #    ec2.create_snapshot('vol-898a6fe0', 'KD: WooHoo!!')
    #  end
    #
    #  Example #2:
    #
    #  # Opposite case when the setting is global:
    #  @ec2 = Rightscale::Ec2::new(aws_access_key_id, aws_secret_access_key,
    #                           :connection_options => { :raise_on_timeout => true })
    #  # Create an SSHKey but do tries on timeout
    #  ec2.with_connection_options(:raise_on_timeout => false) do
    #    new_key = ec2.create_key_pair('my_test_key')
    #  end
    #
    #  Example #3:
    #
    #  # Global settings (HttpConnection level):
    #  Rightscale::HttpConnection::params[:http_connection_open_timeout] = 5
    #  Rightscale::HttpConnection::params[:http_connection_read_timeout] = 250
    #  Rightscale::HttpConnection::params[:http_connection_retry_count]  = 2
    #
    #  # Local setings (RightAws level)
    #  ec2 = Rightscale::Ec2::new(AWS_ID, AWS_KEY,
    #    :region => 'us-east-1',
    #    :connection_options => {
    #      :http_connection_read_timeout => 2,
    #      :http_connection_retry_count  => 5,
    #      :user_agent => 'Mozilla 4.0'
    #    })
    #
    #  # Custom settings (API call level)
    #  ec2.with_connection_options(:raise_on_timeout => true,
    #                              :http_connection_read_timeout => 10,
    #                              :user_agent => '') do
    #    pp ec2.describe_images
    #  end
    #
    def with_connection_options(options, &block)
      @with_connection_options = options
      block.call self
    ensure
      @with_connection_options = {}
    end
  end


  # Exception class to signal any Amazon errors. All errors occuring during calls to Amazon's
  # web services raise this type of error.
  # Attribute inherited by RuntimeError:
  #  message    - the text of the error, generally as returned by AWS in its XML response.
  class AwsError < RuntimeError
    
    # either an array of errors where each item is itself an array of [code, message]),
    # or an error string if the error was raised manually, as in <tt>AwsError.new('err_text')</tt>
    attr_reader :errors
    
    # Request id (if exists)
    attr_reader :request_id
    
    # Response HTTP error code
    attr_reader :http_code
    
    def initialize(errors=nil, http_code=nil, request_id=nil)
      @errors      = errors
      @request_id  = request_id
      @http_code   = http_code
      super(@errors.is_a?(Array) ? @errors.map{|code, msg| "#{code}: #{msg}"}.join("; ") : @errors.to_s)
    end
    
    # Does any of the error messages include the regexp +pattern+?
    # Used to determine whether to retry request.
    def include?(pattern)
      if @errors.is_a?(Array)
        @errors.each{ |code, msg| return true if code =~ pattern } 
      else
        return true if @errors_str =~ pattern 
      end
      false
    end
    
    # Generic handler for AwsErrors. +aws+ is the RightAws::S3, RightAws::EC2, or RightAws::SQS
    # object that caused the exception (it must provide last_request and last_response). Supported
    # boolean options are:
    # * <tt>:log</tt> print a message into the log using aws.logger to access the Logger
    # * <tt>:puts</tt> do a "puts" of the error
    # * <tt>:raise</tt> re-raise the error after logging
    def self.on_aws_exception(aws, options={:raise=>true, :log=>true})
 	    # Only log & notify if not user error
      if !options[:raise] || system_error?($!)
        error_text = "#{$!.inspect}\n#{$@}.join('\n')}"
        puts error_text if options[:puts]
          # Log the error
        if options[:log]
          request  = aws.last_request  ? aws.last_request.path :  '-none-'
          response = aws.last_response ? "#{aws.last_response.code} -- #{aws.last_response.message} -- #{aws.last_response.body}" : '-none-'
          aws.logger.error error_text
          aws.logger.error "Request was:  #{request}"
          aws.logger.error "Response was: #{response}"
        end
      end
      raise if options[:raise]  # re-raise an exception
      return nil
    end
    
    # True if e is an AWS system error, i.e. something that is for sure not the caller's fault.
    # Used to force logging.
    def self.system_error?(e)
 	    !e.is_a?(self) || e.message =~ /InternalError|InsufficientInstanceCapacity|Unavailable/
    end

  end


  class AWSErrorHandler
    # 0-100 (%) 
    DEFAULT_CLOSE_ON_4XX_PROBABILITY = 10     
    
    @@reiteration_start_delay = 0.2
    def self.reiteration_start_delay
      @@reiteration_start_delay
    end
    def self.reiteration_start_delay=(reiteration_start_delay)
      @@reiteration_start_delay = reiteration_start_delay
    end

    @@reiteration_time = 5
    def self.reiteration_time
      @@reiteration_time
    end
    def self.reiteration_time=(reiteration_time)
      @@reiteration_time = reiteration_time
    end
    
    @@close_on_error = true 
    def self.close_on_error 
      @@close_on_error 
    end 
    def self.close_on_error=(close_on_error) 
      @@close_on_error = close_on_error 
    end 
 
    @@close_on_4xx_probability = DEFAULT_CLOSE_ON_4XX_PROBABILITY 
    def self.close_on_4xx_probability 
      @@close_on_4xx_probability 
    end 
    def self.close_on_4xx_probability=(close_on_4xx_probability) 
      @@close_on_4xx_probability = close_on_4xx_probability 
    end 
 
    # params: 
    #  :reiteration_time 
    #  :errors_list 
    #  :close_on_error           = true | false 
    #  :close_on_4xx_probability = 1-100 
    def initialize(aws, parser, params={}) #:nodoc:     
      @aws           = aws              # Link to RightEc2 | RightSqs | RightS3 instance
      @parser        = parser           # parser to parse Amazon response
      @started_at    = Time.now
      @stop_at       = @started_at  + (params[:reiteration_time] || @@reiteration_time) 
      @errors_list   = params[:errors_list] || [] 
      @reiteration_delay = @@reiteration_start_delay
      @retries       = 0
      # close current HTTP(S) connection on 5xx, errors from list and 4xx errors 
      @close_on_error           = params[:close_on_error].nil? ? @@close_on_error : params[:close_on_error]
      @close_on_4xx_probability = params[:close_on_4xx_probability] || @@close_on_4xx_probability       
    end
    
      # Returns false if 
    def check(request)  #:nodoc:
      result           = false
      error_found      = false
      redirect_detected= false
      error_match      = nil
      last_errors_text = ''
      response         = @aws.last_response
      # log error
      request_text_data = "#{request[:protocol]}://#{request[:server]}:#{request[:port]}#{request[:request].path}"
      # is this a redirect?
      # yes!
      if response.is_a?(Net::HTTPRedirection)
        redirect_detected = true 
      else
        # no, it's an error ...
        @aws.logger.warn("##### #{@aws.class.name} returned an error: #{response.code} #{response.message}\n#{response.body} #####")
        @aws.logger.warn("##### #{@aws.class.name} request: #{request_text_data} ####")
      end

      # Extract error/redirection message from the response body
      # Amazon claims that a redirection must have a body but somethimes it is nil....
      if response.body && response.body[/^(<\?xml|<ErrorResponse)/]
        error_parser = RightErrorResponseParser.new
        @aws.class.bench_xml.add! do
          error_parser.parse(response.body)
        end
        @aws.last_errors     = error_parser.errors
        @aws.last_request_id = error_parser.requestID
        last_errors_text     = @aws.last_errors.flatten.join("\n")
      else
        @aws.last_errors     = [[response.code, "#{response.message} (#{request_text_data})"]]
        @aws.last_request_id = '-undefined-'
        last_errors_text     = response.message
      end
      
      # Ok, it is a redirect, find the new destination location
      if redirect_detected
        location = response['location']
        # As for 301 ( Moved Permanently) Amazon does not return a 'Location' header but
        # it is possible to extract a new endpoint from the response body
        if location.right_blank? && response.code=='301' && response.body
          new_endpoint = response.body[/<Endpoint>(.*?)<\/Endpoint>/] && $1
          location     = "#{request[:protocol]}://#{new_endpoint}:#{request[:port]}#{request[:request].path}"
        end
        # ... log information and ...
        @aws.logger.info("##### #{@aws.class.name} redirect requested: #{response.code} #{response.message} #####")
        @aws.logger.info("      Old location: #{request_text_data}")
        @aws.logger.info("      New location: #{location}")
        @aws.logger.info("      Request Verb: #{request[:request].class.name}")
        # ... fix the connection data
        request[:server]   = URI.parse(location).host
        request[:protocol] = URI.parse(location).scheme
        request[:port]     = URI.parse(location).port
      else
        # Not a redirect but an error: try to find the error in our list
        @errors_list.each do |error_to_find|
          if last_errors_text[/#{error_to_find}/i]
            error_found = true
            error_match = error_to_find
            @aws.logger.warn("##### Retry is needed, error pattern match: #{error_to_find} #####")
            break
          end
        end
      end
      
        # check the time has gone from the first error come
      if redirect_detected || error_found
        # Close the connection to the server and recreate a new one. 
        # It may have a chance that one server is a semi-down and reconnection 
        # will help us to connect to the other server 
        if !redirect_detected && @close_on_error
          @aws.destroy_connection(request, "#{self.class.name}: error match to pattern '#{error_match}'")
        end 
                 
        if (Time.now < @stop_at)
          @retries += 1
          unless redirect_detected
            @aws.logger.warn("##### Retry ##{@retries} is being performed. Sleeping for #{@reiteration_delay} sec. Whole time: #{Time.now-@started_at} sec ####")
            sleep @reiteration_delay 
            @reiteration_delay *= 2

            # Always make sure that the fp is set to point to the beginning(?)
            # of the File/IO. TODO: it assumes that offset is 0, which is bad.
            if(request[:request].body_stream && request[:request].body_stream.respond_to?(:pos))
              begin
                request[:request].body_stream.pos = 0
              rescue Exception => e
                @logger.warn("Retry may fail due to unable to reset the file pointer" +
                             " -- #{self.class.name} : #{e.inspect}")
              end
            end
          else
            @aws.logger.info("##### Retry ##{@retries} is being performed due to a redirect.  ####")
          end
          result = @aws.request_info(request, @parser)
        else
          @aws.logger.warn("##### Ooops, time is over... ####")
        end 
      # aha, this is unhandled error: 
      elsif @close_on_error 
        # On 5xx(Server errors), 403(RequestTimeTooSkewed) and 408(Request Timeout) a conection has to be closed
        if @aws.last_response.code.to_s[/^(5\d\d|403|408)$/]
          @aws.destroy_connection(request, "#{self.class.name}: code: #{@aws.last_response.code}: '#{@aws.last_response.message}'")
        # Is this a 4xx error ? 
        elsif @aws.last_response.code.to_s[/^4\d\d$/] && @close_on_4xx_probability > rand(100) 
          @aws.destroy_connection(request, "#{self.class.name}: code: #{@aws.last_response.code}: '#{@aws.last_response.message}', " +
                                           "probability: #{@close_on_4xx_probability}%")
        end
      end
      result
    end
    
  end


  #-----------------------------------------------------------------

  class RightSaxParserCallbackTemplate #:nodoc:
    def initialize(right_aws_parser) 
      @right_aws_parser = right_aws_parser 
    end 
    def on_characters(chars) 
      @right_aws_parser.text(chars)
    end 
    def on_start_document; end 
    def on_comment(msg); end 
    def on_processing_instruction(target, data); end 
    def on_cdata_block(cdata); end 
    def on_end_document; end 
  end 

  class RightSaxParserCallback < RightSaxParserCallbackTemplate
    def self.include_callback
      include XML::SaxParser::Callbacks
    end
    def on_start_element(name, attr_hash)
      @right_aws_parser.tag_start(name, attr_hash)
    end
    def on_end_element(name)
      @right_aws_parser.tag_end(name)
    end
  end

  class RightSaxParserCallbackNs < RightSaxParserCallbackTemplate
    def on_start_element_ns(name, attr_hash, prefix, uri, namespaces)
      @right_aws_parser.tag_start(name, attr_hash)
    end
    def on_end_element_ns(name, prefix, uri)
      @right_aws_parser.tag_end(name)
    end
  end

  class RightAWSParser  #:nodoc:
      # default parsing library 
    DEFAULT_XML_LIBRARY = 'rexml' 
      # a list of supported parsers 
    @@supported_xml_libs = [DEFAULT_XML_LIBRARY, 'libxml'] 
     
    @@xml_lib = DEFAULT_XML_LIBRARY # xml library name: 'rexml' | 'libxml' 
    def self.xml_lib
      @@xml_lib
    end
    def self.xml_lib=(new_lib_name)
      @@xml_lib = new_lib_name
    end
    
    attr_accessor :result
    attr_reader   :xmlpath
    attr_accessor :xml_lib
    attr_reader   :full_tag_name
    attr_reader   :tag
    
    def initialize(params={})
      @xmlpath = ''
      @full_tag_name = ''
      @result  = false
      @text    = ''
      @tag     = ''
      @xml_lib = params[:xml_lib] || @@xml_lib
      @logger  = params[:logger]
      reset
    end
    def tag_start(name, attributes)
      @text = ''
      @tag  = name
      @full_tag_name += @full_tag_name.empty? ? name : "/#{name}"
      tagstart(name, attributes)
      @xmlpath = @full_tag_name
    end
    def tag_end(name)
      @xmlpath = @full_tag_name[/^(.*?)\/?#{name}$/] && $1
      tagend(name)
      @full_tag_name = @xmlpath
    end
    def text(text)
      @text += text
      tagtext(text)
    end
      # Parser method.
      # Params:
      #   xml_text         - xml message text(String) or Net:HTTPxxx instance (response)
      #   params[:xml_lib] - library name: 'rexml' | 'libxml'
    def parse(xml_text, params={})
        # Get response body
      xml_text = xml_text.body unless xml_text.is_a?(String)
      @xml_lib = params[:xml_lib] || @xml_lib
        # check that we had no problems with this library otherwise use default 
      @xml_lib = DEFAULT_XML_LIBRARY unless @@supported_xml_libs.include?(@xml_lib)       
        # load xml library
      if @xml_lib=='libxml' && !defined?(XML::SaxParser)
        begin
          require 'xml/libxml'
          # Setup SaxParserCallback 
          if XML::Parser::VERSION >= '0.5.1' &&
             XML::Parser::VERSION  < '0.9.7'
            RightSaxParserCallback.include_callback
          end           
        rescue LoadError => e
          @@supported_xml_libs.delete(@xml_lib)
          @xml_lib = DEFAULT_XML_LIBRARY
          if @logger
            @logger.error e.inspect
            @logger.error e.backtrace
            @logger.info "Can not load 'libxml' library. '#{DEFAULT_XML_LIBRARY}' is used for parsing."
          end
        end
      end
        # Parse the xml text
      case @xml_lib
      when 'libxml'
        if XML::Parser::VERSION >= '0.9.9'
          # avoid warning on every usage
          xml        = XML::SaxParser.string(xml_text)
        else
          xml        = XML::SaxParser.new
          xml.string = xml_text 
        end
        # check libxml-ruby version 
        if    XML::Parser::VERSION >= '0.9.7'
          xml.callbacks = RightSaxParserCallbackNs.new(self)
        elsif XML::Parser::VERSION >= '0.5.1'
          xml.callbacks = RightSaxParserCallback.new(self) 
        else 
          xml.on_start_element{|name, attr_hash| self.tag_start(name, attr_hash)} 
          xml.on_characters{   |text|            self.text(text)}
          xml.on_end_element{  |name|            self.tag_end(name)} 
        end 
        xml.parse
      else
        REXML::Document.parse_stream(xml_text, self)
      end
    end
      # Parser must have a lots of methods 
      # (see /usr/lib/ruby/1.8/rexml/parsers/streamparser.rb)
      # We dont need most of them in RightAWSParser and method_missing helps us
      # to skip their definition
    def method_missing(method, *params)
        # if the method is one of known - just skip it ...
      return if [:comment, :attlistdecl, :notationdecl, :elementdecl, 
                 :entitydecl, :cdata, :xmldecl, :attlistdecl, :instruction, 
                 :doctype].include?(method)
        # ... else - call super to raise an exception
      super(method, params)
    end
      # the functions to be overriden by children (if nessesery)
    def reset                     ; end
    def tagstart(name, attributes); end
    def tagend(name)              ; end
    def tagtext(text)             ; end
  end

  #-----------------------------------------------------------------
  #      PARSERS: Errors
  #-----------------------------------------------------------------

#<Error>
#  <Code>TemporaryRedirect</Code>
#  <Message>Please re-send this request to the specified temporary endpoint. Continue to use the original request endpoint for future requests.</Message>
#  <RequestId>FD8D5026D1C5ABA3</RequestId>
#  <Endpoint>bucket-for-k.s3-external-3.amazonaws.com</Endpoint>
#  <HostId>ItJy8xPFPli1fq/JR3DzQd3iDvFCRqi1LTRmunEdM1Uf6ZtW2r2kfGPWhRE1vtaU</HostId>
#  <Bucket>bucket-for-k</Bucket>
#</Error>

  class RightErrorResponseParser < RightAWSParser #:nodoc:
    attr_accessor :errors  # array of hashes: error/message
    attr_accessor :requestID
#    attr_accessor :endpoint, :host_id, :bucket
    def tagend(name)
      case name
        when 'RequestID' ; @requestID = @text
        when 'Code'      ; @code      = @text
        when 'Message'   ; @message   = @text
#       when 'Endpoint'  ; @endpoint  = @text
#       when 'HostId'    ; @host_id   = @text
#       when 'Bucket'    ; @bucket    = @text
        when 'Error'     ; @errors   << [ @code, @message ]
      end
    end
    def reset
      @errors = []
    end
  end

  # Dummy parser - does nothing
  # Returns the original params back
  class RightDummyParser  # :nodoc:
    attr_accessor :result
    def parse(response, params={})
      @result = [response, params]
    end
  end

  class RightHttp2xxParser < RightAWSParser # :nodoc:
    def parse(response)
      @result = response.is_a?(Net::HTTPSuccess)
    end
  end

  class RightBoolResponseParser < RightAWSParser #:nodoc:
    def tagend(name)
      @result = (@text=='true') if name == 'return'
    end
  end

end

