#
# Copyright (c) 2007 RightScale Inc
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

  class S3Interface
    
    DEFAULT_HOST           = 's3.amazonaws.com'
    DEFAULT_PORT           = 443
    DEFAULT_PROTOCOL       = 'https'
    REQUEST_TTL            = 30
    DEFAULT_EXPIRES_AFTER  = 1.day
    AMAZON_HEADER_PREFIX   = 'x-amz-'
    AMAZON_METADATA_PREFIX = 'x-amz-meta-'

      # A list if Amazons problems we can handle by AWSErrorHandler.
    @@amazon_problems = RightAws::AMAZON_PROBLEMS
   
	# TODO TRB 6/19/07 - all the below accessors are shared in the 
	# three service gems.  See if is it reasonable to stick these
	# in an interface class in right_awsbase that we can mixin
	#
	# Same for the benchmarking code - all three service gems have
	# the same.  Break out into a helper class.  Also look at the 
	# benchmarking fix as a good thing to move to common code.
 
      # Current aws_access_key_id
    attr_reader :aws_access_key_id
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
    
    @@bench_s3  = Benchmark::Tms.new()
    @@bench_xml = Benchmark::Tms.new()

      # Benchmark::Tms instance for S3 access benchmark.
    def self.bench_s3;  @@bench_s3;  end  
    
      # Benchmark::Tms instance for XML parsing benchmark.
    def self.bench_xml; @@bench_xml; end  # For benchmark puposes.

      # Returns a list of Amazon service responses which are known as problems on Amazon side. 
      # We have to re-request again if we've got any of them - probably the problem will disappear. By default returns the same value as AMAZON_PROBLEMS const.
    def self.amazon_problems
      @@amazon_problems
    end

      # Sets a list of Amazon side problems.
    def self.amazon_problems=(problems_list)
      @@amazon_problems = problems_list
    end

      # Creates new RightS3 instance.
      #
      #  s3 = RightAws::S3Interface.new('1E3GDYEOGFJPIT7XXXXXX','hgTHt68JY07JKUY08ftHYtERkjgtfERn57XXXXXX', {:multi_thread => true, :logger => Logger.new('/tmp/x.log')}) #=> #<RightS3:0xb7b3c27c>
      #  
      # Params is a hash:
      #
      #    {:server       => 's3.amazonaws.com'   # Amazon service host: 's3.amazonaws.com'(default)
      #     :port         => 443                  # Amazon service port: 80 or 443(default)
      #     :protocol     => 'https'              # Amazon service protocol: 'http' or 'https'(default)
      #     :multi_thread => true|false           # Multi-threaded (connection per each thread): true or false(default)
      #     :logger       => Logger Object}       # Logger instance: logs to STDOUT if omitted }
      #
    def initialize(aws_access_key_id, aws_secret_access_key, params={})
      @params = params
      raise AwsError.new("AWS access keys are required to operate on S3") \
        if aws_access_key_id.blank? || aws_secret_access_key.blank?

	# TODO TRB 6/19/07 - keys, basic params, and logger are all 
	# candidates to break out into a helper class common to all 
	# service gems.  Stick the helper in right_awsbase
      @aws_access_key_id     = aws_access_key_id
      @aws_secret_access_key = aws_secret_access_key
        # params
      @params[:server]       ||= DEFAULT_HOST
      @params[:port]         ||= DEFAULT_PORT
      @params[:protocol]     ||= DEFAULT_PROTOCOL
      @params[:multi_thread] ||= defined?(AWS_DAEMON)
        # set logger
      @logger = @params[:logger]
      @logger = RAILS_DEFAULT_LOGGER if !@logger && defined?(RAILS_DEFAULT_LOGGER)
      @logger = Logger.new(STDOUT)   if !@logger
      @logger.info "New #{self.class.name} using #{@params[:multi_thread] ? 'multi' : 'single'}-threaded mode"
    end

	# TODO TRB 6/19/07 - Service gem common method
    def on_exception(options={:raise=>true, :log=>true}) # :nodoc:
      RightAws::AwsError::on_aws_exception(self, options)
    end

	# TODO TRB 6/19/07 - Service gem common method

      # Return the +true+ if this RightS3 instance works in multi_thread state and +false+ otherwise.
    def multi_thread
      @params[:multi_thread]
    end

  #-----------------------------------------------------------------
  #      Requests
  #-----------------------------------------------------------------
      # Produces canonical string for signing.
    def canonical_string(method, path, headers={}, expires=nil) # :nodoc:
      s3_headers = {}
      headers.each do |key, value|
        key = key.downcase
        s3_headers[key] = value.to_s.strip if key[/^#{AMAZON_HEADER_PREFIX}|^content-md5$|^content-type$|^date$/o]
      end
      s3_headers['content-type'] ||= ''
      s3_headers['content-md5']  ||= ''
      s3_headers['date']           = ''      if s3_headers.has_key? 'x-amz-date'
      s3_headers['date']           = expires if expires
        # prepare output string
      out_string = "#{method}\n"
      s3_headers.sort { |a, b| a[0] <=> b[0] }.each do |key, value|
        out_string << (key[/^#{AMAZON_HEADER_PREFIX}/o] ? "#{key}:#{value}\n" : "#{value}\n")
      end
        # ignore everything after the question mark...
      out_string << path.gsub(/\?.*$/, '')
       # ...unless there is an acl or torrent parameter
      out_string << '?acl'    if path[/[&?]acl($|&|=)/]
      out_string << '?torrent'if path[/[&?]torrent($|&|=)/]
      out_string
    end

      # Generates request hash for REST API.
    def generate_rest_request(method, headers)  # :nodoc:
      path = headers[:url]
      path = "/#{path}" unless path[/^\//]
      data = headers[:data]
        # remove unset(==optional) and symbolyc keys
      headers.each{ |key, value| headers.delete(key) if (value.nil? || key.is_a?(Symbol)) }
        #
      headers['content-type'] ||= ''
      headers['date']           = Time.now.httpdate
        # create request
      request      = "Net::HTTP::#{method.titleize}".constantize.new(URI::escape(CGI::unescape(path)))
      request.body = data if data
        # set request headers and meta headers
      headers.each      { |key, value| request[key.to_s] = value }
        #generate auth strings
      auth_string = canonical_string(request.method, request.path, request.to_hash)
      signature   = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new("sha1"), @aws_secret_access_key, auth_string)).strip
        # set other headers
      request['Authorization'] = "AWS #{@aws_access_key_id}:#{signature}"
        # prepare output hash
      { :request  => request, 
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol] }
    end

      # Sends request to Amazon and parses the response.
      # Raises AwsError if any banana happened.
      # TODO TRB 6/19/07: 
      # request_info is a candidate to move to right_awsbase      
      # because it currently appears (in identical form) in right_s3,
      # right_ec2, and right_sqs
    def request_info(request, parser, &block) # :nodoc:
      thread = @params[:multi_thread] ? Thread.current : Thread.main
      thread[:s3_connection] ||= Rightscale::HttpConnection.new(:exception => RightAws::AwsError)
      @last_request  = request[:request]
      @last_response = nil
      response=nil

      if(block != nil)
        @@bench_s3.add! do
          responsehdr = thread[:s3_connection].request(request) do |response|
            if response.is_a?(Net::HTTPSuccess)
              @error_handler = nil
              response.read_body(&block)
            else
              @error_handler = AWSErrorHandler.new(self, parser, @@amazon_problems) unless @error_handler
              check_result   = @error_handler.check(request)
              if check_result
                @error_handler = nil
                return check_result 
              end
              raise AwsError.new(@last_errors, @last_response.code, @last_request_id)
            end
          end
          @@bench_xml.add! do
            parser.parse(responsehdr)
          end
          return parser.result
        end
      else
        @@bench_s3.add!{ response = thread[:s3_connection].request(request) }
          # check response for errors...
        @last_response = response
        if response.is_a?(Net::HTTPSuccess)
          @error_handler = nil
          @@bench_xml.add! do
            if parser.kind_of?(RightAWSParser)
              REXML::Document.parse_stream(response.body, parser)
            else
              parser.parse(response)
            end
          end
          return parser.result
        else
          @error_handler = AWSErrorHandler.new(self, parser, @@amazon_problems) unless @error_handler
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


      # Returns an array of customer's buckets. Each item is a +hash+.
      #
      #  s3.list_all_my_buckets #=> 
      #    [{:owner_id           => "00000000009314cc309ffe736daa2b264357476c7fea6efb2c3347ac3ab2792a",
      #      :owner_display_name => "root",
      #      :name               => "bucket_name",
      #      :creation_date      => "2007-04-19T18:47:43.000Z"}, ..., {...}]
      #
    def list_all_my_buckets(headers={})
      req_hash = generate_rest_request('GET', headers.merge(:url=>''))
      request_info(req_hash, S3ListAllMyBucketsParser.new)
    rescue
      on_exception
    end
    
      # Creates new bucket. Returns +true+ or an exception.
      #
      #  s3.create_bucket('my_awesome_bucket') #=> true
      #
    def create_bucket(bucket, headers={})
      req_hash = generate_rest_request('PUT', headers.merge(:url=>bucket))
      request_info(req_hash, S3TrueParser.new)
    rescue
      on_exception
    end
    
      # Deletes new bucket. Bucket must be empty! Returns +true+ or an exception.
      #
      #  s3.delete_bucket('my_awesome_bucket')  #=> true
      # 
      # See also: force_delete_bucket method
      #
    def delete_bucket(bucket, headers={})
      req_hash = generate_rest_request('DELETE', headers.merge(:url=>bucket))
      request_info(req_hash, S3TrueParser.new)
    rescue
      on_exception
    end
    
      # Returns an array of bucket's keys. Each array item (key data) is a +hash+.
      #
      #  s3.list_bucket('my_awesome_bucket', { 'prefix'=>'t', 'marker'=>'', 'max-keys'=>5, delimiter=>'' }) #=>
      #    [{:key                => "test1",
      #      :last_modified      => "2007-05-18T07:00:59.000Z",
      #      :owner_id           => "00000000009314cc309ffe736daa2b264357476c7fea6efb2c3347ac3ab2792a",
      #      :owner_display_name => "root",
      #      :e_tag              => "000000000059075b964b07152d234b70",
      #      :storage_class      => "STANDARD",
      #      :size               => 3,
      #      :service=> {'is_truncated' => false,
      #                  'prefix'       => "t",
      #                  'marker'       => "",
      #                  'name'         => "my_awesome_bucket",
      #                  'max-keys'     => "5"}, ..., {...}]
      #
    def list_bucket(bucket, options={}, headers={})
      bucket  += '?'+options.map{|k, v| "#{k.to_s}=#{CGI::escape v.to_s}"}.join('&') unless options.blank?
      req_hash = generate_rest_request('GET', headers.merge(:url=>bucket))
      request_info(req_hash, S3ListBucketParser.new)
    rescue
      on_exception
    end

    # Incrementally list the contents of a bucket. Yields the following hash to a block:
    #  s3.incrementally_list_bucket('my_awesome_bucket', { 'prefix'=>'t', 'marker'=>'', 'max-keys'=>5, delimiter=>'' }) yields  
    #   {
    #     :name => 'bucketname',
    #     :prefix => 'subfolder/',
    #     :marker => 'fileN.jpg',
    #     :max_keys => 234,
    #     :delimiter => '/',
    #     :is_truncated => true,
    #     :next_marker => 'fileX.jpg',
    #     :contents => [
    #       { :key => "file1",
    #         :last_modified => "2007-05-18T07:00:59.000Z",
    #         :e_tag => "000000000059075b964b07152d234b70",
    #         :size => 3,
    #         :storage_class => "STANDARD",
    #         :owner_id => "00000000009314cc309ffe736daa2b264357476c7fea6efb2c3347ac3ab2792a",
    #         :owner_display_name => "root"
    #       }, { :key, ...}, ... {:key, ...}
    #     ]
    #     :common_prefixes => [
    #       "prefix1",
    #       "prefix2",
    #       ...,
    #       "prefixN"
    #     ]
    #   }
    def incrementally_list_bucket(bucket, options={}, headers={}, &block)
      internal_options = options.dup
      begin 
        internal_bucket = bucket.dup
        internal_bucket  += '?'+internal_options.map{|k, v| "#{k.to_s}=#{CGI::escape v.to_s}"}.join('&') unless internal_options.blank?
        req_hash = generate_rest_request('GET', headers.merge(:url=>internal_bucket))
        response = request_info(req_hash, S3ImprovedListBucketParser.new)
        there_are_more_keys = response[:is_truncated]
        if(there_are_more_keys)
          if(response[:next_marker])
            internal_options['marker'] = response[:next_marker]
          else 
            internal_options['marker'] = response[:contents].last[:key]
          end
          internal_options['max-keys'] ? (internal_options['max-keys'] -= response[:contents].length) : nil 
        end
        yield response
      end while there_are_more_keys 
      true
    rescue
      on_exception
    end
    
      # Saves object to Amazon. Returns +true+  or an exception. 
      # Any header starting with AMAZON_METADATA_PREFIX is considered user metadata. It will be stored with the object and returned when you retrieve the object. The total size of the HTTP request, not including the body, must be less than 4 KB.
      #    
      #  s3.put('my_awesome_bucket', 'log/curent/1.log', 'Ola-la!', 'x-amz-meta-family'=>'Woho556!') #=> true
      #
    def put(bucket, key, data=nil, headers={})
      req_hash = generate_rest_request('PUT', headers.merge(:url=>"#{bucket}/#{CGI::escape key}", :data=>data))
      request_info(req_hash, S3TrueParser.new)
    rescue
      on_exception
    end
    
      # Retrieves object data from Amazon. Returns a +hash+  or an exception.
      #
      #  s3.get('my_awesome_bucket', 'log/curent/1.log') #=>
      #
      #      {:object  => "Ola-la!", 
      #       :headers => {"last-modified"     => "Wed, 23 May 2007 09:08:04 GMT", 
      #                    "content-type"      => "", 
      #                    "etag"              => "\"000000000096f4ee74bc4596443ef2a4\"", 
      #                     "date"              => "Wed, 23 May 2007 09:08:03 GMT", 
      #                     "x-amz-id-2"        => "ZZZZZZZZZZZZZZZZZZZZ1HJXZoehfrS4QxcxTdNGldR7w/FVqblP50fU8cuIMLiu", 
      #                     "x-amz-meta-family" => "Woho556!",
      #                     "x-amz-request-id"  => "0000000C246D770C", 
      #                     "server"            => "AmazonS3", 
      #                     "content-length"    => "7"}}
      #
      # If a block is provided, yields incrementally to the block as
      # the response is read.  For large responses, this function is ideal as
      # the response can be 'streamed'.  The hash containing header fields is
      # still returned.
      # Example:
      # foo = File.new('./chunder.txt', File::CREAT|File::RDWR)
      # rhdr = s3.get('aws-test', 'Cent5V1_7_1.img.part.00') do |chunk|
      #   foo.write(chunk)
      # end
      # foo.close
      # 

    def get(bucket, key, headers={}, &block)
      req_hash = generate_rest_request('GET', headers.merge(:url=>"#{bucket}/#{CGI::escape key}"))
      request_info(req_hash, S3HttpResponseBodyParser.new, &block)
    rescue
      on_exception
    end

      # Retrieves object metadata. Returns a +hash+ of http_response_headers.
      #
      #  s3.head('my_awesome_bucket', 'log/curent/1.log') #=>
      #    {"last-modified"     => "Wed, 23 May 2007 09:08:04 GMT", 
      #     "content-type"      => "", 
      #     "etag"              => "\"000000000096f4ee74bc4596443ef2a4\"", 
      #     "date"              => "Wed, 23 May 2007 09:08:03 GMT", 
      #     "x-amz-id-2"        => "ZZZZZZZZZZZZZZZZZZZZ1HJXZoehfrS4QxcxTdNGldR7w/FVqblP50fU8cuIMLiu", 
      #     "x-amz-meta-family" => "Woho556!",
      #     "x-amz-request-id"  => "0000000C246D770C", 
      #     "server"            => "AmazonS3", 
      #     "content-length"    => "7"}
      #
    def head(bucket, key, headers={})
      req_hash = generate_rest_request('HEAD', headers.merge(:url=>"#{bucket}/#{CGI::escape key}"))
      request_info(req_hash, S3HttpResponseHeadParser.new)
    rescue
      on_exception
    end

      # Deletes key. Returns +true+ or an exception.
      #
      #  s3.delete('my_awesome_bucket', 'log/curent/1.log') #=> true
      #
    def delete(bucket, key='', headers={})
      req_hash = generate_rest_request('DELETE', headers.merge(:url=>"#{bucket}/#{CGI::escape key}"))
      request_info(req_hash, S3TrueParser.new)
    rescue
      on_exception
    end

      
      # Retieves the ACL (access control policy) for a bucket or object. Returns a hash of headers and xml doc with ACL data. See: http://docs.amazonwebservices.com/AmazonS3/2006-03-01/RESTAccessPolicy.html.
      #
      #  s3.get_acl('my_awesome_bucket', 'log/curent/1.log') #=>
      #    {:headers => {"x-amz-id-2"=>"B3BdDMDUz+phFF2mGBH04E46ZD4Qb9HF5PoPHqDRWBv+NVGeA3TOQ3BkVvPBjgxX",
      #                  "content-type"=>"application/xml;charset=ISO-8859-1",
      #                  "date"=>"Wed, 23 May 2007 09:40:16 GMT",
      #                  "x-amz-request-id"=>"B183FA7AB5FBB4DD",
      #                  "server"=>"AmazonS3",
      #                  "transfer-encoding"=>"chunked"},
      #     :object  => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner>
      #                  <ID>16144ab2929314cc309ffe736daa2b264357476c7fea6efb2c3347ac3ab2792a</ID><DisplayName>root</DisplayName></Owner>
      #                  <AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>
      #                  16144ab2929314cc309ffe736daa2b264357476c7fea6efb2c3347ac3ab2792a</ID><DisplayName>root</DisplayName></Grantee>
      #                  <Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>" }
      #
    def get_acl(bucket, key='', headers={})
      key = key.blank? ? '' : "/#{CGI::escape key}"
      req_hash = generate_rest_request('GET', headers.merge(:url=>"#{bucket}#{key}?acl"))
      request_info(req_hash, S3HttpResponseBodyParser.new) 
    rescue
      on_exception
    end
      
      # Retieves the ACL (access control policy) for a bucket or object. 
      # Returns a hash of {:owner, :grantees}
      #
      #  s3.get_acl_parse('my_awesome_bucket', 'log/curent/1.log') #=>
      #
      #  { :grantees=>
      #    { "16...2a"=>
      #      { :display_name=>"root",
      #        :permissions=>["FULL_CONTROL"],
      #        :attributes=>
      #         { "xsi:type"=>"CanonicalUser",
      #           "xmlns:xsi"=>"http://www.w3.org/2001/XMLSchema-instance"}},
      #     "http://acs.amazonaws.com/groups/global/AllUsers"=>
      #       { :display_name=>"AllUsers",
      #         :permissions=>["READ"],
      #         :attributes=>
      #          { "xsi:type"=>"Group",
      #            "xmlns:xsi"=>"http://www.w3.org/2001/XMLSchema-instance"}}},
      #   :owner=>
      #     { :id=>"16..2a",
      #       :display_name=>"root"}}
      #
    def get_acl_parse(bucket, key='', headers={})
      key = key.blank? ? '' : "/#{CGI::escape key}"
      req_hash = generate_rest_request('GET', headers.merge(:url=>"#{bucket}#{key}?acl"))
      acl = request_info(req_hash, S3AclParser.new)
      result = {}
      result[:owner]    = acl[:owner]
      result[:grantees] = {}
      acl[:grantees].each do |grantee|
        key = grantee[:id] || grantee[:uri]
        if result[:grantees].key?(key)
          result[:grantees][key][:permissions] << grantee[:permissions]
        else
          result[:grantees][key] = 
            { :display_name => grantee[:display_name] || grantee[:uri].to_s[/[^\/]*$/],
              :permissions  => grantee[:permissions].to_a,
              :attributes   => grantee[:attributes] }
        end
      end
      result
    rescue
      on_exception
    end
    
      # Sets the ACL on a bucket or object.
    def put_acl(bucket, key, acl_xml_doc, headers={})
      key = key.blank? ? '' : "/#{CGI::escape key}"
      req_hash = generate_rest_request('PUT', headers.merge(:url=>"#{bucket}#{key}?acl", :data=>acl_xml_doc))
      request_info(req_hash, S3HttpResponseBodyParser.new)
    rescue
      on_exception
    end
    
      # Retieves the ACL (access control policy) for a bucket. Returns a hash of headers and xml doc with ACL data.
    def get_bucket_acl(bucket, headers={})
      return get_acl(bucket, '', headers)
    rescue
      on_exception
    end
    
      # Sets the ACL on a bucket only.
    def put_bucket_acl(bucket, acl_xml_doc, headers={})
      return put_acl(bucket, '', acl_xml_doc, headers)
    rescue
      on_exception
    end


      # Removes all keys from bucket. Returns +true+ or an exception.
      #
      #  s3.clear_bucket('my_awesome_bucket') #=> true
      #
    def clear_bucket(bucket)
      incrementally_list_bucket(bucket) do |results|
        results[:contents].each { |key| delete(bucket, key[:key]) }
      end
      true
    rescue
      on_exception
    end
    
      # Deletes all keys in bucket then deletes bucket. Returns +true+ or an exception.
      #
      #  s3.force_delete_bucket('my_awesome_bucket')
      #
    def force_delete_bucket(bucket)
      clear_bucket(bucket)
      delete_bucket(bucket)
    rescue
      on_exception
    end
    
      # Deletes all keys where the 'folder_key' may be assumed as 'folder' name. Returns an array of string keys that have been deleted.
      #
      #  s3.list_bucket('my_awesome_bucket').map{|key_data| key_data[:key]} #=> ['test','test/2/34','test/3','test1','test1/logs']
      #  s3.delete_folder('my_awesome_bucket','test')                       #=> ['test','test/2/34','test/3']
      #
    def delete_folder(bucket, folder_key, separator='/')
      folder_key.chomp!(separator)
      allkeys = []
      incrementally_list_bucket(bucket, { 'prefix' => folder_key }) do |results|
        keys = results[:contents].map{ |s3_key| s3_key[:key][/^#{folder_key}($|#{separator}.*)/] ? s3_key[:key] : nil}.compact
        keys.each{ |key| delete(bucket, key) }
        allkeys << keys
      end
      allkeys
    rescue
      on_exception
    end
    
      # Retrieves object data only (headers are omitted). Returns +string+ or an exception.
      #
      #  s3.get('my_awesome_bucket', 'log/curent/1.log') #=> 'Ola-la!'
      #
    def get_object(bucket, key, headers={})
      get(bucket, key, headers)[:object]
    rescue
      on_exception
    end
    
    #-----------------------------------------------------------------
    #      Query API: Links
    #-----------------------------------------------------------------

      # Generates link for QUERY API
    def generate_link(method, headers={}, expires=nil) #:nodoc:
      path = headers[:url]
      path = "/#{path}" unless path[/^\//]
       # expiration time
      expires ||= DEFAULT_EXPIRES_AFTER
      expires   = Time.now.utc.since(expires) if expires.is_a?(Fixnum) && (expires<1.year)
      expires   = expires.to_i
        # remove unset(==optional) and symbolyc keys
      headers.each{ |key, value| headers.delete(key) if (value.nil? || key.is_a?(Symbol)) }
        #generate auth strings
      auth_string = canonical_string(method, path, headers, expires)
      signature   = CGI::escape(Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new("sha1"), @aws_secret_access_key, auth_string)).strip)
        # path building
      addon = "Signature=#{signature}&Expires=#{expires}&AWSAccessKeyId=#{@aws_access_key_id}"
      path += path[/\?/] ? "&#{addon}" : "?#{addon}"
      "#{@params[:protocol]}://#{@params[:server]}:#{@params[:port]}#{path}"
    rescue
      on_exception
    end
    
      # Generates link for 'ListAllMyBuckets'.
      #
      #  s3.list_all_my_buckets_link #=> url string
      #
    def list_all_my_buckets_link(expires=nil, headers={})
      generate_link('GET', headers.merge(:url=>''), expires)
    rescue
      on_exception
    end
    
      # Generates link for 'CreateBucket'.
      #
      #  s3.create_bucket_link('my_awesome_bucket') #=> url string
      #
    def create_bucket_link(bucket, expires=nil, headers={})
      generate_link('PUT', headers.merge(:url=>bucket), expires)
    rescue
      on_exception
    end
    
      # Generates link for 'DeleteBucket'.
      #
      #  s3.delete_bucket_link('my_awesome_bucket') #=> url string
      #
    def delete_bucket_link(bucket, expires=nil,  headers={})
      generate_link('DELETE', headers.merge(:url=>bucket), expires)
    rescue
      on_exception
    end
    
      # Generates link for 'ListBucket'.
      #
      #  s3.list_bucket_link('my_awesome_bucket') #=> url string
      #
    def list_bucket_link(bucket, options=nil, expires=nil, headers={})
      bucket += '?' + options.map{|k, v| "#{k.to_s}=#{CGI::escape v.to_s}"}.join('&') unless options.blank?
      generate_link('GET', headers.merge(:url=>bucket), expires)
    rescue
      on_exception
    end
    
      # Generates link for 'PutObject'.
      #
      #  s3.put_link('my_awesome_bucket',key, object) #=> url string
      #
    def put_link(bucket, key, data=nil, expires=nil, headers={})
      generate_link('PUT', headers.merge(:url=>"#{bucket}/#{CGI::escape key}", :data=>data), expires)
    rescue
      on_exception
    end
    
      # Generates link for 'GetObject'.
      #
      #  s3.get_link('my_awesome_bucket',key) #=> url string
      #
    def get_link(bucket, key, expires=nil, headers={})
      generate_link('GET', headers.merge(:url=>"#{bucket}/#{CGI::escape key}"), expires)
    rescue
      on_exception
    end
    
      # Generates link for 'HeadObject'.
      #
      #  s3.head_link('my_awesome_bucket',key) #=> url string
      #
    def head_link(bucket, key, expires=nil,  headers={})
      generate_link('HEAD', headers.merge(:url=>"#{bucket}/#{CGI::escape key}"), expires)
    rescue
      on_exception
    end
    
      # Generates link for 'DeleteObject'.
      #
      #  s3.delete_link('my_awesome_bucket',key) #=> url string
      #
    def delete_link(bucket, key, expires=nil, headers={})
      generate_link('DELETE', headers.merge(:url=>"#{bucket}/#{CGI::escape key}"), expires)
    rescue
      on_exception
    end
    
    
      # Generates link for 'GetACL'.
      #
      #  s3.get_acl_link('my_awesome_bucket',key) #=> url string
      #
    def get_acl_link(bucket, key='', headers={})
      return generate_link('GET', headers.merge(:url=>"#{bucket}/#{CGI::escape key}?acl"))
    rescue
      on_exception
    end
    
      # Generates link for 'PutACL'.
      #
      #  s3.put_acl_link('my_awesome_bucket',key) #=> url string
      #
    def put_acl_link(bucket, key='', headers={})
      return generate_link('PUT', headers.merge(:url=>"#{bucket}/#{CGI::escape key}?acl"))
    rescue
      on_exception
    end
    
      # Generates link for 'GetBucketACL'.
      #
      #  s3.get_acl_link('my_awesome_bucket',key) #=> url string
      #
    def get_bucket_acl_link(bucket, headers={})
      return get_acl_link(bucket, '', headers)
    rescue
      on_exception
    end
    
      # Generates link for 'PutBucketACL'.
      #
      #  s3.put_acl_link('my_awesome_bucket',key) #=> url string
      #
    def put_bucket_acl_link(bucket, acl_xml_doc, headers={})
      return put_acl_link(bucket, '', acl_xml_doc, headers)
    rescue
      on_exception
    end

    #-----------------------------------------------------------------
    #      PARSERS:
    #-----------------------------------------------------------------

    class S3ListAllMyBucketsParser < RightAWSParser # :nodoc:
      def reset
        @result = []
        @owner  = {}
      end
      def tagstart(name, attributes)
        @current_bucket = {} if name == 'Bucket'
      end
      def tagend(name)
        case name
          when 'ID'          ; @owner[:owner_id]               = @text
          when 'DisplayName' ; @owner[:owner_display_name]     = @text
          when 'Name'        ; @current_bucket[:name]          = @text
          when 'CreationDate'; @current_bucket[:creation_date] = @text
          when 'Bucket'      ; @result << @current_bucket.merge(@owner)
        end
      end
    end

    class S3ListBucketParser < RightAWSParser  # :nodoc:
      def reset
        @result      = []
        @service     = {}
        @current_key = {}
      end
      def tagstart(name, attributes)
        @current_key = {} if name == 'Contents'
      end
      def tagend(name)
        case name
            # service info
          when 'Name'        ; @service['name']         = @text
          when 'Prefix'      ; @service['prefix']       = @text
          when 'Marker'      ; @service['marker']       = @text
          when 'MaxKeys'     ; @service['max-keys']     = @text
          when 'Delimiter'   ; @service['delimiter']    = @text
          when 'IsTruncated' ; @service['is_truncated'] = (@text =~ /false/ ? false : true)
            # key data
          when 'Key'         ; @current_key[:key]                = @text
          when 'LastModified'; @current_key[:last_modified]      = @text
          when 'ETag'        ; @current_key[:e_tag]              = @text
          when 'Size'        ; @current_key[:size]               = @text.to_i
          when 'StorageClass'; @current_key[:storage_class]      = @text
          when 'ID'          ; @current_key[:owner_id]           = @text
          when 'DisplayName' ; @current_key[:owner_display_name] = @text
          when 'Contents'    ; @current_key[:service]            = @service;  @result << @current_key
        end
      end
    end

    class S3ImprovedListBucketParser < RightAWSParser  # :nodoc:
      def reset
        @result      = {}
        @result[:contents] = []
        @result[:common_prefixes] = []
        @contents    = []
        @current_key = {}
        @common_prefixes = []
        @in_common_prefixes = false
      end
      def tagstart(name, attributes)
        @current_key = {} if name == 'Contents'
        @in_common_prefixes = true if name == 'CommonPrefixes'
      end
      def tagend(name)
        case name
            # service info
          when 'Name'        ; @result[:name]         = @text
          # Amazon uses the same tag for the search prefix and for the entries
            # in common prefix...so use our simple flag to see which element
            # we are parsing
          when 'Prefix'      ; @in_common_prefixes ? @common_prefixes << @text : @result[:prefix] = @text
          when 'Marker'      ; @result[:marker]       = @text
          when 'MaxKeys'     ; @result[:max_keys]     = @text
          when 'Delimiter'   ; @result[:delimiter]    = @text
          when 'IsTruncated' ; @result[:is_truncated] = (@text =~ /false/ ? false : true)
          when 'NextMarker'  ; @result[:next_marker]  = @text
            # key data
          when 'Key'         ; @current_key[:key]                = @text
          when 'LastModified'; @current_key[:last_modified]      = @text
          when 'ETag'        ; @current_key[:e_tag]              = @text
          when 'Size'        ; @current_key[:size]               = @text.to_i
          when 'StorageClass'; @current_key[:storage_class]      = @text
          when 'ID'          ; @current_key[:owner_id]           = @text
          when 'DisplayName' ; @current_key[:owner_display_name] = @text
          when 'Contents'    ; @result[:contents] << @current_key
            # Common Prefix stuff
          when 'CommonPrefixes' ; @result[:common_prefixes] = @common_prefixes; @in_common_prefixes = false
        end
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Non XML
    #-----------------------------------------------------------------

    class S3HttpResponseParser   # :nodoc:
      attr_reader :result
      def parse(response)
        @result = response
      end
      def headers_to_string(headers)
        result = {}
        headers.each do |key, value|
          value       = value.to_s if value.is_a?(Array) && value.size<2
          result[key] = value
        end
        result
      end
    end

    class S3TrueParser < S3HttpResponseParser  # :nodoc:
      def parse(response)
        @result = response.is_a?(Net::HTTPSuccess)
      end
    end

    class S3HttpResponseBodyParser < S3HttpResponseParser  # :nodoc:
      def parse(response)
        @result = { 
          :object  => response.body, 
          :headers => headers_to_string(response.to_hash)
        }
      end
    end

    class S3HttpResponseHeadParser < S3HttpResponseParser  # :nodoc:
      def parse(response)
        @result = headers_to_string(response.to_hash)
      end
    end


    class S3AclParser < RightAWSParser  # :nodoc:
      def reset
        @result          = {:grantees=>[], :owner=>{}}
        @current_grantee = {}
      end
      def tagstart(name, attributes)
        @current_grantee = { :attributes => attributes } if name=='Grantee'
      end
      def tagend(name)
        case name
            # service info
          when 'ID'
            if @xmlpath == 'AccessControlPolicy/Owner'
              @result[:owner][:id] = @text
            else
              @current_grantee[:id] = @text
            end
          when 'DisplayName'
            if @xmlpath == 'AccessControlPolicy/Owner'
              @result[:owner][:display_name] = @text
            else
              @current_grantee[:display_name] = @text
            end
          when 'URI'
            @current_grantee[:uri] = @text
          when 'Permission'
            @current_grantee[:permissions] = @text
          when 'Grant'
            @result[:grantees] << @current_grantee
        end
      end
    end
    
  end

end
