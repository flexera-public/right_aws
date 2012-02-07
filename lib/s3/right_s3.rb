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
  
  # = RightAws::S3 -- RightScale's Amazon S3 interface
  # The RightAws::S3 class provides a complete interface to Amazon's Simple
  # Storage Service.
  # For explanations of the semantics
  # of each call, please refer to Amazon's documentation at
  # http://developer.amazonwebservices.com/connect/kbcategory.jspa?categoryID=48
  #
  # See examples below for the bucket and buckets methods.
  #
  # Error handling: all operations raise an RightAws::AwsError in case
  # of problems. Note that transient errors are automatically retried.
  #
  # It is a good way to use domain naming style getting a name for the buckets. 
  # See http://docs.amazonwebservices.com/AmazonS3/2006-03-01/UsingBucket.html
  # about the naming convention for the buckets. This case they can be accessed using a virtual domains.
  # 
  # Let assume you have 3 buckets: 'awesome-bucket', 'awesome_bucket' and 'AWEsomE-bucket'.
  # The first ones objects can be accessed as: http:// awesome-bucket.s3.amazonaws.com/key/object
  # 
  # But the rest have to be accessed as:
  # http:// s3.amazonaws.com/awesome_bucket/key/object and  http:// s3.amazonaws.com/AWEsomE-bucket/key/object
  #  
  # See: http://docs.amazonwebservices.com/AmazonS3/2006-03-01/VirtualHosting.html for better explanation.
  #
  class S3
    attr_reader :interface
    
    # Create a new handle to an S3 account. All handles share the same per process or per thread
    # HTTP connection to Amazon S3. Each handle is for a specific account.
    # The +params+ are passed through as-is to RightAws::S3Interface.new
    # 
    # Params is a hash:
    #
    #    {:server       => 's3.amazonaws.com'   # Amazon service host: 's3.amazonaws.com'(default)
    #     :port         => 443                  # Amazon service port: 80 or 443(default)
    #     :protocol     => 'https'              # Amazon service protocol: 'http' or 'https'(default)
    #     :logger       => Logger Object}       # Logger instance: logs to STDOUT if omitted }
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      @interface = S3Interface.new(aws_access_key_id, aws_secret_access_key, params)
    end
    
    # Retrieve a list of buckets.
    # Returns an array of RightAws::S3::Bucket instances.
    #  # Create handle to S3 account
    #  s3 = RightAws::S3.new(aws_access_key_id, aws_secret_access_key)
    #  my_buckets_names = s3.buckets.map{|b| b.name}
    #  puts "Buckets on S3: #{my_bucket_names.join(', ')}"
    def buckets
      @interface.list_all_my_buckets.map! do |entry|
        owner = Owner.new(entry[:owner_id], entry[:owner_display_name])
        Bucket.new(self, entry[:name], entry[:creation_date], owner)
      end
    end
    
    # Retrieve an individual bucket.
    # If the bucket does not exist and +create+ is set, a new bucket
    # is created on S3. Launching this method with +create+=+true+ may
    # affect on the bucket's ACL if the bucket already exists.
    # Returns a RightAws::S3::Bucket instance or +nil+ if the bucket does not exist 
    # and +create+ is not set.
    #
    #  s3 = RightAws::S3.new(aws_access_key_id, aws_secret_access_key)
    #  bucket1 = s3.bucket('my_awesome_bucket_1')
    #  bucket1.keys  #=> exception here if the bucket does not exists
    #   ...
    #  bucket2 = s3.bucket('my_awesome_bucket_2', true)
    #  bucket2.keys  #=> list of keys
    #  # create a bucket at the European location with public read access
    #  bucket3 = s3.bucket('my-awesome-bucket-3', true, 'public-read', :location => :eu)
    #  
    #  see http://docs.amazonwebservices.com/AmazonS3/2006-03-01/RESTAccessPolicy.html
    #  (section: Canned Access Policies)
    #
    def bucket(name, create=false, perms=nil, headers={})
      result = nil
      if create
        headers['x-amz-acl'] = perms if perms
        @interface.create_bucket(name, headers) 
      end
      begin
        buckets.each do |bucket| 
          if bucket.name == name 
            result = bucket
            break
          end
        end
      rescue RightAws::AwsError => e
        # With non root creds one can use bucket(s) but can't list them
        raise e unless e.message['AccessDenied']
        result = Bucket::new(self, name)
      end
      result
    end
    

    class Bucket
      attr_reader :s3, :name, :owner, :creation_date
      
      # Create a Bucket instance.
      # If the bucket does not exist and +create+ is set, a new bucket
      # is created on S3. Launching this method with +create+=+true+ may
      # affect on the bucket's ACL if the bucket already exists.
      # Returns Bucket instance or +nil+ if the bucket does not exist 
      # and +create+ is not set.
      #
      #  s3 = RightAws::S3.new(aws_access_key_id, aws_secret_access_key)
      #   ...
      #  bucket1 = RightAws::S3::Bucket.create(s3, 'my_awesome_bucket_1')
      #  bucket1.keys  #=> exception here if the bucket does not exists
      #   ...
      #  bucket2 = RightAws::S3::Bucket.create(s3, 'my_awesome_bucket_2', true)
      #  bucket2.keys  #=> list of keys
      #  # create a bucket at the European location with public read access
      #  bucket3 = RightAws::S3::Bucket.create(s3,'my-awesome-bucket-3', true, 'public-read', :location => :eu)
      #  
      #  see http://docs.amazonwebservices.com/AmazonS3/2006-03-01/RESTAccessPolicy.html
      #  (section: Canned Access Policies)
      #
      def self.create(s3, name, create=false, perms=nil, headers={}) 
        s3.bucket(name, create, perms, headers)
      end


        # Create a bucket instance. In normal use this method should
        # not be called directly.
        # Use RightAws::S3::Bucket.create or RightAws::S3.bucket instead. 
      def initialize(s3, name, creation_date=nil, owner=nil)
        @s3    = s3
        @name  = name
        @owner = owner
        @creation_date = creation_date
        if @creation_date && !@creation_date.is_a?(Time)
          @creation_date = Time.parse(@creation_date)
        end
      end
      
        # Return bucket name as a String.
        #
        #  bucket = RightAws::S3.bucket('my_awesome_bucket') 
        #  puts bucket #=> 'my_awesome_bucket'
        #
      def to_s
        @name.to_s
      end
      alias_method :full_name, :to_s
      
        # Return a public link to bucket.
        # 
        #  bucket.public_link #=> 'https://s3.amazonaws.com:443/my_awesome_bucket'
        #
      def public_link
        params = @s3.interface.params
        "#{params[:protocol]}://#{params[:server]}:#{params[:port]}/#{full_name}"
      end
      
        # Returns the bucket location
      def location
        @location ||= @s3.interface.bucket_location(@name)
      end
      
      # Retrieves the logging configuration for a bucket. 
      # Returns a hash of {:enabled, :targetbucket, :targetprefix}
      # 
      #   bucket.logging_info()
      #   => {:enabled=>true, :targetbucket=>"mylogbucket", :targetprefix=>"loggylogs/"}
      def logging_info
        @s3.interface.get_logging_parse(:bucket => @name)
      end
      
      # Enables S3 server access logging on a bucket.  The target bucket must have been properly configured to receive server
      # access logs.
      #  Params:
      #   :targetbucket - either the target bucket object or the name of the target bucket
      #   :targetprefix - the prefix under which all logs should be stored
      #
      #  bucket.enable_logging(:targetbucket=>"mylogbucket", :targetprefix=>"loggylogs/")
      #    => true
      def enable_logging(params)
        AwsUtils.mandatory_arguments([:targetbucket, :targetprefix], params)
        AwsUtils.allow_only([:targetbucket, :targetprefix], params)
        xmldoc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><BucketLoggingStatus xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\"><LoggingEnabled><TargetBucket>#{params[:targetbucket]}</TargetBucket><TargetPrefix>#{params[:targetprefix]}</TargetPrefix></LoggingEnabled></BucketLoggingStatus>"
        @s3.interface.put_logging(:bucket => @name, :xmldoc => xmldoc)
      end
      
      # Disables S3 server access logging on a bucket.  Takes no arguments.
      def disable_logging
        xmldoc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><BucketLoggingStatus xmlns=\"http://doc.s3.amazonaws.com/2006-03-01\"></BucketLoggingStatus>"
        @s3.interface.put_logging(:bucket => @name, :xmldoc => xmldoc)
      end

        # Retrieve a group of keys from Amazon. 
        # +options+ is a hash: { 'prefix'=>'', 'marker'=>'', 'max-keys'=>5, 'delimiter'=>'' }). 
        # Retrieves meta-headers information if +head+ it +true+. 
        # Returns an array of Key instances. 
        #
        #  bucket.keys                     #=> # returns all keys from bucket
        #  bucket.keys('prefix' => 'logs') #=> # returns all keys that starts with 'logs'
        #
      def keys(options={}, head=false)
        keys_and_service(options, head)[0]
      end

        # Same as +keys+ method but return an array of [keys, service_data]. 
        # where +service_data+ is a hash with additional output information.
        #
        #  keys, service = bucket.keys_and_service({'max-keys'=> 2, 'prefix' => 'logs'})
        #  p keys    #=> # 2 keys array
        #  p service #=> {"max-keys"=>"2", "prefix"=>"logs", "name"=>"my_awesome_bucket", "marker"=>"", "is_truncated"=>true, :common_prefixes=>[]}
        #
      def keys_and_service(options={}, head=false)
        opt = {}; options.each{ |key, value| opt[key.to_s] = value }
        service = {}
        keys = []
        @s3.interface.incrementally_list_bucket(@name, opt) do |_service|
          service = _service
          service[:contents].each do |entry|
            owner = Owner.new(entry[:owner_id], entry[:owner_display_name])
            key = Key.new(self, entry[:key], nil, {}, {}, entry[:last_modified], entry[:e_tag], entry[:size], entry[:storage_class], owner)
            key.head if head
            keys << key
          end
        end
        service.delete(:contents)
        [keys, service]
      end

        # Retrieve key information from Amazon. 
        # The +key_name+ is a +String+ or Key instance. 
        # Retrieves meta-header information if +head+ is +true+. 
        # Returns new Key instance. 
        #
        #  key = bucket.key('logs/today/1.log', true) #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #   # is the same as:
        #  key = RightAws::S3::Key.create(bucket, 'logs/today/1.log')
        #  key.head
        #
      def key(key_name, head=false)
        raise 'Key name can not be empty.' if key_name.right_blank?
        key_instance = nil
          # if this key exists - find it ....
        keys({'prefix'=>key_name}, head).each do |key|
          if key.name == key_name.to_s
            key_instance = key
            break
          end
        end
          # .... else this key is unknown
        unless key_instance
          key_instance = Key.create(self, key_name.to_s)
        end
        key_instance
      end
      
        # Store object data. 
        # The +key+ is a +String+ or Key instance. 
        # Returns +true+.
        #
        #  bucket.put('logs/today/1.log', 'Olala!') #=> true
        #
      def put(key, data=nil, meta_headers={}, perms=nil, headers={})
        key = Key.create(self, key.to_s, data, meta_headers) unless key.is_a?(Key) 
        key.put(data, perms, headers)
      end

        # Retrieve data object from Amazon. 
        # The +key+ is a +String+ or Key. 
        # Returns String instance. 
        #
        #  data = bucket.get('logs/today/1.log') #=> 
        #  puts data #=> 'sasfasfasdf'
        #
      def get(key, headers={})
        key = Key.create(self, key.to_s) unless key.is_a?(Key)
        key.get(headers)
      end

        # Rename object. Returns RightAws::S3::Key instance.
        # 
        #  new_key = bucket.rename_key('logs/today/1.log','logs/today/2.log')   #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #  puts key.name   #=> 'logs/today/2.log'
        #  key.exists?     #=> true
        #
      def rename_key(old_key_or_name, new_name)
        old_key_or_name = Key.create(self, old_key_or_name.to_s) unless old_key_or_name.is_a?(Key)
        old_key_or_name.rename(new_name)
        old_key_or_name
      end

        # Create an object copy. Returns a destination RightAws::S3::Key instance.
        # 
        #  new_key = bucket.copy_key('logs/today/1.log','logs/today/2.log')   #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #  puts key.name   #=> 'logs/today/2.log'
        #  key.exists?     #=> true
        #
      def copy_key(old_key_or_name, new_key_or_name)
        old_key_or_name = Key.create(self, old_key_or_name.to_s) unless old_key_or_name.is_a?(Key)
        old_key_or_name.copy(new_key_or_name)
      end
      
        # Move an object to other location. Returns a destination RightAws::S3::Key instance.
        # 
        #  new_key = bucket.copy_key('logs/today/1.log','logs/today/2.log')   #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #  puts key.name   #=> 'logs/today/2.log'
        #  key.exists?     #=> true
        #
      def move_key(old_key_or_name, new_key_or_name)
        old_key_or_name = Key.create(self, old_key_or_name.to_s) unless old_key_or_name.is_a?(Key)
        old_key_or_name.move(new_key_or_name)
      end
      
        # Remove all keys from a bucket. 
        # Returns +true+. 
        #
        #  bucket.clear #=> true
        #
      def clear
        @s3.interface.clear_bucket(@name)  
      end

        # Delete all keys where the 'folder_key' can be interpreted
        # as a 'folder' name. 
        # Returns an array of string keys that have been deleted.
        #
        #  bucket.keys.map{|key| key.name}.join(', ') #=> 'test, test/2/34, test/3, test1, test1/logs'
        #  bucket.delete_folder('test')               #=> ['test','test/2/34','test/3']
        #
      def delete_folder(folder, separator='/')
        @s3.interface.delete_folder(@name, folder, separator)
      end
      
        # Delete a bucket. Bucket must be empty.
        # If +force+ is set, clears and deletes the bucket. 
        # Returns +true+. 
        #
        #  bucket.delete(:force => true) #=> true
        #
      def delete(options={})
        force = options.is_a?(Hash) && options[:force]==true
        force ? @s3.interface.force_delete_bucket(@name) : @s3.interface.delete_bucket(@name)
      end

        # Return a list of grantees. 
        #
      def grantees
        Grantee::grantees(self)
      end

    end


    class Key
      attr_reader   :bucket,  :name, :last_modified, :e_tag, :size, :storage_class, :owner
      attr_accessor :headers, :meta_headers
      attr_writer   :data

        # Separate Amazon meta headers from other headers
      def self.split_meta(headers) #:nodoc:
        hash = headers.dup
        meta = {}
        hash.each do |key, value|
          if key[/^#{S3Interface::AMAZON_METADATA_PREFIX}/]
            meta[key.gsub(S3Interface::AMAZON_METADATA_PREFIX,'')] = value
            hash.delete(key)
          end
        end
        [hash, meta]
      end
      
      def self.add_meta_prefix(meta_headers, prefix=S3Interface::AMAZON_METADATA_PREFIX)
        meta = {}
        meta_headers.each do |meta_header, value|
          if meta_header[/#{prefix}/]
            meta[meta_header] = value
          else
            meta["#{S3Interface::AMAZON_METADATA_PREFIX}#{meta_header}"] = value
          end
        end
        meta
      end


        # Create a new Key instance, but do not create the actual key. 
        # The +name+ is a +String+.
        # Returns a new Key instance. 
        #
        #  key = RightAws::S3::Key.create(bucket, 'logs/today/1.log') #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #  key.exists?                                                  #=> true | false
        #  key.put('Woohoo!')                                           #=> true
        #  key.exists?                                                  #=> true
        #
      def self.create(bucket, name, data=nil, meta_headers={})
        new(bucket, name, data, {}, meta_headers)
      end
      
        # Create a new Key instance, but do not create the actual key.
        # In normal use this method should not be called directly.
        # Use RightAws::S3::Key.create or bucket.key() instead. 
        #
      def initialize(bucket, name, data=nil, headers={}, meta_headers={}, 
                     last_modified=nil, e_tag=nil, size=nil, storage_class=nil, owner=nil)
        raise 'Bucket must be a Bucket instance.' unless bucket.is_a?(Bucket)
        @bucket        = bucket
        @name          = name
        @data          = data
        @e_tag         = e_tag
        @size          = size.to_i
        @storage_class = storage_class
        @owner         = owner
        @last_modified = last_modified
        if @last_modified && !@last_modified.is_a?(Time) 
          @last_modified = Time.parse(@last_modified)
        end
        @headers, @meta_headers = self.class.split_meta(headers)
        @meta_headers.merge!(meta_headers)
      end
      
        # Return key name as a String.
        #
        #  key = RightAws::S3::Key.create(bucket, 'logs/today/1.log') #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #  puts key                                                   #=> 'logs/today/1.log'
        #
      def to_s
        @name.to_s
      end
      
        # Return the full S3 path to this key (bucket/key).
        # 
        #  key.full_name #=> 'my_awesome_bucket/cool_key'
        #
      def full_name(separator='/')
        "#{@bucket.to_s}#{separator}#{@name}"
      end
        
        # Return a public link to a key.
        # 
        #  key.public_link #=> 'https://s3.amazonaws.com:443/my_awesome_bucket/cool_key'
        #
      def public_link
        params = @bucket.s3.interface.params
        "#{params[:protocol]}://#{params[:server]}:#{params[:port]}/#{full_name('/')}"
      end
         
        # Return Key data. Retrieve this data from Amazon if it is the first time call.
        # TODO TRB 6/19/07 What does the above mean? Clarify.
        #
      def data
        get if !@data and exists?
        @data
      end
        
        # Getter for the 'content-type' metadata
      def content_type
        @headers['content-type'] if @headers
      end
      
        # Helper to get and URI-decode a header metadata.
        # Metadata have to be HTTP encoded (rfc2616) as we use the Amazon S3 REST api
        # see http://docs.amazonwebservices.com/AmazonS3/latest/index.html?UsingMetadata.html
      def decoded_meta_headers(key = nil)
        if key
          # Get one metadata value by its key
          URI.decode(@meta_headers[key.to_s])
        else
          # Get a hash of all metadata with a decoded value
          @decoded_meta_headers ||= begin
            metadata = {}
            @meta_headers.each do |key, value|
              metadata[key.to_sym] = URI.decode(value)
            end
            metadata
          end
        end
      end
      
        # Retrieve object data and attributes from Amazon. 
        # Returns a +String+. 
        #
      def get(headers={})
        response = @bucket.s3.interface.get(@bucket.name, @name, headers)
        @data    = response[:object]
        @headers, @meta_headers = self.class.split_meta(response[:headers])
        refresh(false)
        @data
      end
      
        # Store object data on S3. 
        # Parameter +data+ is a +String+ or S3Object instance. 
        # Returns +true+.
        #
        #  key = RightAws::S3::Key.create(bucket, 'logs/today/1.log')
        #  key.data = 'Qwerty'
        #  key.put             #=> true
        #   ...
        #  key.put('Olala!')   #=> true
        #
      def put(data=nil, perms=nil, headers={})
        headers['x-amz-acl'] = perms if perms
        @data = data || @data
        meta  = self.class.add_meta_prefix(@meta_headers)
        @bucket.s3.interface.put(@bucket.name, @name, @data, meta.merge(headers))
      end

        # Store object data on S3 using the Multipart Upload API. This is useful if you do not know the file size
        # upfront (for example reading from pipe or socket) or if you are transmitting data over an unreliable network.
        #
        # Parameter +data+ is an object which responds to :read or an object which can be converted to a String prior to upload.
        # Parameter +part_size+ determines the size of each part sent (must be > 5MB per Amazon's API requirements)
        #
        # If data is a stream the caller is responsible for calling close() on the stream after this methods returns
        #
        # Returns +true+.
        #
        #  upload_data = StringIO.new('My sample data')
        #  key = RightAws::S3::Key.create(bucket, 'logs/today/1.log')
        #  key.data = upload_data
        #  key.put_multipart(:part_size => 5*1024*1024)             #=> true
        #
      def put_multipart(data=nil, perms=nil, headers={}, part_size=nil)
        headers['x-amz-acl'] = perms if perms
        @data = data || @data
        meta  = self.class.add_meta_prefix(@meta_headers)
        @bucket.s3.interface.store_object_multipart({:bucket => @bucket.name, :key => @name, :data => @data, :headers => meta.merge(headers), :part_size => part_size})
      end
      
        # Rename an object. Returns new object name.
        # 
        #  key = RightAws::S3::Key.create(bucket, 'logs/today/1.log') #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #  key.rename('logs/today/2.log')   #=> 'logs/today/2.log'
        #  puts key.name                    #=> 'logs/today/2.log'
        #  key.exists?                      #=> true
        #
      def rename(new_name)
        @bucket.s3.interface.rename(@bucket.name, @name, new_name)
        @name = new_name
      end
      
        # Create an object copy. Returns a destination RightAws::S3::Key instance.
        #
        #  # Key instance as destination
        #  key1 = RightAws::S3::Key.create(bucket, 'logs/today/1.log') #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #  key2 = RightAws::S3::Key.create(bucket, 'logs/today/2.log') #=> #<RightAws::S3::Key:0xb7b5e240 ... >
        #  key1.put('Olala!')   #=> true
        #  key1.copy(key2)      #=> #<RightAws::S3::Key:0xb7b5e240 ... >
        #  key1.exists?         #=> true
        #  key2.exists?         #=> true
        #  puts key2.data       #=> 'Olala!'
        #
        #  # String as destination
        #  key = RightAws::S3::Key.create(bucket, 'logs/today/777.log') #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #  key.put('Olala!')                          #=> true
        #  new_key = key.copy('logs/today/888.log')   #=> #<RightAws::S3::Key:0xb7b5e240 ... >
        #  key.exists?                                #=> true
        #  new_key.exists?                            #=> true
        #
      def copy(new_key_or_name)
        new_key_or_name = Key.create(@bucket, new_key_or_name.to_s) unless new_key_or_name.is_a?(Key)
        @bucket.s3.interface.copy(@bucket.name, @name, new_key_or_name.bucket.name, new_key_or_name.name)
        new_key_or_name
      end

        # Move an object to other location. Returns a destination RightAws::S3::Key instance.
        #
        #  # Key instance as destination
        #  key1 = RightAws::S3::Key.create(bucket, 'logs/today/1.log') #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #  key2 = RightAws::S3::Key.create(bucket, 'logs/today/2.log') #=> #<RightAws::S3::Key:0xb7b5e240 ... >
        #  key1.put('Olala!')   #=> true
        #  key1.move(key2)      #=> #<RightAws::S3::Key:0xb7b5e240 ... >
        #  key1.exists?         #=> false
        #  key2.exists?         #=> true
        #  puts key2.data       #=> 'Olala!'
        #  
        #  # String as destination
        #  key = RightAws::S3::Key.create(bucket, 'logs/today/777.log') #=> #<RightAws::S3::Key:0xb7b1e240 ... >
        #  key.put('Olala!')                          #=> true
        #  new_key = key.move('logs/today/888.log')   #=> #<RightAws::S3::Key:0xb7b5e240 ... >
        #  key.exists?                                #=> false
        #  new_key.exists?                            #=> true
        #
      def move(new_key_or_name)
        new_key_or_name = Key.create(@bucket, new_key_or_name.to_s) unless new_key_or_name.is_a?(Key)
        @bucket.s3.interface.move(@bucket.name, @name, new_key_or_name.bucket.name, new_key_or_name.name)
        new_key_or_name
      end
      
        # Retrieve key info from bucket and update attributes.
        # Refresh meta-headers (by calling +head+ method) if +head+ is set. 
        # Returns +true+ if the key exists in bucket and +false+ otherwise. 
        #
        #  key = RightAws::S3::Key.create(bucket, 'logs/today/1.log')
        #  key.e_tag        #=> nil
        #  key.meta_headers #=> {}
        #  key.refresh      #=> true
        #  key.e_tag        #=> '12345678901234567890bf11094484b6'
        #  key.meta_headers #=> {"family"=>"qwerty", "name"=>"asdfg"}
        #
      def refresh(head=true)
        new_key        = @bucket.key(self)
        @last_modified = new_key.last_modified
        @e_tag         = new_key.e_tag
        @size          = new_key.size
        @storage_class = new_key.storage_class
        @owner         = new_key.owner
        if @last_modified
          self.head
          true
        else
          @headers = @meta_headers = {}
          false
        end
      end

        # Updates headers and meta-headers from S3.
        # Returns +true+. 
        #
        #  key.meta_headers #=> {"family"=>"qwerty"}
        #  key.head         #=> true
        #  key.meta_headers #=> {"family"=>"qwerty", "name"=>"asdfg"}
        #
      def head
        @headers, @meta_headers = self.class.split_meta(@bucket.s3.interface.head(@bucket, @name))
        true
      end
      
        # Reload meta-headers only. Returns meta-headers hash.
        #
        #  key.reload_meta   #=> {"family"=>"qwerty", "name"=>"asdfg"}
        #
      def reload_meta
        @meta_headers = self.class.split_meta(@bucket.s3.interface.head(@bucket, @name)).last
      end
      
        # Replace meta-headers by new hash at S3. Returns new meta-headers hash.
        #
        #  key.reload_meta   #=> {"family"=>"qwerty", "name"=>"asdfg"}
        #  key.save_meta     #=> {"family"=>"oops", "race" => "troll"}
        #  key.reload_meta   #=> {"family"=>"oops", "race" => "troll"}
        #
      def save_meta(meta_headers)
        meta = self.class.add_meta_prefix(meta_headers)
        @bucket.s3.interface.copy(@bucket.name, @name, @bucket.name, @name, :replace, meta)
        @meta_headers = self.class.split_meta(meta)[1]
      end
 
        # Check for existence of the key in the given bucket. 
        # Returns +true+ or +false+. 
        #
        #  key = RightAws::S3::Key.create(bucket,'logs/today/1.log')
        #  key.exists?        #=> false
        #  key.put('Woohoo!') #=> true
        #  key.exists?        #=> true
        #
      def exists?
        @bucket.key(self).last_modified ? true : false
      end
      
        # Remove key from bucket. 
        # Returns +true+. 
        #
        #  key.delete #=> true
        #
      def delete
        raise 'Key name must be specified.' if @name.right_blank?
        @bucket.s3.interface.delete(@bucket, @name) 
      end
      
        # Return a list of grantees. 
        #
      def grantees
        Grantee::grantees(self)
      end
      
    end
    

    class Owner
      attr_reader :id, :name
      
      def initialize(id, name)
        @id   = id
        @name = name
      end
      
        # Return Owner name as a +String+.
      def to_s
        @name
      end
    end
    
    
      # There are 2 ways to set permissions for a bucket or key (called a +thing+ below):
      #
      # 1 . Use +perms+ param to set 'Canned Access Policies' when calling the <tt>bucket.create</tt>, 
      # <tt>bucket.put</tt> and <tt>key.put</tt> methods. 
      # The +perms+ param can take these values: 'private', 'public-read', 'public-read-write' and
      # 'authenticated-read'. 
      # (see http://docs.amazonwebservices.com/AmazonS3/2006-03-01/RESTAccessPolicy.html).
      #
      #  bucket = s3.bucket('bucket_for_kd_test_13', true, 'public-read')
      #  key.put('Woohoo!','public-read-write' )
      #
      # 2 . Use Grantee instances (the permission is a +String+ or an +Array+ of: 'READ', 'WRITE', 
      # 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'):
      #
      #  bucket  = s3.bucket('my_awesome_bucket', true)
      #  grantee1 = RightAws::S3::Grantee.new(bucket, 'a123b...223c', FULL_CONTROL, :apply)
      #  grantee2 = RightAws::S3::Grantee.new(bucket, 'xy3v3...5fhp', [READ, WRITE], :apply)
      #
      # There is only one way to get and to remove permission (via Grantee instances):
      #
      #  grantees = bucket.grantees # a list of Grantees that have any access for this bucket
      #  grantee1 = RightAws::S3::Grantee.new(bucket, 'a123b...223c')
      #  grantee1.perms #=> returns a list of perms for this grantee to that bucket
      #    ...
      #  grantee1.drop             # remove all perms for this grantee
      #  grantee2.revoke('WRITE')  # revoke write access only
      #
    class Grantee
        # A bucket or a key the grantee has an access to.
      attr_reader :thing
        # Grantee Amazon id.
      attr_reader :id
        # Grantee display name.
      attr_reader :name
        # Array of permissions.
      attr_accessor :perms
        
        # Retrieve Owner information and a list of Grantee instances that have
        # a access to this thing (bucket or key). 
        #
        #  bucket = s3.bucket('my_awesome_bucket', true, 'public-read')
        #   ...
        #  RightAws::S3::Grantee.owner_and_grantees(bucket) #=> [owner, grantees]
        #
      def self.owner_and_grantees(thing)
        if thing.is_a?(Bucket)
          bucket, key = thing, ''
        else
          bucket, key = thing.bucket, thing
        end
        hash = bucket.s3.interface.get_acl_parse(bucket.to_s, key.to_s)
        owner = Owner.new(hash[:owner][:id], hash[:owner][:display_name])
        
        grantees = []
        hash[:grantees].each do |id, params|
          grantees << new(thing, id, params[:permissions], nil, params[:display_name])
        end
        [owner, grantees]
      end

        # Retrieves a list of Grantees instances that have an access to this thing(bucket or key). 
        #
        #  bucket = s3.bucket('my_awesome_bucket', true, 'public-read')
        #   ...
        #  RightAws::S3::Grantee.grantees(bucket) #=> grantees
        #
      def self.grantees(thing)
        owner_and_grantees(thing)[1]
      end

      def self.put_acl(thing, owner, grantees) #:nodoc:
        if thing.is_a?(Bucket)
          bucket, key = thing, ''
        else
          bucket, key = thing.bucket, thing
        end
        body = "<AccessControlPolicy>" +
               "<Owner>" +
               "<ID>#{owner.id}</ID>" +
               "<DisplayName>#{owner.name}</DisplayName>" +
               "</Owner>" +
               "<AccessControlList>" +
               grantees.map{|grantee| grantee.to_xml}.join +
               "</AccessControlList>" +
               "</AccessControlPolicy>"
        bucket.s3.interface.put_acl(bucket.to_s, key.to_s, body)
      end

        # Create a new Grantee instance. 
        # Grantee +id+ must exist on S3. If +action+ == :refresh, then retrieve
        # permissions from S3 and update @perms. If +action+ == :apply, then apply
        # perms to +thing+ at S3. If +action+ == :apply_and_refresh then it performs.
        # both the actions. This is used for the new grantees that had no perms to 
        # this thing before. The default action is :refresh.
        #
        #  bucket = s3.bucket('my_awesome_bucket', true, 'public-read')
        #  grantee1 = RightAws::S3::Grantee.new(bucket, 'a123b...223c', FULL_CONTROL)
        #    ...
        #  grantee2 = RightAws::S3::Grantee.new(bucket, 'abcde...asdf', [FULL_CONTROL, READ], :apply)
        #  grantee3 = RightAws::S3::Grantee.new(bucket, 'aaaaa...aaaa', 'READ', :apply_and_refresh)  
        #
      def initialize(thing, id, perms=[], action=:refresh, name=nil)
        @thing = thing
        @id    = id
        @name  = name
        @perms = Array(perms)
        case action
          when :apply             then apply
          when :refresh           then refresh
          when :apply_and_refresh then apply; refresh
        end
      end
      
        # Return +true+ if the grantee has any permissions to the thing.
      def exists?
        self.class.grantees(@thing).each do |grantee|
          return true if @id == grantee.id
        end
        false
      end
      
        # Return Grantee type (+String+): "Group", "AmazonCustomerByEmail" or "CanonicalUser".
      def type
        case @id
        when /^http:/ then "Group"
        when /@/      then "AmazonCustomerByEmail"
        else               "CanonicalUser"
        end
      end
 
        # Return a name or an id.
      def to_s
        @name || @id
      end
      
        # Add permissions for grantee. 
        # Permissions: 'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'. 
        # See http://docs.amazonwebservices.com/AmazonS3/2006-03-01/UsingPermissions.html .
        # Returns +true+. 
        #
        #  grantee.grant('FULL_CONTROL')                  #=> true
        #  grantee.grant('FULL_CONTROL','WRITE','READ')   #=> true
        #  grantee.grant(['WRITE_ACP','READ','READ_ACP']) #=> true
        #  
      def grant(*permissions)
        permissions.flatten!
        old_perms = @perms.dup
        @perms   += permissions
        @perms.uniq!
        return true if @perms == old_perms
        apply
      end
      
        # Revoke permissions for grantee. 
        # Permissions: 'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'
        # See http://docs.amazonwebservices.com/AmazonS3/2006-03-01/UsingPermissions.html .
        # Default value is 'FULL_CONTROL'. 
        # Returns +true+.
        #
        #  grantee.revoke('READ')                   #=> true
        #  grantee.revoke('FULL_CONTROL','WRITE')   #=> true
        #  grantee.revoke(['READ_ACP','WRITE_ACP']) #=> true
        #
      def revoke(*permissions)
        permissions.flatten!
        old_perms = @perms.dup
        @perms   -= permissions
        @perms.uniq!
        return true if @perms == old_perms
        apply
      end
     
        # Revoke all permissions for this grantee. 
        # Returns +true+.
        #
        #  grantee.drop #=> true
        #
      def drop
        @perms = []
        apply
      end
         
        # Refresh grantee perms for its +thing+.
        # Returns +true+ if the grantee has perms for this +thing+ or
        # +false+ otherwise, and updates @perms value as a side-effect.
        #
        #  grantee.grant('FULL_CONTROL') #=> true
        #  grantee.refresh               #=> true
        #  grantee.drop                  #=> true
        #  grantee.refresh               #=> false
        #
      def refresh
        @perms = []
        self.class.grantees(@thing).each do |grantee|
          if @id == grantee.id
            @name  = grantee.name
            @perms = grantee.perms
            return true
          end
        end
        false
      end

        # Apply current grantee @perms to +thing+. This method is called internally by the +grant+
        # and +revoke+ methods. In normal use this method should not
        # be called directly.
        # 
        #  grantee.perms = ['FULL_CONTROL']
        #  grantee.apply #=> true
        #
      def apply
        @perms.uniq!
        owner, grantees = self.class.owner_and_grantees(@thing)
        # walk through all the grantees and replace the data for the current one and ...
        grantees.map! { |grantee| grantee.id == @id ? self : grantee }
        # ... if this grantee is not known - add this bad boy to a list
        grantees << self unless grantees.include?(self)
        # set permissions
        self.class.put_acl(@thing, owner, grantees)
      end

      def to_xml   # :nodoc:
        id_str = case @id
                 when /^http/ then "<URI>#{@id}</URI>"
                 when /@/     then "<EmailAddress>#{@id}</EmailAddress>"
                 else              "<ID>#{@id}</ID>"
                 end
        grants = ''
        @perms.each do |perm|
          grants << "<Grant>"    +
                    "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
                      "xsi:type=\"#{type}\">#{id_str}</Grantee>" +
                    "<Permission>#{perm}</Permission>" +
                    "</Grant>"
        end
        grants
      end

    end
    
  end

    # RightAws::S3Generator and RightAws::S3Generator::Bucket methods:
    #
    #  s3g = RightAws::S3Generator.new('1...2', 'nx...Y6') #=> #<RightAws::S3Generator:0xb7b5cc94>
    #
    #    # List all buckets(method 'GET'):
    #  buckets_list = s3g.buckets #=> 'https://s3.amazonaws.com:443/?Signature=Y...D&Expires=1180941864&AWSAccessKeyId=1...2'
    #    # Create bucket link (method 'PUT'):
    #  bucket = s3g.bucket('my_awesome_bucket')     #=> #<RightAws::S3Generator::Bucket:0xb7bcbda8>
    #  link_to_create = bucket.create_link(1.hour)  #=> https://s3.amazonaws.com:443/my_awesome_bucket?Signature=4...D&Expires=1180942132&AWSAccessKeyId=1...2
    #    # ... or:
    #  bucket = RightAws::S3Generator::Bucket.create(s3g, 'my_awesome_bucket') #=> #<RightAws::S3Generator::Bucket:0xb7bcbda8>
    #  link_to_create = bucket.create_link(1.hour)                                 #=> https://s3.amazonaws.com:443/my_awesome_bucket?Signature=4...D&Expires=1180942132&AWSAccessKeyId=1...2
    #    # ... or:
    #  bucket = RightAws::S3Generator::Bucket.new(s3g, 'my_awesome_bucket') #=> #<RightAws::S3Generator::Bucket:0xb7bcbda8>
    #  link_to_create = bucket.create_link(1.hour)                              #=> https://s3.amazonaws.com:443/my_awesome_bucket?Signature=4...D&Expires=1180942132&AWSAccessKeyId=1...2
    #    # List bucket(method 'GET'):
    #  bucket.keys(1.day) #=> https://s3.amazonaws.com:443/my_awesome_bucket?Signature=i...D&Expires=1180942620&AWSAccessKeyId=1...2
    #    # Create/put key (method 'PUT'):
    #  bucket.put('my_cool_key') #=> https://s3.amazonaws.com:443/my_awesome_bucket/my_cool_key?Signature=q...D&Expires=1180943094&AWSAccessKeyId=1...2
    #    # Get key data (method 'GET'):
    #  bucket.get('logs/today/1.log', 1.hour) #=> https://s3.amazonaws.com:443/my_awesome_bucket/my_cool_key?Signature=h...M%3D&Expires=1180820032&AWSAccessKeyId=1...2
    #    # Delete bucket (method 'DELETE'): 
    #  bucket.delete(2.hour) #=> https://s3.amazonaws.com:443/my_awesome_bucket/logs%2Ftoday%2F1.log?Signature=4...D&Expires=1180820032&AWSAccessKeyId=1...2
    #  
    # RightAws::S3Generator::Key methods:
    #
    #    # Create Key instance:  
    #  key = RightAws::S3Generator::Key.new(bicket, 'my_cool_key') #=> #<RightAws::S3Generator::Key:0xb7b7394c>
    #    # Put key data (method 'PUT'):
    #  key.put    #=> https://s3.amazonaws.com:443/my_awesome_bucket/my_cool_key?Signature=2...D&Expires=1180943302&AWSAccessKeyId=1...2
    #    # Get key data (method 'GET'):
    #  key.get    #=> https://s3.amazonaws.com:443/my_awesome_bucket/my_cool_key?Signature=a...D&Expires=1180820032&AWSAccessKeyId=1...2
    #    # Head key (method 'HEAD'):
    #  key.head   #=> https://s3.amazonaws.com:443/my_awesome_bucket/my_cool_key?Signature=b...D&Expires=1180820032&AWSAccessKeyId=1...2
    #    # Delete key (method 'DELETE'):
    #  key.delete #=> https://s3.amazonaws.com:443/my_awesome_bucket/my_cool_key?Signature=x...D&Expires=1180820032&AWSAccessKeyId=1...2
    #
  class S3Generator
    attr_reader :interface
    
    def initialize(aws_access_key_id, aws_secret_access_key, params={})
      @interface = S3Interface.new(aws_access_key_id, aws_secret_access_key, params)
    end
    
      # Generate link to list all buckets
      #
      #  s3.buckets(1.hour)
      #
    def buckets(expires=nil, headers={})
      @interface.list_all_my_buckets_link(expires, headers)
    end

      # Create new S3LinkBucket instance and generate link to create it at S3.
      #
      #  bucket= s3.bucket('my_owesome_bucket')
      #
    def bucket(name, expires=nil, headers={})
      Bucket.create(self, name.to_s)
    end
  
    class Bucket
      attr_reader :s3, :name
      
      def to_s
        @name
      end
      alias_method :full_name, :to_s
        
        # Return a public link to bucket.
        # 
        #  bucket.public_link #=> 'https://s3.amazonaws.com:443/my_awesome_bucket'
        #
      def public_link
        params = @s3.interface.params
        "#{params[:protocol]}://#{params[:server]}:#{params[:port]}/#{full_name}"
      end
      
        #  Create new S3LinkBucket instance and generate creation link for it. 
      def self.create(s3, name, expires=nil, headers={})
        new(s3, name.to_s)
      end
        
        #  Create new S3LinkBucket instance. 
      def initialize(s3, name)
        @s3, @name = s3, name.to_s
      end
        
        # Return a link to create this bucket. 
        #
      def create_link(expires=nil, headers={})
        @s3.interface.create_bucket_link(@name, expires, headers)
      end

        # Generate link to list keys. 
        #
        #  bucket.keys
        #  bucket.keys('prefix'=>'logs')
        #
      def keys(options=nil, expires=nil, headers={})
        @s3.interface.list_bucket_link(@name, options, expires, headers)
      end

        # Return a S3Generator::Key instance.
        #
        #  bucket.key('my_cool_key').get    #=> https://s3.amazonaws.com:443/my_awesome_bucket/my_cool_key?Signature=B...D&Expires=1180820032&AWSAccessKeyId=1...2
        #  bucket.key('my_cool_key').delete #=> https://s3.amazonaws.com:443/my_awesome_bucket/my_cool_key?Signature=B...D&Expires=1180820098&AWSAccessKeyId=1...2
        #
      def key(name)
        Key.new(self, name)
      end

        # Generates link to PUT key data. 
        #
        #  puts bucket.put('logs/today/1.log', 2.hour)
        #
      def put(key, meta_headers={}, expires=nil, headers={})
        meta = RightAws::S3::Key.add_meta_prefix(meta_headers)
        @s3.interface.put_link(@name, key.to_s, nil, expires, meta.merge(headers))
      end
        
        # Generate link to GET key data. 
        #
        #  bucket.get('logs/today/1.log', 1.hour)
        #
      def get(key, expires=nil, headers={}, response_params={})
        @s3.interface.get_link(@name, key.to_s, expires, headers, response_params)
      end
       
        # Generate link to delete bucket. 
        #
        #  bucket.delete(2.hour)
        #
      def delete(expires=nil,  headers={})
        @s3.interface.delete_bucket_link(@name, expires,  headers)
      end
    end


    class Key
      attr_reader :bucket, :name
      
      def to_s
        @name
      end
      
        # Return a full S# name (bucket/key).
        # 
        #  key.full_name #=> 'my_awesome_bucket/cool_key'
        #
      def full_name(separator='/')
        "#{@bucket.to_s}#{separator}#{@name}"
      end
        
        # Return a public link to key.
        # 
        #  key.public_link #=> 'https://s3.amazonaws.com:443/my_awesome_bucket/cool_key'
        #
      def public_link
        params = @bucket.s3.interface.params
        "#{params[:protocol]}://#{params[:server]}:#{params[:port]}/#{full_name('/')}"
      end
      
      def initialize(bucket, name, meta_headers={})
        @bucket       = bucket
        @name         = name.to_s
        @meta_headers = meta_headers
        raise 'Key name can not be empty.' if @name.right_blank?
      end
      
        # Generate link to PUT key data. 
        #
        #  puts bucket.put('logs/today/1.log', '123', 2.hour) #=> https://s3.amazonaws.com:443/my_awesome_bucket/logs%2Ftoday%2F1.log?Signature=B...D&Expires=1180820032&AWSAccessKeyId=1...2
        #
      def put(expires=nil, headers={})
        @bucket.put(@name.to_s, @meta_headers, expires, headers)
      end
        
        # Generate link to GET key data. 
        #
        #  bucket.get('logs/today/1.log', 1.hour) #=> https://s3.amazonaws.com:443/my_awesome_bucket/logs%2Ftoday%2F1.log?Signature=h...M%3D&Expires=1180820032&AWSAccessKeyId=1...2
        #
      def get(expires=nil, headers={}, response_params={})
        @bucket.s3.interface.get_link(@bucket.to_s, @name, expires, headers, response_params)
      end
       
        # Generate link to delete key. 
        #
        #  bucket.delete(2.hour) #=> https://s3.amazonaws.com:443/my_awesome_bucket/logs%2Ftoday%2F1.log?Signature=4...D&Expires=1180820032&AWSAccessKeyId=1...2
        #
      def delete(expires=nil,  headers={})
        @bucket.s3.interface.delete_link(@bucket.to_s, @name, expires,  headers)
      end
      
        # Generate link to head key. 
        #
        #  bucket.head(2.hour) #=> https://s3.amazonaws.com:443/my_awesome_bucket/logs%2Ftoday%2F1.log?Signature=4...D&Expires=1180820032&AWSAccessKeyId=1...2
        #
      def head(expires=nil,  headers={})
        @bucket.s3.interface.head_link(@bucket.to_s, @name, expires,  headers)
      end
    end
  end

end
