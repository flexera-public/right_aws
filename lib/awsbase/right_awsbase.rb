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

# Test
module RightAws

  class AwsUtils
    def self.sign(aws_secret_access_key, auth_string)
      Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new("sha1"), aws_secret_access_key, auth_string)).strip
    end

  end

  class AwsBenchmarkingBlock
    attr_accessor :xml, :service
    def initialize
      # Benchmark::Tms instance for service (Ec2, S3, or SQS) access benchmarking.
      @service = Benchmark::Tms.new()
      # Benchmark::Tms instance for XML parsing benchmarking.
      @xml = Benchmark::Tms.new()
    end
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

  end

  module RightAwsBaseInterface

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

    def init(service_info, aws_access_key_id, aws_secret_access_key, params={})
      @params = params
      raise AwsError.new("AWS access keys are required to operate on #{service_info[:name]}") \
        if aws_access_key_id.blank? || aws_secret_access_key.blank?
      @aws_access_key_id     = aws_access_key_id
      @aws_secret_access_key = aws_secret_access_key
      @params[:server]       ||= service_info[:default_host]
      @params[:port]         ||= service_info[:default_port]
      @params[:protocol]     ||= service_info[:default_protocol]
      @params[:multi_thread] ||= defined?(AWS_DAEMON)
      @logger = @params[:logger]
      @logger = RAILS_DEFAULT_LOGGER if !@logger && defined?(RAILS_DEFAULT_LOGGER)
      @logger = Logger.new(STDOUT)   if !@logger
      @logger.info "New #{self.class.name} using #{@params[:multi_thread] ? 'multi' : 'single'}-threaded mode"
      @error_handler = nil
    end

    def on_exception(options={:raise=>true, :log=>true}) # :nodoc:
      AwsError::on_aws_exception(self, options)
    end
    
      # Return +true+ if this instance works in multi_thread mode and +false+ otherwise.
    def multi_thread
      @params[:multi_thread]
    end

    def request_info_impl(connection, benchblock, request, parser, &block)
      @last_request  = request[:request]
      @last_response = nil
      response=nil
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
          responsehdr = connection.request(request) do |response|
          #########
            begin
              @last_response = response
              if response.is_a?(Net::HTTPSuccess)
                @error_handler = nil
                response.read_body(&block)
              else
                @error_handler = AWSErrorHandler.new(self, parser, self.class.amazon_problems) unless @error_handler
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
        benchblock.service.add!{ response = connection.request(request) }
          # check response for errors...
        @last_response = response
        if response.is_a?(Net::HTTPSuccess)
          @error_handler = nil
          benchblock.xml.add! { parser.parse(response) }
          return parser.result
        else
          @error_handler = AWSErrorHandler.new(self, parser, self.class.amazon_problems) unless @error_handler
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
    
    def initialize(aws, parser,  errors_list=nil,  reiteration_time=nil) #:nodoc:
      @aws           = aws              # Link to RightEc2 | RightSqs | RightS3 instance
      @parser        = parser           # parser to parse Amazon response
      @started_at    = Time.now
      @stop_at       = @started_at  + (reiteration_time || @@reiteration_time)
      @errors_list   = errors_list || []
      @reiteration_delay = @@reiteration_start_delay
      @retries       = 0
    end
    
      # Returns false if 
    def check(request)  #:nodoc:
      result           = false
      error_found      = false
      last_errors_text = ''
      response         = @aws.last_response
        # log error
      request_text_data = "#{request[:server]}:#{request[:port]}#{request[:request].path}"
      @aws.logger.warn("##### #{@aws.class.name} returned an error: #{response.code} #{response.message}\n#{response.body} #####")
      @aws.logger.warn("##### #{@aws.class.name} request: #{request_text_data} ####")
        # Check response body: if it is an Amazon XML document or not:
      if response.body && response.body[/<\?xml/]         # ... it is a xml document
        @aws.class.bench_xml.add! do
          error_parser = RightErrorResponseParser.new
          error_parser.parse(response)
          @aws.last_errors     = error_parser.errors
          @aws.last_request_id = error_parser.requestID
          last_errors_text     = @aws.last_errors.flatten.join("\n")
        end
      else                               # ... it is not a xml document(probably just a html page?)
        @aws.last_errors     = [[response.code, "#{response.message} (#{request_text_data})"]]
        @aws.last_request_id = '-undefined-'
        last_errors_text     = response.message
      end
        # now - check the error
      @errors_list.each do |error_to_find|
        if last_errors_text[/#{error_to_find}/i]
          error_found = true
          @aws.logger.warn("##### Retry is needed, error pattern match: #{error_to_find} #####")
          break
        end
      end
        # check the time has gone from the first error come
      if error_found
        if (Time.now < @stop_at)
          @retries += 1
          @aws.logger.warn("##### Retry ##{@retries} is being performed. Sleeping for #{@reiteration_delay} sec. Whole time: #{Time.now-@started_at} sec ####")
          sleep @reiteration_delay
          
          @reiteration_delay *= 2
          result = @aws.request_info(request, @parser)
        else
          @aws.logger.warn("##### Ooops, time is over... ####")
        end
      end
      result
    end
    
  end


  #-----------------------------------------------------------------

  class RightAWSParser  #:nodoc:
    @@xml_lib = 'rexml' # xml library name: 'rexml' | 'libxml'
    def self.xml_lib
      @@xml_lib
    end
    def self.xml_lib=(new_lib_name)
      @@xml_lib = new_lib_name
    end
    
    attr_accessor :result
    attr_reader   :xmlpath
    attr_accessor :xml_lib
    
    def initialize(params={})
      @xmlpath = ''
      @result  = false
      @text    = ''
      @xml_lib = params[:xml_lib] || @@xml_lib
      @logger  = params[:logger]
      reset
    end
    def tag_start(name, attributes)
      @text = ''
      tagstart(name, attributes)
      @xmlpath += @xmlpath.empty? ? name : "/#{name}"
    end
    def tag_end(name)
      @xmlpath[/^(.*?)\/?#{name}$/]
      @xmlpath = $1
      tagend(name)
    end
    def text(text)
      @text = text
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
        # load xml library
      if @xml_lib=='libxml' && !defined?(XML::SaxParser)
        begin
          require 'xml/libxml' 
        rescue LoadError => e
          @xml_lib = 'rexml'
          if @logger
            @logger.error e.inspect
            @logger.error e.backtrace
            @logger.info "Can not load 'libxml' library. 'Rexml' is used for parsing."
          end
        end
      end
        # Parse the xml text
      case @xml_lib
      when 'libxml'  
        xml = XML::SaxParser.new
        xml.string = xml_text
        xml.on_start_element{|name, attr_hash| self.tag_start(name, attr_hash)}
        xml.on_characters{   |text|            self.text(text)}
        xml.on_end_element{  |name|            self.tag_end(name)}
        xml.parse
      else
        if @logger && @xml_lib!='rexml'
          @logger.info "RightAWSParser#parse: Unknown xml library ('#{@xml_lib}') is selected. The default 'rexml' is used."
        end
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

  class RightErrorResponseParser < RightAWSParser #:nodoc:
    attr_accessor :errors  # array of hashes: error/message
    attr_accessor :requestID
    def tagend(name)
      case name
        when 'RequestID' ; @requestID = @text
        when 'Code'      ; @code      = @text
        when 'Message'   ; @message   = @text
        when 'Error'     ; @errors   << [ @code, @message ]
      end
    end
    def reset
      @errors = []
    end
  end
  
end
