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
 
    # Exception class to handle any Amazon errors
    # Attributes:
    #  message    - the text of error
    #  errors     - a list of errors as array or a string(==message if raised manually as AwsError.new('err_text'))
    #  request_id - amazon's request id (if exists)
    #  http_code  - HTTP response error code (if exists)
  class AwsError < RuntimeError
    attr_reader :errors       # Array of errors list(each item is an array - [code,message]) or error string
    attr_reader :request_id   # Request id (if exists)
    attr_reader :http_code    # Response HTTP error code
    def initialize(errors=nil, http_code=nil, request_id=nil)
      @errors      = errors
      @request_id  = request_id
      @http_code   = http_code
      super(@errors.is_a?(Array) ? @errors.map{|code, msg| "#{code}: #{msg}"}.join("; ") : @errors.to_s)
    end
    def include?(pattern)
      if @errors.is_a?(Array)
        @errors.each{ |code, msg| return true if code =~ pattern } 
      else
        return true if @errors_str =~ pattern 
      end
      false
    end
    
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
          REXML::Document.parse_stream(response.body, error_parser)
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

  class RightAWSParser #:nodoc:
    attr_accessor :result
    attr_reader   :xmlpath
    def initialize
      @xmlpath = ''
      @result  = false
      @text    = ''
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
