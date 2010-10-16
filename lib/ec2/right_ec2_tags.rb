#
# Copyright (c) 2007-2009 RightScale Inc
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
  class Ec2

    #-----------------------------------------------------------------
    #      Tags
    #-----------------------------------------------------------------

    # Describe tags.
    #
    #  ec2.describe_tags  #=> [{:resource_id=>"i-12345678",
    #                           :value=>"foo",
    #                           :resource_type=>"instance",
    #                           :key=>"myKey"}]
    #
    def describe_tags
      link = generate_request("DescribeTags")
      request_cache_or_info :describe_tags, link,  QEc2DescribeTagsParser, @@bench
    rescue Exception
      on_exception
    end

    # Create tags.
    #
    # Add a single tag with no value to a resource:
    # ec2.create_tags("i-12345678", "myKey") => true
    #
    # Add multiple keys and values to a resource:
    # ec2.create_tags("i-12345678", [{"myKey1" => "foo",
    #                                 "myKey2" => "bar",
    #                                 "myKeyWithoutVal" => nil
    #                                 }]) #=> true
    #
    # Add a key and value to multiple resources:
    # ec2.create_tags(["i-12345678","i-86fb3eec","i-86fb3eed"],
    #                 {"myKey" => "foo"}) #=> true
    #
    def create_tags(resources, tags)
      params = amazonize_list("ResourceId", resources)
      params.merge! amazonize_tags(tags)
      link = generate_request("CreateTags", params)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Delete tags.
    #
    # Delete a  tag from a resource regardless of value:
    # ec2.delete_tags("i-12345678", "myKey") => true
    #
    # Delete multiple keys and values to a resource:
    # ec2.delete_tags("i-12345678", [{"myKey1" => "foo",
    #                                 "myKey2" => "bar",
    #                                 "myKeyForAnyVal" => nil
    #                                 }]) #=> true
    #
    # Delete a key and value on multiple resources:
    # ec2.delete_tags(["i-12345678","i-a1234567","i-b1234567"],
    #                 {"myKey" => "foo"}) #=> true
    #

    def delete_tags(resources, tags)
      params = amazonize_list("ResourceId", resources)
      params.merge! amazonize_tags(tags, false)
      link = generate_request("DeleteTags", params)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    def amazonize_tags(tags,require_value=true) # :nodoc:
      # NB: CreateTags requires Tag.n.Value, DeleteTags does not.
      result = {}
      Array(tags).each_with_index do |ary, idx|
        key, value = ary
        result["Tag.#{idx+1}.Key"]   = key
        result["Tag.#{idx+1}.Value"] = value.to_s if value || require_value
      end
      result
    end


    #-----------------------------------------------------------------
    #      PARSERS: Tags
    #-----------------------------------------------------------------

    class QEc2DescribeTagsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @resource_tag = {} if name == 'item'
      end

      def tagend(name)
        case name
        when 'resourceId'   then @resource_tag[:resource_id]   = @text
        when 'resourceType' then @resource_tag[:resource_type] = @text
        when 'key'          then @resource_tag[:key]           = @text
        when 'value'        then @resource_tag[:value]         = @text
        when 'item'         then  @result                     << @resource_tag
        end
      end

      def reset
        @result = []
      end
    end

  end

end
