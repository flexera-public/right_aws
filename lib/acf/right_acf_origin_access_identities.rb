#
# Copyright (c) 2010 RightScale Inc
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
  
  class AcfInterface

    # List Origin Access Identities.
    #
    #  acf.list_origin_access_identities #=>
    #    [{:comment=>"kd: TEST",
    #      :s3_canonical_user_id=>
    #       "c7ca36f6c5d384e60aeca02032ac748bae3c458c5322a2e279382935f1f71b16d9ac251f7f71f1ea91c37d3c214645b8",
    #      :aws_id=>"E3TL4XWF5KTGH"},
    #     {:comment=>"kd: TEST-2",
    #      :s3_canonical_user_id=>
    #       "9af7058b1d197c2c03fdcc3ddad07012a7822f5fc4a8156025409ffac646bdae4dc714820482c92e6988e5703c8d9954",
    #      :aws_id=>"E3HJ7V8C3324VF"},
    #     {:comment=>"MyTestAccessIdentity",
    #      :s3_canonical_user_id=>
    #       "de4361b33dbaf499d3d77159bfa1571d3451eaec25a2b16553de5e534da8089bb8c31a4898d73d1a658155d0e48872a7",
    #      :aws_id=>"E3JPJZ80ZBX24G"}]
    #
    def list_origin_access_identities
      result = []
      incrementally_list_origin_access_identities do |response|
        result += response[:origin_access_identities]
        true
      end
      result
    end

    # Incrementally list Origin Access Identities.
    # Optional params: +:marker+ and +:max_items+.
    #
    #  acf.incrementally_list_origin_access_identities(:max_items => 2) #=>
    #    {:origin_access_identities=>
    #      [{:comment=>"kd: TEST",
    #        :s3_canonical_user_id=>
    #         "c7ca36f6c5d384e60aeca02032ac748bae3c458c5322a2e279382935f1f71b16d9ac251f7f71f1ea91c37d3c214645b8",
    #        :aws_id=>"E3TL4XWF5KTGH"},
    #       {:comment=>"kd: TEST-2",
    #        :s3_canonical_user_id=>
    #         "9af7058b1d197c2c03fdcc3ddad07012a7822f5fc4a8156025409ffac646bdae4dc714820482c92e6988e5703c8d9954",
    #        :aws_id=>"E3HJ7V8C3324VF"}],
    #     :is_truncated=>true,
    #     :max_items=>2,
    #     :marker=>"",
    #     :next_marker=>"E3HJ7V8C3324VF"}
    #
    #   # get max 100 origin access identities (the list will be restricted by a default MaxItems value ==100 )
    #   incrementally_list_origin_access_identities
    #
    #   # list origin access identities by 10
    #   acf.incrementally_list_origin_access_identities(:max_items => 10) do |response|
    #     puts response.inspect # a list of 10 distributions
    #     true # return false if the listing should be broken otherwise use true
    #   end
    #
    def incrementally_list_origin_access_identities(params={}, &block)
      opts = {}
      opts['MaxItems'] = params[:max_items] if params[:max_items]
      opts['Marker']   = params[:marker]    if params[:marker]
      last_response = nil
      loop do
        link = generate_request('GET', 'origin-access-identity/cloudfront', opts)
        last_response = request_info(link,  AcfOriginAccesIdentitiesListParser.new(:logger => @logger))
        opts['Marker'] = last_response[:next_marker]
        break unless block && block.call(last_response) && !last_response[:next_marker].blank?
      end
      last_response
    end

    #-----------------------------------------------------------------
    #      Origin Access Identity
    #-----------------------------------------------------------------

    # Create a new CloudFront Origin Access Identity.
    #
    #  acf.create_origin_access_identity('MyTestAccessIdentity') #=>
    #    {:e_tag=>"E2QOKZEXCUWHJX",
    #     :comment=>"MyTestAccessIdentity",
    #     :location=>
    #       "https://cloudfront.amazonaws.com/origin-access-identity/cloudfront/E3JPJZ80ZBX24G",
    #     :caller_reference=>"201004161657467493031273",
    #     :s3_canonical_user_id=>
    #       "de4361b33dbaf499d3d77159bfa1571d3451eaec25a2b16553de5e534da8089bb8c31a4898d73d1a658155d0e48872a7",
    #     :aws_id=>"E3JPJZ80ZBX24G"}
    #
    def create_origin_access_identity(comment='', caller_reference=nil)
      config = { :comment          => comment,
                 :caller_reference => caller_reference }
      create_origin_access_identity_by_config(config)
    end

    def create_origin_access_identity_by_config(config)
      config[:caller_reference] ||= generate_call_reference
      link = generate_request('POST', 'origin-access-identity/cloudfront', {}, origin_access_identity_config_to_xml(config))
      merge_headers(request_info(link, AcfOriginAccesIdentitiesListParser.new(:logger => @logger))[:origin_access_identities].first)
    end

    # Get Origin Access Identity
    #
    #  acf.get_origin_access_identity('E3HJ7V8C3324VF') #=>
    #    {:comment=>"kd: TEST-2",
    #     :caller_reference=>"201004161655035372351604",
    #     :aws_id=>"E3HJ7V8C3324VF",
    #     :s3_canonical_user_id=>
    #      "9af7058b1d197c2c03fdcc3ddad07012a7822f5fc4a8156025409ffac646bdae4dc714820482c92e6988e5703c8d9954",
    #     :e_tag=>"E309Q4IM450498"}
    #
    def get_origin_access_identity(aws_id)
      link = generate_request('GET', "origin-access-identity/cloudfront/#{aws_id}")
      merge_headers(request_info(link, AcfOriginAccesIdentitiesListParser.new(:logger => @logger))[:origin_access_identities].first)
    end

    # Get Origin Access Identity
    #
    #  acf.get_origin_access_identity('E3HJ7V8C3324VF') #=>
    #    {:comment=>"kd: TEST-2",
    #     :caller_reference=>"201004161655035372351604",
    #     :aws_id=>"E3HJ7V8C3324VF",
    #     :s3_canonical_user_id=>
    #      "9af7058b1d197c2c03fdcc3ddad07012a7822f5fc4a8156025409ffac646bdae4dc714820482c92e6988e5703c8d9954",
    #     :e_tag=>"E309Q4IM450498"}
    #
    #  acf.delete_origin_access_identity("E3HJ7V8C3324VF","E309Q4IM450498") #=> true
    #
    def delete_origin_access_identity(aws_id, e_tag)
      link = generate_request('DELETE', "origin-access-identity/cloudfront/#{aws_id}", {}, nil,
                                        'If-Match' => e_tag)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Config
    #-----------------------------------------------------------------

    def origin_access_identity_config_to_xml(config) # :nodoc:
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
      "<CloudFrontOriginAccessIdentityConfig xmlns=\"http://#{@params[:server]}/doc/#{API_VERSION}/\">\n" +
      "  <CallerReference>#{config[:caller_reference]}</CallerReference>\n" +
      "  <Comment>#{AcfInterface::escape(config[:comment].to_s)}</Comment>\n" +
      "</CloudFrontOriginAccessIdentityConfig>"
    end

    # Get Origin Access Identity config
    #
    #  acf.get_origin_access_identity_config("E3JPJZ80ZBX24G") #=>
    #    {:comment=>"MyTestAccessIdentity",
    #     :caller_reference=>"201004161657467493031273",
    #     :e_tag=>"E2QOKZEXCUWHJX"}
    #
    def get_origin_access_identity_config(aws_id)
      link = generate_request('GET', "origin-access-identity/cloudfront/#{aws_id}/config")
      merge_headers(request_info(link, AcfOriginAccesIdentitiesListParser.new(:logger => @logger))[:origin_access_identities].first)
    end

    # Set Origin Access Identity config
    #
    #
    #  acf.set_origin_access_identity_config("E2QOKZEXCUWHJX",
    #                                        :comment => "MyBestOriginAccessConfig",
    #                                        :caller_reference => '01234567890',
    #                                        :e_tag=>"E2QOKZEXCUWHJX") #=> true
    #                                        
    # P.S. This guy is not tested yet: http://developer.amazonwebservices.com/connect/thread.jspa?threadID=45256
    def set_origin_access_identity_config(aws_id, config)
      link = generate_request('PUT', "origin-access-identity/cloudfront/#{aws_id}/config", {}, origin_access_identity_config_to_xml(config),
                                     'If-Match' => config[:e_tag])
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS:
    #-----------------------------------------------------------------

    class AcfOriginAccesIdentitiesListParser < RightAWSParser # :nodoc:
      def reset
        @result = { :origin_access_identities => [] }
      end
      def tagstart(name, attributes)
        case full_tag_name
        when %r{CloudFrontOriginAccessIdentitySummary$},
             %r{^CloudFrontOriginAccessIdentity$},
             %r{^CloudFrontOriginAccessIdentityConfig$}
          @item = {}
        end
      end
      def tagend(name)
        case name
        when 'Marker'            then @result[:marker]       = @text
        when 'NextMarker'        then @result[:next_marker]  = @text
        when 'MaxItems'          then @result[:max_items]    = @text.to_i
        when 'IsTruncated'       then @result[:is_truncated] = (@text == 'true')
        when 'Id'                then @item[:aws_id]               = @text
        when 'S3CanonicalUserId' then @item[:s3_canonical_user_id] = @text
        when 'CallerReference'   then @item[:caller_reference] = @text
        when 'Comment'           then @item[:comment]              = AcfInterface::unescape(@text)
        end
        case full_tag_name
        when %r{CloudFrontOriginAccessIdentitySummary$},
             %r{^CloudFrontOriginAccessIdentity$},
             %r{^CloudFrontOriginAccessIdentityConfig$}
          @result[:origin_access_identities] << @item
        end
      end
    end

  end
end