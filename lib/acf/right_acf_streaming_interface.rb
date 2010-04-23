#
# Copyright (c) 2008 RightScale Inc
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
    
    def streaming_distribution_config_to_xml(config) # :nodoc:
      distribution_config_to_xml(config, 'StreamingDistributionConfig')
    end

    #-----------------------------------------------------------------
    #      API Calls:
    #-----------------------------------------------------------------

    # List all streaming distributions.
    # Returns an array of distributions or RightAws::AwsError exception.
    #
    #  acf.list_streaming_distributions #=>
    #    [{:status=>"Deployed",
    #      :aws_id=>"E3CWE2Z9USOS6B",
    #      :enabled=>true,
    #      :domain_name=>"s2jz1ourvss1fj.cloudfront.net",
    #      :origin=>"bucket-for-konstantin-00.s3.amazonaws.com",
    #      :last_modified_time=>"2010-04-19T08:53:32.574Z",
    #      :comment=>"Woo-Hoo!",
    #      :cnames=>["stream.web.my-awesome-site.net"]},
    #      ...
    #     {:status=>"Deployed",
    #      :aws_id=>"E3NPQZY4LKAYQ8",
    #      :enabled=>true,
    #      :domain_name=>"sw9nrsq9pudk3.cloudfront.net",
    #      :origin=>"bucket-for-konstantin-00.s3.amazonaws.com",
    #      :last_modified_time=>"2010-04-19T08:59:09.600Z",
    #      :comment=>"Woo-Hoo!",
    #      :cnames=>["stream-6.web.my-awesome-site.net"]}]
    #
    def list_streaming_distributions
      result = []
      incrementally_list_streaming_distributions do |response|
        result += response[:distributions]
        true
      end
      result
    end

    # Incrementally list streaming distributions.
    #
    # Optional params: +:marker+ and +:max_items+.
    #
    #   # get first streaming distribution
    #   incrementally_list_distributions(:max_items => 1) #=>
    #    {:marker=>"",
    #     :next_marker=>"E3CWE2Z9USOS6B",
    #     :distributions=>
    #      [{:status=>"Deployed",
    #        :cnames=>["stream.web.my-awesome-site.net"],
    #        :aws_id=>"E3CWE2Z9USOS6B",
    #        :enabled=>true,
    #        :last_modified_time=>"2010-04-19T08:53:32.574Z",
    #        :domain_name=>"s2jz1ourvss1fj.cloudfront.net",
    #        :origin=>"bucket-for-konstantin-00.s3.amazonaws.com",
    #        :comment=>"Woo-Hoo!"}],
    #     :max_items=>1,
    #     :is_truncated=>true}
    #
    #   # get max 100 streaming distributions (the list will be restricted by a default MaxItems value ==100 )
    #   incrementally_list_streaming_distributions
    #
    #   # list streaming distributions by 10
    #   incrementally_list_streaming_distributions(:max_items => 10) do |response|
    #     puts response.inspect # a list of 10 distributions
    #     true # return false if the listing should be broken otherwise use true
    #   end
    #
    def incrementally_list_streaming_distributions(params={}, &block)
      opts = {}
      opts['MaxItems'] = params[:max_items] if params[:max_items]
      opts['Marker']   = params[:marker]    if params[:marker]
      last_response = nil
      loop do
        link = generate_request('GET', 'streaming-distribution', opts)
        last_response = request_info(link,  AcfDistributionListParser.new(:logger => @logger))
        opts['Marker'] = last_response[:next_marker]
        break unless block && block.call(last_response) && !last_response[:next_marker].blank?
      end
      last_response
    end

    # Create a new streaming distribution.
    # Returns the just created distribution or RightAws::AwsError exception.
    #
    #  acf.create_streaming_distribution('bucket-for-konstantin-00.s3.amazonaws.com', 'Woo-Hoo!', true,
    #                                    ['stream-1.web.my-awesome-site.net']) #=>
    #    {:status=>"InProgress",
    #     :caller_reference=>"201004191254412191173215",
    #     :cnames=>["stream-1.web.my-awesome-site.net"],
    #     :aws_id=>"E1M5LERJLU636F",
    #     :e_tag=>"E2588L5QL4BLXH",
    #     :enabled=>true,
    #     :domain_name=>"s1di8imd85wgld.cloudfront.net",
    #     :origin=>"bucket-for-konstantin-00.s3.amazonaws.com",
    #     :last_modified_time=>Mon Apr 19 08:54:42 UTC 2010,
    #     :location=>
    #      "https://cloudfront.amazonaws.com/streaming-distribution/E1M5LERJLU636F",
    #     :comment=>"Woo-Hoo!"}
    #
    def create_streaming_distribution(origin, comment='', enabled=true, cnames=[], caller_reference=nil)
      config = { :origin  => origin,
                 :comment => comment,
                 :enabled => enabled,
                 :cnames  => Array(cnames),
                 :caller_reference => caller_reference }
      create_streaming_distribution_by_config(config)
    end

    def create_streaming_distribution_by_config(config)
      config[:caller_reference] ||= generate_call_reference
      link = generate_request('POST', 'streaming-distribution', {}, streaming_distribution_config_to_xml(config))
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end

    # Get a streaming distribution's information.
    # Returns a distribution's information or RightAws::AwsError exception.
    #
    #  acf.get_streaming_distribution('E3CWE2Z9USOS6B') #=>
    #    {:status=>"Deployed",
    #     :e_tag=>"EXTZ2SXAQT39K",
    #     :cnames=>["stream.web.my-awesome-site.net"],
    #     :aws_id=>"E3CWE2Z9USOS6B",
    #     :enabled=>true,
    #     :domain_name=>"s2jz1ourvss1fj.cloudfront.net",
    #     :origin=>"bucket-for-konstantin-00.s3.amazonaws.com",
    #     :last_modified_time=>"2010-04-19T08:53:32.574Z",
    #     :comment=>"Woo-Hoo!",
    #     :caller_reference=>"201004191253311625537161"}
    #
    #  acf.get_streaming_distribution('E1M5LERJLU636F') #=>
    #    {:trusted_signers=>["self", "648772220000", "120288270000"],
    #     :status=>"InProgress",
    #     :e_tag=>"E2K6XD13RCJQ6E",
    #     :cnames=>["stream-1.web.my-awesome-site.net"],
    #     :active_trusted_signers=>
    #      [{:key_pair_ids=>["APKAIK74BJWCLXZUMEJA"],
    #        :aws_account_number=>"120288270000"},
    #       {:aws_account_number=>"self"},
    #       {:aws_account_number=>"648772220000"}],
    #     :aws_id=>"E1M5LERJLU636F",
    #     :enabled=>false,
    #     :domain_name=>"s1di8imd85wgld.cloudfront.net",
    #     :origin=>"bucket-for-konstantin-00.s3.amazonaws.com",
    #     :last_modified_time=>"2010-04-19T09:14:07.160Z",
    #     :comment=>"Olah-lah!",
    #     :origin_access_identity=>"origin-access-identity/cloudfront/E3JPJZ80ZBX24G",
    #     :caller_reference=>"201004191254412191173215"}
    #
    def get_streaming_distribution(aws_id)
      link = generate_request('GET', "streaming-distribution/#{aws_id}")
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end

    # Get a streaming distribution's configuration.
    # Returns a distribution's configuration or RightAws::AwsError exception.
    #
    #  acf.get_streaming_distribution_config('E1M5LERJLU636F') #=>
    #    {:trusted_signers=>["self", "648772220000", "120288270000"],
    #     :e_tag=>"E2K6XD13RCJQ6E",
    #     :cnames=>["stream-1.web.my-awesome-site.net"],
    #     :enabled=>false,
    #     :origin=>"bucket-for-konstantin-00.s3.amazonaws.com",
    #     :comment=>"Olah-lah!",
    #     :origin_access_identity=>"origin-access-identity/cloudfront/E3JPJZ80ZBX24G",
    #     :caller_reference=>"201004191254412191173215"}
    #
    def get_streaming_distribution_config(aws_id)
      link = generate_request('GET', "streaming-distribution/#{aws_id}/config")
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end

    # Set a streaming distribution's configuration
    # (the :origin and the :caller_reference cannot be changed).
    # Returns +true+ on success or RightAws::AwsError exception.
    #
    #  acf.get_streaming_distribution_config('E1M5LERJLU636F') #=>
    #    {:e_tag=>"E2588L5QL4BLXH",
    #     :cnames=>["stream-1.web.my-awesome-site.net"],
    #     :enabled=>true,
    #     :origin=>"bucket-for-konstantin-00.s3.amazonaws.com",
    #     :comment=>"Woo-Hoo!",
    #     :caller_reference=>"201004191254412191173215"}
    #
    #  config[:comment]                = 'Olah-lah!'
    #  config[:enabled]                = false
    #  config[:origin_access_identity] = "origin-access-identity/cloudfront/E3JPJZ80ZBX24G"
    #  config[:trusted_signers]        = ['self', '648772220000', '120288270000']
    #
    #  acf.set_distribution_config('E2REJM3VUN5RSI', config) #=> true
    #
    def set_streaming_distribution_config(aws_id, config)
      link = generate_request('PUT', "streaming-distribution/#{aws_id}/config", {}, streaming_distribution_config_to_xml(config),
                                     'If-Match' => config[:e_tag])
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Delete a streaming distribution. The enabled distribution cannot be deleted.
    # Returns +true+ on success or RightAws::AwsError exception.
    #
    #  acf.delete_streaming_distribution('E1M5LERJLU636F', 'E2588L5QL4BLXH') #=> true
    #
    def delete_streaming_distribution(aws_id, e_tag)
      link = generate_request('DELETE', "streaming-distribution/#{aws_id}", {}, nil,
                                        'If-Match' => e_tag)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

  end
end
