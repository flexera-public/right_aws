# Copyright (c) 2007-2011 RightScale Inc
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

  # = RightAws::Route53Interface -- Amazon Route 53 web service interface.
  #
  # The RightAws::Route53Interface class provides a complete interface to Amazon Route 53: a web
  # service that enables you to manage your DNS service.
  #
  # For explanations of the semantics of each call, please refer to Amazon's documentation at
  # http://aws.amazon.com/documentation/route53/
  #
  # Examples:
  #
  #  # Create Route53 handler
  #  r53 = RightAws::Route53Interface.new(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
  #
  #  #------------------------
  #  # Create Hosted Zone
  #  #------------------------
  #  
  #  hosted_zone_config = {
  #    :name   => 'my-awesome-site.com.',
  #    :config => {
  #      :comment => 'My test site!'
  #     }
  #  }
  #  r53.create_hosted_zone(hosted_zone_config) #=>
  #    {:name_servers=>
  #      ["ns-1115.awsdns-11.org",
  #       "ns-696.awsdns-23.net",
  #       "ns-1963.awsdns-53.co.uk",
  #       "ns-362.awsdns-45.com"],
  #     :aws_id=>"/hostedzone/Z1K6NCF0EB26FB",
  #     :caller_reference=>"1295424990-710392-gqMuw-KcY8F-LFlrB-SQhp9",
  #     :config=>{:comment=>"My test site!"},
  #     :change_info=>
  #      {:status=>"PENDING",
  #       :aws_id=>"/change/C23QGMT8XTCAJY",
  #       :submitted_at=>"2011-01-19T08:16:31.046Z"},
  #     :name=>"my-awesome-site.com."}
  #
  #  # List Hosted Zones
  #  r53.list_hosted_zones #=> []
  #    [{:aws_id=>"/hostedzone/Z1K6NCF0EB26FB",
  #      :caller_reference=>"1295424990-710392-gqMuw-KcY8F-LFlrB-SQhp9",
  #      :config=>{:comment=>"My test site!"},
  #      :name=>"my-awesome-site.com."}]
  #
  #  #--------------------------------
  #  # Manage DNS Records and Changes
  #  #--------------------------------
  #
  #  # Create DNS Records
  #  resource_record_sets = [ { :name => 'www1.my-awesome-site.com.',
  #                             :type => 'NS',
  #                             :ttl => 600,
  #                             :resource_records => 'www.mysite.com' },
  #                           { :name => 'www2.my-awesome-site.com.',
  #                             :type => 'A',
  #                             :ttl => 600,
  #                             :resource_records => ['10.0.0.1'] } ]
  #  r53.create_resource_record_sets("/hostedzone/Z1K6NCF0EB26FB", resource_record_sets, 'my first set of records') #=>
  #    { :status=>"PENDING",
  #      :aws_id=>"/change/C2C6IGNRTKA0AY",
  #      :submitted_at=>"2011-01-19T08:29:26.160Z" }
  #
  #  # Delete DNS records
  #  r53.delete_resource_record_sets("/hostedzone/Z1K6NCF0EB26FB", resource_record_sets, 'I dont need them any more') #=>
  #    { :status=>"PENDING",
  #      :aws_id=>"/change/C1CYJ10EZBFLO7",
  #      :submitted_at=>"2011-01-19T08:26:41.220Z" }
  #
  #  # Create or delete DNS records (:action key must be provided):
  #  resource_record_sets = [ { :action => :create,
  #                             :name => 'www1.my-awesome-site.com.',
  #                             :type => 'NS',
  #                             :ttl => 600,
  #                             :resource_records => 'www.mysite.com' },
  #                           { :action => :delete,
  #                             :name => 'www2.my-awesome-site.com.',
  #                             :type => 'A',
  #                             :ttl => 600,
  #                             :resource_records => ['10.0.0.1'] } ]
  #  r53.change_resource_record_sets("/hostedzone/Z1K6NCF0EB26FB", resource_record_sets, 'do change records')
  #    { :status=>"PENDING",
  #      :aws_id=>"/change/C2PWXVECN794LK",
  #      :submitted_at=>"2011-01-19T08:31:33.301Z" }
  #
  #  # List DNS Records
  #  r53.list_resource_record_sets("/hostedzone/Z1K6NCF0EB26FB") #=>
  #    [{:type=>"NS",
  #      :ttl=>172800,
  #      :resource_records=>
  #       ["ns-1115.awsdns-11.org.",
  #        "ns-696.awsdns-23.net.",
  #        "ns-1963.awsdns-53.co.uk.",
  #        "ns-362.awsdns-45.com."],
  #      :name=>"my-awesome-site.com."},
  #     {:type=>"SOA",
  #      :ttl=>900,
  #      :resource_records=>
  #       ["ns-1115.awsdns-11.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"],
  #      :name=>"my-awesome-site.com."},
  #     {:type=>"NS",
  #      :ttl=>600,
  #      :resource_records=>["www.mysite.com"],
  #      :name=>"www1.my-awesome-site.com."}]
  #
  #  # Get Change info
  #  r53.get_change("/change/C2C6IGNRTKA0AY")
  #    {:status=>"INSYNC",
  #     :aws_id=>"/change/C2C6IGNRTKA0AY",
  #     :submitted_at=>"2011-01-19T08:29:26.160Z"}
  #
  #  #------------------------
  #  # Delete Hosted Zone
  #  #------------------------
  #
  #  # Get a list of DNS records I have created (the first 2 records were added by Amazon and cannot be deleted)
  #  resource_record_sets = r53.list_resource_record_sets("/hostedzone/Z1K6NCF0EB26FB")
  #  resource_record_sets.shift
  #  resource_record_sets.shift
  #
  #  # Delete them all
  #  delete_resource_record_sets("/hostedzone/Z1K6NCF0EB26FB", resource_record_sets, 'kill all records I have created') #=>
  #    { :status=>"PENDING",
  #      :aws_id=>"/change/C6NCO8Z50MHXV",
  #      :submitted_at=>"2011-01-19T08:46:37.307Z" }
  #
  #  # Delete Hosted Zone
  #  r53.delete_hosted_zone("/hostedzone/Z1K6NCF0EB26FB") #=> 
  #    { :status=>"PENDING",
  #      :aws_id=>"/change/C3OJ31D4V5P2LU",
  #      :submitted_at=>"2011-01-19T08:46:37.530Z" }
  #
  class Route53Interface < RightAwsBase
    
    include RightAwsBaseInterface

    API_VERSION       = "2011-05-05"
    DEFAULT_HOST      = "route53.amazonaws.com"
    DEFAULT_PATH      = '/'
    DEFAULT_PROTOCOL  = 'https'
    DEFAULT_PORT      = 443

    @@bench = AwsBenchmarkingBlock.new
    def self.bench_xml
      @@bench.xml
    end
    def self.bench_service
      @@bench.service
    end

    # Create a new handle to an Route53 account. All handles share the same per process or per thread
    # HTTP connection to Amazon Route53. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol).
    # * <tt>:server</tt>: Route53 service host, default: DEFAULT_HOST
    # * <tt>:port</tt>: Route53 service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    # * <tt>:signature_version</tt>:  The signature version : '0','1' or '2'(default)
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'ROUTE_53',
             :default_host        => ENV['ROUTE_53_URL'] ? URI.parse(ENV['ROUTE_53_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['ROUTE_53_URL'] ? URI.parse(ENV['ROUTE_53_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['ROUTE_53_URL'] ? URI.parse(ENV['ROUTE_53_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['ROUTE_53_URL'] ? URI.parse(ENV['ROUTE_53_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['ROUTE_53_API_VERSION'] || API_VERSION },
           aws_access_key_id    || ENV['AWS_ACCESS_KEY_ID'] ,
           aws_secret_access_key|| ENV['AWS_SECRET_ACCESS_KEY'],
           params)
    end

    #-----------------------------------------------------------------
    #      Requests
    #-----------------------------------------------------------------

    # Generates request hash for REST API.
    def generate_request(method, path, params={}, body=nil, headers={})  # :nodoc:
      # Params
      params.delete_if{ |key, val| val.right_blank? }
      unless params.right_blank?
        path += "?" + params.to_a.collect{ |key,val| "#{AwsUtils::amz_escape(key)}=#{AwsUtils::amz_escape(val.to_s)}" }.join("&")
      end
      # Headers
      headers['content-type'] ||= 'text/xml' if body
      headers['date']           = Time.now.httpdate
      # Auth
      signature = AwsUtils::sign(@aws_secret_access_key, headers['date'])
      headers['X-Amzn-Authorization'] = "AWS3-HTTPS AWSAccessKeyId=#{@aws_access_key_id},Algorithm=HmacSHA1,Signature=#{signature}"
      # Request
      path    = "#{@params[:service]}#{@params[:api_version]}/#{path}"
      request = "Net::HTTP::#{method.capitalize}".right_constantize.new(path)
      request.body = body if body
      # Set request headers
      headers.each { |key, value| request[key.to_s] = value }
      # prepare output hash
      { :request  => request,
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol] }
      end

      # Sends request to Amazon and parses the response.
      # Raises AwsError if any banana happened.
    def request_info(request, parser, &block) # :nodoc:
      request_info_impl(:acf_connection, @@bench, request, parser, &block)
    end

    def incrementally_list_hosted_zones(path, parser, params={}, &block) # :nodoc:
      opts = {}
      opts['MaxItems'] = params[:max_items] if params[:max_items]
      opts['Marker']   = params[:marker]    if params[:marker]
      last_response = nil
      loop do
        link = generate_request('GET', path, opts)
        last_response = request_info(link,  parser.new(:logger => @logger))
        opts['Marker'] = last_response[:next_marker]
        break unless block && block.call(last_response) && !last_response[:next_marker].right_blank?
      end
      last_response
    end

    def incrementally_list_resource_records(path, parser, params={}, &block) # :nodoc:
      opts = {}
      opts[:maxitems] = params.delete(:max_items) if params[:max_items]
      last_response = nil
      loop do
        link = generate_request('GET', path, opts)
        last_response = request_info(link,  parser.new(:logger => @logger))
        opts[:maxitems] = last_response[:max_items]
        opts[:name]     = last_response[:next_record_name]
        opts[:type]     = last_response[:next_record_type]
        break unless block && block.call(last_response) && last_response[:is_truncated]
      end
      last_response
    end

    def expand_hosted_zone_id(aws_id) # :nodoc:
      aws_id[%r{^/hostedzone/}] ? aws_id : "/hostedzone/#{aws_id}"
    end

    def expand_change_id(aws_id) # :nodoc:
      aws_id[%r{^/change/}] ? aws_id : "/change/#{aws_id}"
    end

    def hosted_zone_config_to_xml(config) # :nodoc:
      config[:caller_reference] ||= AwsUtils::generate_call_reference
      hosted_zone_config = ''
      unless config[:config].right_blank?
        hosted_zone_config = "  <HostedZoneConfig>\n" +
                             "    <Comment>#{AwsUtils::xml_escape config[:config][:comment]}</Comment>\n" +
                             "  </HostedZoneConfig>\n"
      end
      # XML
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
      "<CreateHostedZoneRequest xmlns=\"https://#{@params[:server]}/doc/#{API_VERSION}/\">\n" +
      "  <Name>#{config[:name]}</Name>\n" +
      "  <CallerReference>#{config[:caller_reference]}</CallerReference>\n" +
      hosted_zone_config +
      "</CreateHostedZoneRequest>\n"
    end

    def resource_record_sets_to_xml(resource_record_changes, comment) # :nodoc:
      # Comment
      xml_comment = comment.right_blank? ? '' : "    <Comment>#{AwsUtils::xml_escape(comment)}</Comment>\n"
      # Changes
      xml_changes = ''
      resource_record_changes.each do |change|
        xml_resource_records = Array(change[:resource_records]).map{|record| "            <ResourceRecord><Value>#{AwsUtils::xml_escape(record)}</Value></ResourceRecord>\n" }.join('')
        xml_changes += "      <Change>\n"                                                                +
                       "        <Action>#{AwsUtils::xml_escape(change[:action].to_s.upcase)}</Action>\n" +
                       "        <ResourceRecordSet>\n"                                                   +
                       "          <Name>#{AwsUtils::xml_escape(change[:name])}</Name>\n"                 +
                       "          <Type>#{AwsUtils::xml_escape(change[:type].to_s.upcase)}</Type>\n"
        if change[:alias_target]
          alias_target = change[:alias_target]
          xml_changes +=
                       "          <AliasTarget>\n"                                                                              +
                       "            <HostedZoneId>#{AwsUtils::xml_escape(alias_target[:hosted_zone_id].to_s)}</HostedZoneId>\n" +
                       "            <DNSName>#{AwsUtils::xml_escape(alias_target[:dns_name].to_s)}</DNSName>\n"                 +
                       "          </AliasTarget>\n"
        else
          xml_changes +=
                       "          <TTL>#{AwsUtils::xml_escape(change[:ttl].to_s)}</TTL>\n"               +
                       "          <ResourceRecords>\n"                                                   +
                       xml_resource_records                                                              +
                       "          </ResourceRecords>\n"
        end
        xml_changes +=
                       "        </ResourceRecordSet>\n"                                                  +
                       "      </Change>\n"
      end
      # XML
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
      "<ChangeResourceRecordSetsRequest xmlns=\"https://#{@params[:server]}/doc/#{API_VERSION}/\">\n" +
      "  <ChangeBatch>\n"  +
      xml_comment          +
      "    <Changes>\n"    +
      xml_changes          +
      "    </Changes>\n"   +
      "  </ChangeBatch>\n" +
      "</ChangeResourceRecordSetsRequest>\n"
    end


    #-----------------------------------------------------------------
    #      Hosted Zones
    #-----------------------------------------------------------------

    # List your hosted zones.
    #
    #  r53.list_hosted_zones #=>
    #    [{:config=>{:comment=>"KD1, description"},
    #      :aws_id=>"/hostedzone/Z2P714ENJN23PN",
    #      :caller_reference=>"1295424990-710392-gqMuw-KcY8F-LFlrB-SQhp9",
    #      :name=>"patch-island.com."},
    #     {:config=>{:comment=>"My awesome site!"},
    #      :aws_id=>"/hostedzone/ZWEC7PPVACGQ4",
    #      :caller_reference=>"1295422234-657482-hfkeo-JFKid-Ldfle-Sdrty",
    #      :name=>"mysite.patch-island.com."}, ...]
    #
    # PS: http://docs.amazonwebservices.com/Route53/latest/APIReference/API_ListHostedZones.html
    #
    def list_hosted_zones
      result = []
      incrementally_list_hosted_zones('hostedzone', ListHostedZonesParser) do |response|
        result += response[:items]
        true
      end
      result
    end

    # Create new hosted zone
    #
    #  config = {
    #    :name => 'mysite.patch-island.com.',
    #    :config => {
    #      :comment => 'My awesome site!'
    #     }
    #  }
    #  r53.create_hosted_zone(config) #=>
    #    {:config=>{:comment=>"My awesome site!"},
    #     :change_info=>
    #      {:status=>"PENDING",
    #       :aws_id=>"/change/C2NOTVGL7IOFFF",
    #       :submitted_at=>"2011-01-18T15:34:18.086Z"},
    #     :aws_id=>"/hostedzone/ZWEC7PPVACGQ4",
    #     :caller_reference=>"1295365357-227168-NfZ4P-VGHWi-Yq0p7-nuN6q",
    #     :name_servers=>
    #      ["ns-794.awsdns-35.net",
    #       "ns-459.awsdns-57.com",
    #       "ns-1537.awsdns-00.co.uk",
    #       "ns-1165.awsdns-17.org"],
    #     :name=>"mysite.patch-island.com."}
    #
    # PS: http://docs.amazonwebservices.com/Route53/latest/APIReference/index.html?API_CreateHostedZone.html
    #
    def create_hosted_zone(config)
      config[:caller_reference] ||= AwsUtils::generate_unique_token
      link = generate_request('POST', 'hostedzone', {}, hosted_zone_config_to_xml(config))
      request_info(link, GetHostedZoneParser.new(:logger => @logger))
    end

    # Get your hosted zone.
    #
    #  r53.get_hosted_zone("ZWEC7PPVACGQ4") #=>
    #    {:config=>{:comment=>"My awesome site!"},
    #     :aws_id=>"/hostedzone/ZWEC7PPVACGQ4",
    #     :caller_reference=>"1295422234-657482-hfkeo-JFKid-Ldfle-Sdrty",
    #     :name_servers=>
    #      ["ns-794.awsdns-35.net",
    #       "ns-459.awsdns-57.com",
    #       "ns-1537.awsdns-00.co.uk",
    #       "ns-1165.awsdns-17.org"],
    #     :name=>"mysite.patch-island.com."}
    #
    # PS: http://docs.amazonwebservices.com/Route53/latest/APIReference/API_GetHostedZone.html
    #
    def get_hosted_zone(hosted_zone_aws_id)
      link = generate_request('GET', expand_hosted_zone_id(hosted_zone_aws_id))
      request_info(link, GetHostedZoneParser.new(:logger => @logger))
    end

    # Delete hosted zone.
    #
    #  r53.delete_hosted_zone("/hostedzone/Z2P714ENJN23PN") #=>
    #    {:status=>"PENDING",
    #     :submitted_at=>"2011-01-18T15:45:45.060Z",
    #     :aws_id=>"/change/C1PN1SDWZKPTAC"}
    #
    # PS: http://docs.amazonwebservices.com/Route53/latest/APIReference/API_DeleteHostedZone.html
    #
    def delete_hosted_zone(hosted_zone_aws_id)
      link = generate_request('DELETE', expand_hosted_zone_id(hosted_zone_aws_id))
      request_info(link, GetChangeParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Resource Records Set
    #-----------------------------------------------------------------

    # List your resource record sets.
    # Options: :type, :name, :max_items
    #
    #  r53.list_resource_record_sets("/hostedzone/ZWEC7PPVACGQ4") #=>
    #      [{:type=>"NS",
    #        :ttl=>172800,
    #        :name=>"mysite.patch-island.com.",
    #        :resource_records=>
    #         ["ns-459.awsdns-57.com.",
    #          "ns-794.awsdns-35.net.",
    #          "ns-1165.awsdns-17.org.",
    #          "ns-1537.awsdns-00.co.uk."]},
    #       {:type=>"SOA",
    #        :ttl=>900,
    #        :name=>"mysite.patch-island.com.",
    #        :resource_records=>
    #         ["ns-794.awsdns-35.net. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"]},
    #       {:type=>"NS",
    #        :ttl=>600,
    #        :resource_records=>["xxx.mysite.com"],
    #        :name=>"m1.mysite.patch-island.com."}]
    #
    # PS: http://docs.amazonwebservices.com/Route53/latest/APIReference/API_ListResourceRecordSets.html
    #
    def list_resource_record_sets(hosted_zone_aws_id, options={})
      options = options.dup
      result = []
      incrementally_list_resource_records("#{expand_hosted_zone_id(hosted_zone_aws_id)}/rrset", ListResourceRecordSetsParser, options) do |response|
        result += response[:items]
        true
      end
      result
    end

    # Create or delete DNS records.
    #
    #  resource_record_sets = [{ :action => :create,
    #                            :name => 'm3.mysite.patch-island.com',
    #                            :type => 'NS',
    #                            :ttl => 600,
    #                            :resource_records => 'xxx.mysite.com' },
    #                          { :action => :delete,
    #                            :name => 'm2.mysite.patch-island.com',
    #                            :type => 'A',
    #                            :ttl => 600,
    #                            :resource_records => ['10.0.0.1'] }]
    #  r53.change_resource_record_sets("/hostedzone/Z1K6NCF0EB26FB", resource_record_sets, 'KD: Comment#1') #=>
    #    {:status=>"PENDING",
    #     :submitted_at=>"2011-01-18T20:21:56.828Z",
    #     :aws_id=>"/change/C394PNLM1B2P08"}
    #
    # PS: resource_record_sets must have an :action key set (== :create or :delete)
    # PPS: http://docs.amazonwebservices.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
    #
    def change_resource_record_sets(hosted_zone_aws_id, resource_record_sets, comment = '')
      link = generate_request('POST', "#{expand_hosted_zone_id(hosted_zone_aws_id)}/rrset", {}, resource_record_sets_to_xml(resource_record_sets, comment))
      request_info(link, GetChangeParser.new(:logger => @logger))
    end

    # Create DNS records.
    #
    #  resource_record_sets = [{ :name => 'm3.mysite.patch-island.com',
    #                            :type => 'NS',
    #                            :ttl => 600,
    #                            :resource_records => 'xxx.mysite.com' },
    #                          { :name => 'm2.mysite.patch-island.com',
    #                            :type => 'A',
    #                            :ttl => 600,
    #                            :resource_records => ['10.0.0.1'] }]
    #  r53.create_resource_record_sets("/hostedzone/Z1K6NCF0EB26FB", resource_record_sets, 'KD: Comment#1') #=>
    #    {:status=>"PENDING",
    #     :submitted_at=>"2011-01-18T20:21:56.828Z",
    #     :aws_id=>"/change/C394PNLM1B2P08"}
    #
    # PS: http://docs.amazonwebservices.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
    #
    def create_resource_record_sets(hosted_zone_aws_id, resource_record_sets, comment = '')
      resource_record_sets.each{|rrs| rrs[:action] = :create}
      change_resource_record_sets(hosted_zone_aws_id, resource_record_sets, comment)
    end

    # Delete DNS records.
    #
    #  resource_record_sets = [{ :name => 'm3.mysite.patch-island.com',
    #                            :type => 'NS',
    #                            :ttl => 600,
    #                            :resource_records => 'xxx.mysite.com' },
    #                          { :name => 'm2.mysite.patch-island.com',
    #                            :type => 'A',
    #                            :ttl => 600,
    #                            :resource_records => ['10.0.0.1'] }]
    #  r53.create_resource_record_sets("/hostedzone/Z1K6NCF0EB26FB", resource_record_sets, 'KD: Comment#1') #=>
    #    {:status=>"PENDING",
    #     :submitted_at=>"2011-01-18T20:21:56.828Z",
    #     :aws_id=>"/change/C394PNLM1B2P08"}
    #
    # PS: http://docs.amazonwebservices.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
    #
    def delete_resource_record_sets(hosted_zone_aws_id, resource_record_sets, comment = '')
      resource_record_sets.each{|rrs| rrs[:action] = :delete}
      change_resource_record_sets(hosted_zone_aws_id, resource_record_sets, comment)
    end


    # Get the current state of a change request.
    #
    #  r53.get_change("/change/C1PN1SDWZKPTAC") #=>
    #    {:status=>"INSYNC",
    #     :aws_id=>"/change/C1PN1SDWZKPTAC",
    #     :submitted_at=>"2011-01-18T15:45:45.060Z"}
    #
    # PS: http://docs.amazonwebservices.com/Route53/latest/APIReference/API_GetChange.html
    #
    def get_change(change_aws_id)
      link = generate_request('GET', expand_change_id(change_aws_id))
      request_info(link, GetChangeParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Hosted Zones
    #-----------------------------------------------------------------

    class ListHostedZonesParser < RightAWSParser # :nodoc:
      def reset
        @result = { :items => [] }
      end
      def tagstart(name, attributes)
        case name
        when 'HostedZone' then @item = { :config => {} }
        end
      end
      def tagend(name)
        case name
        when 'IsTruncated'     then @result[:is_truncated]   = @text == 'true'
        when 'NextMarker'      then @result[:next_marker]    = @text
        when 'MaxItems'        then @result[:max_items]      = @text.to_i
        when 'Id'              then @item[:aws_id]           = @text
        when 'Name'            then @item[:name]             = @text
        when 'CallerReference' then @item[:caller_reference] = @text
        when 'HostedZone'      then @result[:items]         << @item
        else
          case full_tag_name
          when %r{/Config/Comment$} then @item[:config][:comment] = @text
          end
        end
      end
    end

    class GetHostedZoneParser < RightAWSParser # :nodoc:
      def reset
        @result = {}
      end
      def tagend(name)
        case full_tag_name
        when %r{/HostedZone/Id}                         then  @result[:aws_id]                             = @text
        when %r{/HostedZone/Name}                       then  @result[:name]                               = @text
        when %r{/HostedZone/CallerReference}            then  @result[:caller_reference]                   = @text
        when %r{/Config/Comment$}                       then (@result[:config] ||= {})[:comment]           = AwsUtils::xml_unescape(@text)
        when %r{/ChangeInfo/Id$}                        then (@result[:change_info] ||= {})[:aws_id]       = @text
        when %r{/ChangeInfo/Status$}                    then (@result[:change_info] ||= {})[:status]       = @text
        when %r{/ChangeInfo/SubmittedAt$}               then (@result[:change_info] ||= {})[:submitted_at] = @text
        when %r{/DelegationSet/NameServers/NameServer$} then (@result[:name_servers] ||= [])              << @text
        end
      end
    end

    #-----------------------------------------------------------------
    #      Resource Records Set
    #-----------------------------------------------------------------

    class ListResourceRecordSetsParser < RightAWSParser # :nodoc:
      def reset
        @result = { :items => [] }
      end
      def tagstart(name, attributes)
        case name
        when 'ResourceRecordSet' then @item = {}
        end
      end
      def tagend(name)
        case name
        when 'IsTruncated'       then @result[:is_truncated]     = @text == 'true'
        when 'NextRecordName'    then @result[:next_record_name] = @text
        when 'NextRecordType'    then @result[:next_record_type] = @text
        when 'MaxItems'          then @result[:max_items]        = @text.to_i
        when 'Type'              then @item[:type]     = @text
        when 'Name'              then @item[:name]     = @text
        when 'TTL'               then @item[:ttl]      = @text.to_i
        when 'ResourceRecordSet' then @result[:items] << @item
        else
          case full_tag_name
          when %r{/ResourceRecord/Value}     then (@item[:resource_records] ||= []) << @text
          when %r{/AliasTarget/DNSName}      then (@item[:alias_target] ||= {})[:dns_name] = @text
          when %r{/AliasTarget/HostedZoneId} then (@item[:alias_target] ||= {})[:hosted_zone_id] = @text
          end
        end
      end
    end

    class GetChangeParser < RightAWSParser # :nodoc:
      def reset
        @result = { }
      end
      def tagend(name)
        case name
        when 'Id'          then @result[:aws_id]       = @text
        when 'Status'      then @result[:status]       = @text
        when 'SubmittedAt' then @result[:submitted_at] = @text
        end
      end
    end

  end

end
