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

  # Load Balancing Service
  class Lbs < RightAwsBase
    include RightAwsBaseInterface

    # Amazon LBS API version being used
    API_VERSION       = "2009-01-22"
    DEFAULT_HOST      = "lbs.amazonaws.com"
    DEFAULT_PATH      = '/'
    # KD: FIXME later to https and 443
    DEFAULT_PROTOCOL  = 'http'
    DEFAULT_PORT      = 80

    @@bench = AwsBenchmarkingBlock.new
    def self.bench_xml
      @@bench.xml
    end
    def self.bench_service
      @@bench.service
    end

    # Create a new handle to an LBS account. All handles share the same per process or per thread
    # HTTP connection to Amazon LBS. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol and :region). Example: 'https://eu-west-1.LBS.amazonaws.com/'
    # * <tt>:server</tt>: LBS service host, default: DEFAULT_HOST
    # * <tt>:region</tt>: LBS region (North America by default)
    # * <tt>:port</tt>: LBS service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:multi_thread</tt>: true=HTTP connection per thread, false=per process
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    # * <tt>:signature_version</tt>:  The signature version : '0','1' or '2'(default)
    # * <tt>:cache</tt>: true/false(default): caching works for: describe_access_points
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'LBS',
             :default_host        => ENV['LBS_URL'] ? URI.parse(ENV['LBS_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['LBS_URL'] ? URI.parse(ENV['LBS_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['LBS_URL'] ? URI.parse(ENV['LBS_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['LBS_URL'] ? URI.parse(ENV['LBS_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['LBS_API_VERSION'] || API_VERSION },
           aws_access_key_id    || ENV['AWS_ACCESS_KEY_ID'] ,
           aws_secret_access_key|| ENV['AWS_SECRET_ACCESS_KEY'],
           params)
    end

    def generate_request(action, params={}) #:nodoc:
      generate_request_impl(:get, action, params )
    end

      # Sends request to Amazon and parses the response
      # Raises AwsError if any banana happened
    def request_info(request, parser)  #:nodoc:
      request_info_impl(:lbs_connection, @@bench, request, parser)
    end

    #-----------------------------------------------------------------
    #      Access Points
    #-----------------------------------------------------------------

    # Describe access points.
    # Returns an array of access points.
    #
    #   lbs.describe_access_points #=>
    #    [{:dns_name     => "konstantin-5626.us-east.lbs.amazonaws.com",
    #      :health_check =>
    #       {:ping_target         => "TCP:90",
    #        :timeout             => 4,
    #        :healthy_threshold   => 5,
    #        :unhealthy_threshold => 5,
    #        :interval            => 5},
    #      :availability_zones => ["us-east-1c"],
    #      :routing_protocol   => "HTTP",
    #      :access_point_port  => 80,
    #      :end_points         => ["i-b070fed9"],
    #      :end_point_port     => 80,
    #      :created_time       => Tue Feb 03 20:35:51 UTC 2009,
    #      :access_point_name  => "konstantin"},
    #     {:dns_name     => "test-5643.us-east.lbs.amazonaws.com",
    #      :health_check =>
    #       {:ping_target         => "TCP:80",
    #        :timeout             => 5,
    #        :healthy_threshold   => 10,
    #        :unhealthy_threshold => 2,
    #        :interval            => 30},
    #      :availability_zones => ["us-east-1c", "us-east-1a"],
    #      :routing_protocol   => "HTTP",
    #      :access_point_port  => 80,
    #      :end_points         => [],
    #      :end_point_port     => 80,
    #      :created_time       => Wed Feb 04 09:19:18 UTC 2009,
    #      :access_point_name  => "test"}]
    #
    def describe_access_points(*access_points)
      access_points = access_points.flatten.compact
      request_hash = amazonize_list("AccessPointNames.member", access_points)
      link = generate_request("DescribeAccessPoints", request_hash)
      request_cache_or_info(:describe_access_points, link,  DescribeAccessPointsParser, @@bench, access_points.blank?)
    end

    # Create new access point.
    # Returns a new access point DNS name.
    #
    #  +Options+ is a hash:
    #    { :routing_protocol  => string  (:http(default) | :https | :tcp),
    #      :access_point_port => integer (80(default), 443 or 1024..65535),
    #      :end_point_port    => integer (1..65535) }
    #
    #  lbs.create_access_point('test', ['us-east-1a','us-east-1c']) #=> "test-5643.us-east.lbs.amazonaws.com"
    #
    def create_access_point(access_point_name, availability_zones=[], options={})
      request_hash = amazonize_list("AvailabilityZones.member", availability_zones)
      request_hash.merge!( 'AccessPointName'   =>  access_point_name,
                           'RoutingProtocol'   => (options[:routing_protocol]  || :http).to_s.upcase,
                           'AccessPointPort'   =>  options[:access_point_port] || 80,
                           'EndPointPort'      =>  options[:end_point_port]    || 80 )
      link = generate_request("CreateAccessPoint", request_hash)
      request_info(link, CreateAccesspointParser.new(:logger => @logger))
    end

    # Delete access point.
    # Returns +true+ on success.
    def delete_access_point(access_point_name)
      link = generate_request("DeleteAccessPoint", 'AccessPointName' => access_point_name )
      request_info(link, DeleteAccesspointParser.new(:logger => @logger))
    end

    # Add one or more zones to an access point.
    # Returns a list of updated availability zones for the access point.
    #
    #  lbs.add_availability_zones("test", "us-east-1c") #=> ["us-east-1a", "us-east-1c"]
    #
    def add_availability_zones(access_point_name, *availability_zones)
      availability_zones.flatten!
      request_hash = amazonize_list("AvailabilityZones.member", availability_zones)
      request_hash.merge!( 'AccessPointName' => access_point_name )
      link = generate_request("AddAvailabilityZones", request_hash)
      request_info(link, AvailabilityZonesParser.new(:logger => @logger))
    end

    # Remove one or more zones from an access point.
    # Returns a list of updated availability zones for the access point.
    #
    #  lbs.add_availability_zones("test", "us-east-1c") #=> ["us-east-1a"]
    #
    def remove_availability_zones(access_point_name, *availability_zones)
      availability_zones.flatten!
      request_hash = amazonize_list("AvailabilityZones.member", availability_zones)
      request_hash.merge!( 'AccessPointName' => access_point_name )
      link = generate_request("RemoveAvailabilityZones", request_hash)
      request_info(link, AvailabilityZonesParser.new(:logger => @logger))
    end

    # Configure an access points health check.
    # Returns an updated health check configuration for the access point.
    #
    #  +Health_check+ is a hash:
    #    { :interval            => integer,
    #      :ping_target         => string,
    #      :timeout             => integer,
    #      :healthy_threshold   => integer,
    #      :unhealthy_threshold => integer }
    #
    def configure_health_check(access_point_name, health_check)
      request_hash = { 'AccessPointName' => access_point_name }
      health_check.each{ |key, value| request_hash["HealthCheck.#{key.to_s.camelize}"] = value }
      link = generate_request("ConfigureHealthCheck", request_hash)
      request_info(link, HealthCheckParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      End Points
    #-----------------------------------------------------------------

    # Describe end points state.
    # Returns a list of end point states containing InService or OutOfService
    # and any reasons associated with the OutOfService state.
    #
    # lbs.describe_end_point_state('test') #=>
    #    [{:instance_id => "i-b070fed9",
    #      :state       => "OutOfService",
    #      :description => "EndPoint has failed at least the UnhealthyThreshold number of health checks consecutively.",
    #      :reason_code => "EndPoint"},
    #     {:instance_id => "i-73149a1a",
    #      :state       => "InService",
    #      :description => "N/A",
    #      :reason_code => "N/A"}]
    #
    def describe_end_point_state(access_point_name, *end_points)
      end_points.flatten!
      request_hash = amazonize_list("EndPoints.member.?.InstanceId", end_points)
      request_hash.merge!( 'AccessPointName' => access_point_name )
      link = generate_request("DescribeEndPointState", request_hash)
      request_info(link, DescribeEndPointStateParser.new(:logger => @logger))
    end

    # Add new instance(s) to the access point.
    # Returns an updated list of endpoints for the access point.
    #
    #  lbs.register_end_points('test', "i-b070fed9") #=> ["i-b070fed9"]
    #
    def register_end_points(access_point_name, *end_points)
      end_points.flatten!
      request_hash = amazonize_list("EndPoints.member.?.InstanceId", end_points)
      request_hash.merge!( 'AccessPointName' => access_point_name )
      link = generate_request("RegisterEndPoints", request_hash)
      request_cache_or_info :register_end_points, link, EndPointsParser, @@bench, end_points.blank?
    end

    # Remove instance(s) from the access point.
    # Returns an updated list of endpoints for the access point.
    #
    #  lbs.deregister_end_points('test', "i-b070fed9") #=> []
    #
    def deregister_end_points(access_point_name, *end_points)
      end_points.flatten!
      request_hash = amazonize_list("EndPoints.member.?.InstanceId", end_points)
      request_hash.merge!( 'AccessPointName' => access_point_name )
      link = generate_request("DeregisterEndPoints", request_hash)
      request_cache_or_info :deregister_end_points, link, EndPointsParser, @@bench, end_points.blank?
    end

    #-----------------------------------------------------------------
    #      PARSERS: Access Points
    #-----------------------------------------------------------------
 
    class DescribeAccessPointsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when 'member'
          case @xmlpath
            when 'DescribeAccessPointsResponse/DescribeAccessPointsResult/AccessPointsDescriptions'
              @item = { :availability_zones => [],
                        :health_check       => {},
                        :end_points         => [] }
          end
        end
      end
      def tagend(name)
        case name
        when 'AccessPointName'    then @item[:access_point_name] = @text
        when 'AccessPointPort'    then @item[:access_point_port] = @text.to_i
        when 'DNSName'            then @item[:dns_name]          = @text
        when 'EndPointPort'       then @item[:end_point_port]    = @text.to_i
        when 'CreatedTime'        then @item[:created_time]      = Time::parse(@text)
        when 'RoutingProtocol'    then @item[:routing_protocol]  = @text
        when 'InstanceId'         then @item[:end_points]        << @text
        when 'Interval'           then @item[:health_check][:interval]            = @text.to_i
        when 'PingTarget'         then @item[:health_check][:ping_target]         = @text
        when 'HealthyThreshold'   then @item[:health_check][:healthy_threshold]   = @text.to_i
        when 'Timeout'            then @item[:health_check][:timeout]             = @text.to_i
        when 'UnhealthyThreshold' then @item[:health_check][:unhealthy_threshold] = @text.to_i
        when 'member'
          case @xmlpath
          when 'DescribeAccessPointsResponse/DescribeAccessPointsResult/AccessPointsDescriptions'
            @result << @item
          when 'DescribeAccessPointsResponse/DescribeAccessPointsResult/AccessPointsDescriptions/member/AvailabilityZones'
            @item[:availability_zones] << @text
          end
        end
      end
      def reset
        @result = []
      end
    end

    class CreateAccesspointParser < RightAWSParser #:nodoc:
      def tagend(name)
        @result = @text if name == 'DNSName'
      end
    end

    class DeleteAccesspointParser < RightAWSParser #:nodoc:
      def tagend(name)
        @result = true if name == 'DeleteAccessPointResult'
      end
    end

    class AvailabilityZonesParser < RightAWSParser #:nodoc:
      def tagend(name)
        @result << @text if name == 'member'
      end
      def reset
        @result = []
      end
    end

    class HealthCheckParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'Interval'           then @result[:interval]            = @text.to_i
        when 'PingTarget'         then @result[:ping_target]         = @text
        when 'HealthyThreshold'   then @result[:healthy_threshold]   = @text.to_i
        when 'Timeout'            then @result[:timeout]             = @text.to_i
        when 'UnhealthyThreshold' then @result[:unhealthy_threshold] = @text.to_i
        end
      end
      def reset
        @result = {}
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: End Points
    #-----------------------------------------------------------------

    class DescribeEndPointStateParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @item = {} if name == 'member'
      end
      def tagend(name)
        case name
        when 'Description' then @item[:description] = @text
        when 'State'       then @item[:state]       = @text
        when 'InstanceId'  then @item[:instance_id] = @text
        when 'ReasonCode'  then @item[:reason_code] = @text
        when 'member'      then @result            << @item
        end
      end
      def reset
        @result = []
      end
    end

    class EndPointsParser < RightAWSParser #:nodoc:
      def tagend(name)
        @result << @text if name == 'InstanceId'
      end
      def reset
        @result = []
      end
    end

  end

end
