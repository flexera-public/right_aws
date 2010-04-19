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

  # = RightAWS::ElbInterface -- RightScale Amazon Elastic Load Balancer interface
  # The RightAws::ElbInterface class provides a complete interface to Amazon's
  # Elastic Load Balancer service.
  # 
  # For explanations of the semantics of each call, please refer to Amazon's documentation at
  # http://docs.amazonwebservices.com/ElasticLoadBalancing/latest/DeveloperGuide/
  # 
  # Create an interface handle:
  #
  #  elb = RightAws::ElbInterface.new(aws_access_key_id, aws_security_access_key)
  #
  # Create an new load balancer:
  #
  #  elb.create_load_balancer( 'test-kd1',
  #                           ['us-east-1a', 'us-east-1b'],
  #                           [ { :protocol => :http, :load_balancer_port => 80,  :instance_port => 80 },
  #		                          { :protocol => :tcp,  :load_balancer_port => 443, :instance_port => 443 } ])
  #
  # Configure its health checking:
  #
  #  elb.configure_health_check( 'test-kd1',
  #                              { :healthy_threshold => 9,
  #                                :unhealthy_threshold => 3,
  #                                :target => "TCP:433",
  #                                :timeout => 6,
  #                                :interval => 31}
  #
  # Register instances with the balancer:
  #
  #  elb.register_instances_with_load_balancer('test-kd1', 'i-8b8bcbe2', 'i-bf8bcbd6') #=> ["i-8b8bcbe2", "i-bf8bcbd6"]
  #
  # Add new availability zones:
  #
  #  elb.enable_availability_zones_for_load_balancer("test-kd1", "us-east-1c")
  #
  class ElbInterface < RightAwsBase
    include RightAwsBaseInterface

    # Amazon ELB API version being used
    API_VERSION       = "2009-11-25"
    DEFAULT_HOST      = "elasticloadbalancing.amazonaws.com"
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

    # Create a new handle to an ELB account. All handles share the same per process or per thread
    # HTTP connection to Amazon ELB. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol). Example: 'https://elasticloadbalancing.amazonaws.com'
    # * <tt>:server</tt>: ELB service host, default: DEFAULT_HOST
    # * <tt>:port</tt>: ELB service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:multi_thread</tt>: true=HTTP connection per thread, false=per process
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    # * <tt>:signature_version</tt>:  The signature version : '0','1' or '2'(default)
    # * <tt>:cache</tt>: true/false(default): caching works for: describe_load_balancers
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'ELB',
             :default_host        => ENV['ELB_URL'] ? URI.parse(ENV['ELB_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['ELB_URL'] ? URI.parse(ENV['ELB_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['ELB_URL'] ? URI.parse(ENV['ELB_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['ELB_URL'] ? URI.parse(ENV['ELB_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['ELB_API_VERSION'] || API_VERSION },
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
    #      Load Balancers
    #-----------------------------------------------------------------
    # Describe load balancers.
    # Returns an array of load balancers.
    #
    #  elb.describe_load_balancers #=>
    #    [ { :health_check =>
    #        { :healthy_threshold => 10,
    #          :unhealthy_threshold => 2,
    #          :target => "TCP:80",
    #          :timeout => 5,
    #          :interval => 30},
    #        :load_balancer_name => "test-kd1",
    #        :availability_zones => ["us-east-1a", "us-east-1b"],
    #        :listeners =>
    #         [ { :protocol => "HTTP", :load_balancer_port => "80",  :instance_port => "80" },
    #           { :protocol => "TCP",  :load_balancer_port => "443", :instance_port => "443" } ],
    #        :created_time => "2009-05-27T11:59:11.000Z",
    #        :dns_name => "test-kd1-1519253964.us-east-1.elb.amazonaws.com",
    #        :instances => [] } ]
    #
    #  elb.describe_load_balancers("test-kd1") #=>
    #    [{:load_balancer_name=>"test-kd1",
    #      :instances=>["i-9fc056f4", "i-b3debfd8"],
    #      :health_check=>
    #       {:interval=>30,
    #        :healthy_threshold=>10,
    #        :target=>"TCP:80",
    #        :unhealthy_threshold=>2,
    #        :timeout=>5},
    #      :dns_name=>"test-kd1-869291821.us-east-1.elb.amazonaws.com",
    #      :listeners=>
    #       [{:load_balancer_port=>"80",
    #         :policy_names=>["my-policy-1"],
    #         :instance_port=>"80",
    #         :protocol=>"HTTP"},
    #        {:load_balancer_port=>"8080",
    #         :policy_names=>["my-policy-lb-1"],
    #         :instance_port=>"8080",
    #         :protocol=>"HTTP"},
    #        {:load_balancer_port=>"443",
    #         :policy_names=>[],
    #         :instance_port=>"443",
    #         :protocol=>"TCP"}],
    #      :created_time=>"2010-04-15T12:04:49.000Z",
    #      :availability_zones=>["us-east-1a", "us-east-1b"],
    #      :app_cookie_stickiness_policies=>
    #       [{:policy_name=>"my-policy-1", :cookie_name=>"my-cookie-1"}],
    #      :lb_cookie_stickiness_policies=>
    #       [{:cookie_expiration_period=>60, :policy_name=>"my-policy-lb-1"}]}]
    #
    def describe_load_balancers(*load_balancers)
      load_balancers = load_balancers.flatten.compact
      request_hash = amazonize_list("LoadBalancerNames.member", load_balancers)
      link = generate_request("DescribeLoadBalancers", request_hash)
      request_cache_or_info(:describe_load_balancers, link,  DescribeLoadBalancersParser, @@bench, load_balancers.blank?)
    end

    # Create new load balancer.
    # Returns a new load balancer DNS name.
    #
    #  lb = elb.create_load_balancer( 'test-kd1',
    #                                ['us-east-1a', 'us-east-1b'],
    #                                [ { :protocol => :http, :load_balancer_port => 80,  :instance_port => 80 },
		#						                    	 { :protocol => :tcp,  :load_balancer_port => 443, :instance_port => 443 } ])
    #	 puts lb #=> "test-kd1-1519253964.us-east-1.elb.amazonaws.com"
    #
    def create_load_balancer(load_balancer_name, availability_zones=[], listeners=[])
      request_hash = { 'LoadBalancerName' => load_balancer_name }
      # merge zones
      request_hash.merge!( amazonize_list("AvailabilityZones.member", availability_zones) )
      # merge listeners
      if listeners.blank?
        listeners = { :protocol           => :http,
                      :load_balancer_port => 80,
                      :instance_port      => 80 }
      end
      listeners = [listeners] unless listeners.is_a?(Array)
      request_hash.merge!( amazonize_list( ['Listeners.member.?.Protocol',
                                            'Listeners.member.?.LoadBalancerPort',
                                            'Listeners.member.?.InstancePort'],
                                             listeners.map{|i| [ (i[:protocol] || 'HTTP').to_s.upcase,
                                                                 (i[:load_balancer_port] || 80),
                                                                 (i[:instance_port] || 80) ] } ) )
      link = generate_request("CreateLoadBalancer", request_hash)
      request_info(link, CreateLoadBalancerParser.new(:logger => @logger))
    end

    # Delete load balancer.
    # Returns +true+ on success.
    #
    #  elb.delete_load_balancer('test-kd1') #=> true
    #
    # Amazon: Because this API has been designed to be idempotent, even if the LoadBalancer does not exist or
    # has been deleted, DeleteLoadBalancer still returns a success.
    #
    def delete_load_balancer(load_balancer_name)
      link = generate_request("DeleteLoadBalancer", 'LoadBalancerName' => load_balancer_name)
      request_info(link, DeleteLoadBalancerParser.new(:logger => @logger))
    end

    # Add one or more zones to a load balancer.
    # Returns a list of updated availability zones for the load balancer.
    #
    #  elb.enable_availability_zones_for_load_balancer("test-kd1", "us-east-1c") #=> ["us-east-1a", "us-east-1c"]
    #
    def enable_availability_zones_for_load_balancer(load_balancer_name, *availability_zones)
      availability_zones.flatten!
      request_hash = amazonize_list("AvailabilityZones.member", availability_zones)
      request_hash.merge!( 'LoadBalancerName' => load_balancer_name )
      link = generate_request("EnableAvailabilityZonesForLoadBalancer", request_hash)
      request_info(link, AvailabilityZonesForLoadBalancerParser.new(:logger => @logger))
    end

    # Remove one or more zones from a load balancer.
    # Returns a list of updated availability zones for the load balancer.
    #
    #  elb.disable_availability_zones_for_load_balancer("test-kd1", "us-east-1c") #=> ["us-east-1a"]
    #
    def disable_availability_zones_for_load_balancer(load_balancer_name, *availability_zones)
      availability_zones.flatten!
      request_hash = amazonize_list("AvailabilityZones.member", availability_zones)
      request_hash.merge!( 'LoadBalancerName' => load_balancer_name )
      link = generate_request("DisableAvailabilityZonesForLoadBalancer", request_hash)
      request_info(link, AvailabilityZonesForLoadBalancerParser.new(:logger => @logger))
    end

    # Define an application healthcheck for the instances.
    # Returns an updated health check configuration for the load balancer.
    #
    #  hc = elb.configure_health_check( 'test-kd1',
    #                                   { :healthy_threshold => 9,
    #                                     :unhealthy_threshold => 3,
    #                                     :target => "TCP:433",
    #                                     :timeout => 6,
    #                                     :interval => 31}
    #  pp hc #=> { :target=>"TCP:433", :timeout=>6, :interval=>31, :healthy_threshold=>9, :unhealthy_threshold=>3 }
    #
    def configure_health_check(load_balancer_name, health_check)
      request_hash = { 'LoadBalancerName' => load_balancer_name }
      health_check.each{ |key, value| request_hash["HealthCheck.#{key.to_s.camelize}"] = value }
      link = generate_request("ConfigureHealthCheck", request_hash)
      request_info(link, HealthCheckParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Instances
    #-----------------------------------------------------------------

    # Describe the current state of the instances of the specified load balancer.
    # Returns a list of the instances.
    #
    #  elb.describe_instance_health('test-kd1', 'i-8b8bcbe2', 'i-bf8bcbd6') #=>
    #      [ { :description => "Instance registration is still in progress",
    #          :reason_code => "ELB",
    #          :instance_id => "i-8b8bcbe2",
    #          :state       => "OutOfService" },
    #        { :description => "Instance has failed at least the UnhealthyThreshold number of health checks consecutively.",
    #          :reason_code => "Instance",
    #          :instance_id => "i-bf8bcbd6",
    #          :state       => "OutOfService" } ]
    #
    def describe_instance_health(load_balancer_name, *instances)
      instances.flatten!
      request_hash = amazonize_list("Instances.member.?.InstanceId", instances)
      request_hash.merge!( 'LoadBalancerName' => load_balancer_name )
      link = generate_request("DescribeInstanceHealth", request_hash)
      request_info(link, DescribeInstanceHealthParser.new(:logger => @logger))
    end

    # Add new instance(s) to the load balancer.
    # Returns an updated list of instances for the load balancer.
    #
    #  elb.register_instances_with_load_balancer('test-kd1', 'i-8b8bcbe2', 'i-bf8bcbd6') #=> ["i-8b8bcbe2", "i-bf8bcbd6"]
    #
    def register_instances_with_load_balancer(load_balancer_name, *instances)
      instances.flatten!
      request_hash = amazonize_list("Instances.member.?.InstanceId", instances)
      request_hash.merge!( 'LoadBalancerName' => load_balancer_name )
      link = generate_request("RegisterInstancesWithLoadBalancer", request_hash)
      request_info(link, InstancesWithLoadBalancerParser.new(:logger => @logger))
    end

    # Remove instance(s) from the load balancer.
    # Returns an updated list of instances for the load balancer.
    #
    #  elb.deregister_instances_with_load_balancer('test-kd1', 'i-8b8bcbe2') #=> ["i-bf8bcbd6"]
    #
    def deregister_instances_with_load_balancer(load_balancer_name, *instances)
      instances.flatten!
      request_hash = amazonize_list("Instances.member.?.InstanceId", instances)
      request_hash.merge!( 'LoadBalancerName' => load_balancer_name )
      link = generate_request("DeregisterInstancesFromLoadBalancer", request_hash)
      request_info(link, InstancesWithLoadBalancerParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Cookies
    #-----------------------------------------------------------------

    # Generates a stickiness policy with sticky session lifetimes that follow
    # that of an application-generated cookie.
    # This policy can only be associated with HTTP listeners.
    #
    #  elb.create_app_cookie_stickiness_policy('my-load-balancer', 'MyLoadBalancerPolicy', 'MyCookie') #=> true
    #
    def create_app_cookie_stickiness_policy(load_balancer_name, policy_name, cookie_name)
      request_hash = { 'LoadBalancerName' => load_balancer_name,
                       'PolicyName'       => policy_name,
                       'CookieName'       => cookie_name }
      link = generate_request("CreateAppCookieStickinessPolicy", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Generates a stickiness policy with sticky session lifetimes controlled by the
    # lifetime of the browser (user-agent) or a specified expiration period.
    # This policy can only be associated only with HTTP listeners.
    #
    #  elb.create_lb_cookie_stickiness_policy('my-load-balancer', 'MyLoadBalancerPolicy', 60) #=> true
    #
    def create_lb_cookie_stickiness_policy(load_balancer_name, policy_name, cookie_expiration_period)
      request_hash = { 'LoadBalancerName'        => load_balancer_name,
                       'PolicyName'              => policy_name,
                       'CookieExpirationPeriod'  => cookie_expiration_period }
      link = generate_request("CreateLBCookieStickinessPolicy", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Associates, updates, or disables a policy with a listener on the load balancer.
    # Only zero(0) or one(1) policy can be associated with a listener.
    #
    #  elb.set_load_balancer_policies_of_listener('my-load-balancer', 80, 'MyLoadBalancerPolicy') #=> true
    #
    def set_load_balancer_policies_of_listener(load_balancer_name, load_balancer_port, *policy_names)
      policy_names.flatten!
      request_hash = { 'LoadBalancerName' => load_balancer_name,
                       'LoadBalancerPort' => load_balancer_port }
      request_hash.merge!(amazonize_list('PolicyNames.member', policy_names))
      link = generate_request("SetLoadBalancerPoliciesOfListener", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS: Load Balancers
    #-----------------------------------------------------------------
 
    class DescribeLoadBalancersParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{LoadBalancerDescriptions/member$}
          @item = { :availability_zones => [],
                    :health_check       => {},
                    :listeners          => [],
                    :instances          => [],
                    :app_cookie_stickiness_policies => [],
                    :lb_cookie_stickiness_policies  => []}
        when %r{ListenerDescriptions/member$}        then @listener = {:policy_names => []}
        when %r{AppCookieStickinessPolicies/member$} then @app_cookie_stickiness_policy = {}
        when %r{LBCookieStickinessPolicies/member$}  then @lb_cookie_stickiness_policy = {}
        end
      end
      def tagend(name)
        case name
        when 'LoadBalancerName'   then @item[:load_balancer_name]   = @text
        when 'DNSName'            then @item[:dns_name]             = @text
        when 'CreatedTime'        then @item[:created_time]         = @text
        when 'Interval'           then @item[:health_check][:interval]            = @text.to_i
        when 'Target'             then @item[:health_check][:target]              = @text
        when 'HealthyThreshold'   then @item[:health_check][:healthy_threshold]   = @text.to_i
        when 'Timeout'            then @item[:health_check][:timeout]             = @text.to_i
        when 'UnhealthyThreshold' then @item[:health_check][:unhealthy_threshold] = @text.to_i       
        when 'Protocol'           then @listener[:protocol]           = @text
        when 'LoadBalancerPort'   then @listener[:load_balancer_port] = @text
        when 'InstancePort'       then @listener[:instance_port]      = @text
        end
        case full_tag_name
        when %r{AvailabilityZones/member$}    then @item[:availability_zones] << @text
        when %r{Instances/member/InstanceId$} then @item[:instances]          << @text
        when %r{ListenerDescriptions/member$} then @item[:listeners]          << @listener
        when %r{ListenerDescriptions/member/PolicyNames/member$} then @listener[:policy_names] << @text
        when %r{AppCookieStickinessPolicies/member}
          case name
          when 'PolicyName' then @app_cookie_stickiness_policy[:policy_name] = @text
          when 'CookieName' then @app_cookie_stickiness_policy[:cookie_name] = @text
          when 'member'     then @item[:app_cookie_stickiness_policies] << @app_cookie_stickiness_policy
          end
        when %r{LBCookieStickinessPolicies/member}
          case name
          when 'PolicyName'             then @lb_cookie_stickiness_policy[:policy_name] = @text
          when 'CookieExpirationPeriod' then @lb_cookie_stickiness_policy[:cookie_expiration_period] = @text.to_i
          when 'member'                 then @item[:lb_cookie_stickiness_policies] << @lb_cookie_stickiness_policy
          end
        when %r{LoadBalancerDescriptions/member$}
          @item[:availability_zones].sort!
          @item[:instances].sort!
          @result << @item
        end
      end
      def reset
        @result = []
      end
    end

    class CreateLoadBalancerParser < RightAWSParser #:nodoc:
      def tagend(name)
        @result = @text if name == 'DNSName'
      end
    end

    class DeleteLoadBalancerParser < RightAWSParser #:nodoc:
      def tagend(name)
        @result = true if name == 'DeleteLoadBalancerResult'
      end
    end

    class AvailabilityZonesForLoadBalancerParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'member'
          @result << @text
        when 'AvailabilityZones'
          @result.sort!
        end
      end
      def reset
        @result = []
      end
    end

    class HealthCheckParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'Interval'           then @result[:interval]            = @text.to_i
        when 'Target'             then @result[:target]              = @text
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
    #      PARSERS: Instances
    #-----------------------------------------------------------------

    class DescribeInstanceHealthParser < RightAWSParser #:nodoc:
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

    class InstancesWithLoadBalancerParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'InstanceId'
          @result << @text
        when 'Instances'
          @result.sort!
        end
      end
      def reset
        @result = []
      end
    end

  end

end
