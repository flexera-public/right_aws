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

  # = RightAWS::AcwInterface -- RightScale Amazon Cloud Watch interface
  # The RightAws::AcwInterface class provides a complete interface to Amazon Cloud Watch service.
  #
  # For explanations of the semantics of each call, please refer to Amazon's documentation at
  # http://docs.amazonwebservices.com/AmazonCloudWatch/latest/DeveloperGuide/
  #
  class AcwInterface < RightAwsBase
    include RightAwsBaseInterface

    # Amazon ACW API version being used
    API_VERSION       = "2009-05-15"
    DEFAULT_HOST      = "monitoring.amazonaws.com"
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

    # Create a new handle to an ACW account. All handles share the same per process or per thread
    # HTTP connection to Amazon ACW. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol). Example: 'https://monitoring.amazonaws.com/'
    # * <tt>:server</tt>: ACW service host, default: DEFAULT_HOST
    # * <tt>:port</tt>: ACW service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:multi_thread</tt>: true=HTTP connection per thread, false=per process
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    # * <tt>:signature_version</tt>:  The signature version : '0','1' or '2'(default)
    # * <tt>:cache</tt>: true/false(default): list_metrics
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'ACW',
             :default_host        => ENV['ACW_URL'] ? URI.parse(ENV['ACW_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['ACW_URL'] ? URI.parse(ENV['ACW_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['ACW_URL'] ? URI.parse(ENV['ACW_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['ACW_URL'] ? URI.parse(ENV['ACW_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['ACW_API_VERSION'] || API_VERSION },
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
      request_info_impl(:ams_connection, @@bench, request, parser)
    end

    #-----------------------------------------------------------------
    #      MetricStatistics
    #-----------------------------------------------------------------

    # Get time-series data for one or more statistics of given a Metric
    # Returns a hash of stat data.
    #
    #  Options are:
    #
    #    :period       - x*60 seconds interval (where x > 0)
    #    :statistics   - Average, Minimum. Maximum, Sum, Samples
    #    :start_time   - The timestamp of the first datapoint to return, inclusive.
    #    :end_time     - The timestamp to use for determining the last datapoint to return. This is the last datapoint to fetch, exclusive.
    #    :namespace    - The namespace corresponding to the service of interest. For example, AWS/EC2 represents Amazon EC2.
    #    :unit         - Seconds, Percent, Bytes, Bits, Count, Bytes/Second, Bits/Second, Count/Second, and None
    #    :custom_unit  - The user-defined CustomUnit applied to a Measure. Please see the key term Unit.
    #    
    #    :dimentions
    #      Dimensions for EC2 Metrics:
    #      * ImageId              - shows the requested metric for all instances running this EC2 Amazon Machine Image(AMI)
    #      * AvailabilityZone     - shows the requested metric for all instances running in that EC2 Availability Zone
    #      * CapacityGroupName    - shows the requested metric for all instances in the specified capacity group - this dimension is
    #                               only available for EC2 metrics when the instances are in an Amazon Automatic Scaling Service
    #                               Capacity Group
    #      * InstanceId           - shows the requested metric for only the identified instance
    #      * InstanceType         - shows the requested metric for all instances running with that instance type
    #      * Service (required)   - the name of the service that reported the monitoring data - for EC2 metrics, use "EC2"
    #      * Namespace (required) - in private beta, the available metrics are all reported by AWS services, so set this to "AWS"
    #      Dimensions for Load Balancing Metrics:
    #      * AccessPointName      - shows the requested metric for the specified AccessPoint name
    #      * AvailabilityZone     - shows the requested metric for all instances running in that EC2 Availability Zone
    #      * Service (required)   - the name of the service that reported the monitoring data - for LoadBalancing metrics, use "LBS"
    #      * Namespace (required) - in private beta, the available metrics are all reported by AWS services, so set this to "AWS"
    #
    #    :measure_name
    #      EC2 Metrics:
    #      * CPUUtilization  the percentage of allocated EC2 Compute Units that are currently in use on the instance. Units are Percent.
    #      * NetworkIn      - the number of bytes received on all network interfaces by the instance. Units are Bytes.
    #      * NetworkOut     - the number of bytes sent out on all network interfaces by the instance. Units are Bytes.
    #      * DiskReadOps    - completed read operations from all disks available to the instance in one minute. Units are Count/Second.
    #      * DiskWriteOps   - completed writes operations to all disks available to the instance in one minute. Units are Count/Second.
    #      * DiskReadBytes  - bytes read from all disks available to the instance in one minute. Units are Bytes/Second.
    #      * DiskWriteBytes - bytes written to all disks available to the instance in one minute. Units are Bytes/Second.
    #      Load Balancing Metrics:
    #      * Latency            - time taken between a request and the corresponding response as seen by the load balancer. Units are in
    #                             seconds, and the available statistics include minimum, maximum, average and count.
    #      * RequestCount       - number of requests processed by the AccessPoint over the valid period. Units are count per second, and
    #                             the available statistics include minimum, maximum and sum. A valid period can be anything equal to or
    #                             multiple of sixty (60) seconds.
    #      * HealthyHostCount   - number of healthy EndPoints for the valid Period. A valid period can be anything equal to or a multiple
    #                             of sixty (60) seconds. Units are the count of EndPoints. The meaningful statistic for HealthyHostCount
    #                             is the average for an AccessPoint within an Availability Zone. Both Load Balancing dimensions,
    #                             AccessPointName and AvailabilityZone, should be specified when retreiving HealthyHostCount.
    #      * UnHealthyHostCount - number of unhealthy EndPoints for the valid Period. A valid period can be anything equal to or a multiple
    #                             of sixty (60) seconds. Units are the count of EndPoints. The meaningful statistic for UnHealthyHostCount
    #                             is the average for an AccessPoint within Availability Amazon Monitoring Service Developer Guide Load
    #                             Balancing Metrics Version PRIVATE BETA 2009-01-22 19 Zone. Both Load Balancing dimensions, AccessPointName
    #                             and AvailabilityZone, should be specified when retreiving UnHealthyHostCount.
    #
    def get_metric_statistics(options={})
      # Period (60 sec by default)
      period = (options[:period] && options[:period].to_i) || 60
      # Statistics ('Average' by default)
      statistics = Array(options[:statistics]).flatten
      statistics = statistics.blank? ? ['Average'] : statistics.map{|statistic| statistic.to_s.capitalize }
      # Times (5.min.ago up to now by default)
      start_time = options[:start_time] || (Time.now.utc - 5*60)
      start_time = start_time.utc.strftime("%Y-%m-%dT%H:%M:%S+00:00") if start_time.is_a?(Time)
      end_time = options[:end_time] || Time.now.utc
      end_time = end_time.utc.strftime("%Y-%m-%dT%H:%M:%S+00:00") if end_time.is_a?(Time)
      # Measure name
      measure_name = options[:measure_name] || 'CPUUtilization'
      # Dimentions (a hash, empty by default)
      dimentions = options[:dimentions] || {}
      #
      request_hash = { 'Period'      => period,
                       'StartTime'   => start_time,
                       'EndTime'     => end_time,
                       'MeasureName' => measure_name }
      request_hash['Unit']       = options[:unit]        if options[:unit]
      request_hash['CustomUnit'] = options[:custom_unit] if options[:custom_unit]
      request_hash['Namespace']  = options[:namespace]   if options[:namespace]
      request_hash.merge!(amazonize_list('Statistics.member', statistics))
      # dimentions
      dim = []
      dimentions.each do |key, values|
        Array(values).each { |value|  dim << [key, value] }
      end
      request_hash.merge!(amazonize_list(['Dimensions.member.?.Name', 'Dimensions.member.?.Value'], dim))
      #
      link = generate_request("GetMetricStatistics", request_hash)
      request_info(link, GetMetricStatisticsParser.new(:logger => @logger))
    end

    # This call returns a list of the valid metrics for which there is recorded data available to a you.
    #
    #  acw.list_metrics #=>
    #      [ { :namespace    => "AWS/ELB",
    #          :measure_name => "HealthyHostCount",
    #          :dimentions   => { "LoadBalancerName"=>"test-kd1" } },
    #        { :namespace    => "AWS/ELB",
    #          :measure_name => "UnHealthyHostCount",
    #          :dimentions   => { "LoadBalancerName"=>"test-kd1" } } ]
    def list_metrics
      link = generate_request("ListMetrics")
      request_cache_or_info :list_metrics, link,  ListMetricsParser, @@bench, true
    end

    #-----------------------------------------------------------------
    #      PARSERS: MetricStatistics
    #-----------------------------------------------------------------

    class GetMetricStatisticsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @item = {} if name == 'member'
      end
      def tagend(name)
        case name
        when 'Timestamp'  then @item[:timestamp]   = @text
        when 'Unit'       then @item[:unit]        = @text
        when 'CustomUnit' then @item[:custom_unit] = @text
        when 'Samples'    then @item[:samples]     = @text.to_f
        when 'Average'    then @item[:average]     = @text.to_f
        when 'Minimum'    then @item[:minimum]     = @text.to_f
        when 'Maximum'    then @item[:maximum]     = @text.to_f
        when 'Sum'        then @item[:sum]         = @text.to_f
        when 'member'     then @result[:datapoints] << @item
        when 'Label'      then @result[:label]     = @text
        end
      end
      def reset
        @result = { :datapoints => [] }
      end
    end

    class ListMetricsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when 'member'
          case @xmlpath
            when @p then @item = { :dimentions => {} }
          end
        end
      end
      def tagend(name)
        case name
        when 'MeasureName' then @item[:measure_name] = @text
        when 'Namespace'   then @item[:namespace] = @text
        when 'Name'        then @dname  = @text
        when 'Value'       then @dvalue = @text
        when 'member'
          case @xmlpath
          when "#@p/member/Dimensions" then @item[:dimentions][@dname] = @dvalue
          when @p then @result << @item
          end
        end
      end
      def reset
        @p      = 'ListMetricsResponse/ListMetricsResult/Metrics'
        @result = []
      end
    end

  end

end
