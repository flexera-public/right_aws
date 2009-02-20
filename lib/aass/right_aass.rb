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

  # Amazon Auto Scaling System
  class Aass < RightAwsBase
    include RightAwsBaseInterface

    # Amazon AASS API version being used
    API_VERSION       = "2009-01-22"
    DEFAULT_HOST      = "csls.amazonaws.com"
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

    # Create a new handle to an CSLS account. All handles share the same per process or per thread
    # HTTP connection to Amazon CSLS. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol and :region). Example: 'https://eu-west-1.AASS.amazonaws.com/'
    # * <tt>:server</tt>: AASS service host, default: DEFAULT_HOST
    # * <tt>:region</tt>: AASS region (North America by default)
    # * <tt>:port</tt>: AASS service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:multi_thread</tt>: true=HTTP connection per thread, false=per process
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    # * <tt>:signature_version</tt>:  The signature version : '0','1' or '2'(default)
    # * <tt>:cache</tt>: true/false(default): caching works for: describe_access_points
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'AASS',
             :default_host        => ENV['AASS_URL'] ? URI.parse(ENV['AASS_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['AASS_URL'] ? URI.parse(ENV['AASS_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['AASS_URL'] ? URI.parse(ENV['AASS_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['AASS_URL'] ? URI.parse(ENV['AASS_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['AASS_API_VERSION'] || API_VERSION },
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
      request_info_impl(:aass_connection, @@bench, request, parser)
    end

    #-----------------------------------------------------------------
    #      Capacity Groups
    #-----------------------------------------------------------------

    # Describe Capacity Groups.
    #
    # Returns a full description of the capacity groups that have the specified IDs from the given list. This
    # includes all EC2 instances that are members of the group. If a list of IDs is not provided, then the
    # full details of all capacity groups is returned.
    #
    def describe_capacity_groups(*capacity_group_names)
      capacity_group_names = capacity_group_names.flatten.compact
      request_hash = amazonize_list('CapacityGroupNames.member', capacity_group_names)
      link = generate_request("DescribeCapacityGroups", request_hash)
      request_cache_or_info(:describe_capacity_groups, link,  DescribeCapacityGroupsParser, @@bench, capacity_group_names.blank?)
    end

    # Creates a new Capacity Group with the specified name.
    # Returns +true+ or raises an exception.
    #
    # Options: +:min_size+, +:max_size+, +:default_cooldown+
    #
    #  aass.create_capacity_group('kd.CentOS.array', 'CentOS.5.1', 'us-east-1c',
    #                             :min_size => 2,
    #                             :max_size => 5)  #=> true
    #
    # PS availability_zones is restricted to 1 item only (it is not clear from Amazon's docs: is it for beta or forever?)
    #
    def create_capacity_group(capacity_group_name, launch_configuration_name, availability_zones, options={})
      options[:min_size]         ||= 1
      options[:max_size]         ||= 20
      options[:default_cooldown] ||= 0
      availability_zones = availability_zones.to_a
      request_hash = amazonize_list('AvailabilityZones.member', availability_zones)
      request_hash.merge!( 'CapacityGroupName'       =>  capacity_group_name,
                           'LaunchConfigurationName' => launch_configuration_name,
                           'MinSize'                 => options[:min_size],
                           'MaxSize'                 => options[:max_size],
                           'DefaultCooldown'         => options[:default_cooldown] )
      link = generate_request("CreateCapacityGroup", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Deletes all configuration for this Capacity Group and also deletes the group. EC2 instances
    # that are currently provisioned and part of this capacity group will remain provisioned but are now
    # unmanaged. The load balancer state does not change. If you wish to change the load balancer state,
    # then you should set desired size to zero on the group before making this call to delete. Monitoring
    # for each host will continue, except now data from each host will not be tagged with capacity group
    # information.
    #
    # Returns +true+ or raises an exception.
    #
    def delete_capacity_group(capacity_group_name)
      link = generate_request('DeleteCapacityGroup', 'CapacityGroupName' => capacity_group_name)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Adjusts the desired size of the Capacity Group by using scaling actions, as necessary. When
    # adjusting the size of the group downward, it is not possible to define which EC2 instances will be
    # terminated. This also applies to any auto-scaling decisions that might result in the termination of
    # instances.
    #
    # Returns +true+ or raises an exception.
    #
    #  aass.set_desired_capacity('kd.CentOS.array',3) #=> 3
    #
    def set_desired_capacity(capacity_group_name, desired_capacity)
      link = generate_request('SetDesiredCapacity', 'CapacityGroupName' => capacity_group_name,
                                                    'DesiredCapacity'   => desired_capacity )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Updates the configuration for the given Capacity Group. If LaunchConfigurationName is
    # left empty, then the current Launch Configuration is unchanged. If MaxSize is lower than the
    # current size, then there will be an implicit call to SetDesiredCapacity (p. 44) to set the group to the new
    # MaxSize. The same is true for MinSize. The parameters MinSize and MaxSize are optional and
    # may be left empty, in which case the current settings will remain unchanged.
    # 
    # The new settings are registered upon the completion of this call. Note that if there are triggers that are
    # implicitly involved in the update, those triggers may not fire immediately. Also note that any launch
    # configuration settings will take effect on any triggers after this call returns. However, triggers that are
    # current in progress may not be affected.
    #
    # Returns +true+ or raises an exception.
    #
    # Options: +:launch_configuration_name+, +:min_size+, +:max_size+, +:default_cooldown+
    #
    #  aass.update_capacity_group('kd.CentOS.array', :min_size => 1, :max_size => 4) #=> true
    #
    def update_capacity_group(capacity_group_name, options={})
      availability_zones = availability_zones.to_a
      request_hash = { 'CapacityGroupName' => capacity_group_name }
      request_hash['LaunchConfigurationName'] = options[:launch_configuration_name] if options[:launch_configuration_name]
      request_hash['MinSize']                 = options[:min_size]                  if options[:min_size]
      request_hash['MaxSize']                 = options[:max_size]                  if options[:max_size]
      request_hash['DefaultCooldown']         = options[:default_cooldown]          if options[:default_cooldown]
      link = generate_request("UpdateCapacityGroup", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Capacity Activities
    #-----------------------------------------------------------------

    # Describe Capacity Activities.
    #
    # Returns the capacity activities specified for the given group. If the input list is empty, all the activities
    # from the past ten minutes will be returned. Activities will be sorted by completion time. Activities that
    # have no completion time will be considered as using the most recent possible time.
    #
    #  aass.describe_capacity_activities('kd.CentOS.array') #=>
    #    {:activity_id       => "c334e97d-e056-459c-bc0b-a01a5e8c3ad8",
    #      :progress         => 0,
    #      :routing_protocol => "Launching a new EC2 instance. Status Reason: Launching ec2 instance failed",
    #      :status_code      => "Failed",
    #      :cause            => "Automated Capacity Adjustment",
    #      :start_time       => Fri Feb 20 08:40:26 +0300 2009},
    #     {:activity_id      => "421e6b10-e122-4d47-86ef-082ed64db4a8",
    #      :progress         => 0,
    #      :routing_protocol => "Launching a new EC2 instance. Status Reason: Launching ec2 instance failed",
    #      :status_code      => "Failed",
    #      :cause            => "Automated Capacity Adjustment",
    #      :start_time       => Fri Feb 20 08:35:14 +0300 2009}, ... ]
    #
    def describe_capacity_activities(capacity_group_name, *activity_ids)
      activity_ids = activity_ids.flatten.compact
      request_hash = amazonize_list('ActivityIds.member', activity_ids)
      request_hash.merge!('CapacityGroupName' => capacity_group_name)
      link = generate_request('DescribeCapacityActivities', request_hash)
      request_cache_or_info(:describe_capacity_activities, link,  DescribeCapacityActivitiesParser, @@bench, activity_ids.blank?)
    end

    #-----------------------------------------------------------------
    #      Instance and Instance Workflow Operations
    #-----------------------------------------------------------------

    # This call will remove any load balancer EndPoints currently pointing to the host that were previously
    # configured, and then terminate the EC2 instance. Optionally, the desired group size can be adjusted. If
    # set to true, the default, the Capacity Group (p. 7) size will decrease by one.
    #
    # This call simply registers a termination request. The termination of the instance may not happen
    # immediately. The load balancer removal of endpoints is subject to the guarantees made by the load
    # balancer calls used.
    #
    # Returns the activity to terminate the instance.
    #
    def terminate_instance(instance_id, should_decrement_desired_capacity=true)
      request_hash = { 'InstanceId' => instance_id }
      request_hash['ShouldDecrementDesiredCapacity'] = should_decrement_desired_capacity
      link = generate_request('TerminateInstance', request_hash )
      request_info(link, DescribeCapacityActivitiesParser.new(:logger => @logger)).first
    end

    #-----------------------------------------------------------------
    #      Launch Configuration Operations
    #-----------------------------------------------------------------

    # Creates a new Launch Configuration. Please note that the launch configuration name used must
    # be unique, within the scope of your Amazon Web Services AWS account, and the maximum limit of
    # launch configurations must not yet have been met, or else the call will fail.
    #
    # Once created, the new launch configuration is available for immediate use.
    #
    # Options: +:access_point_names+, +:security_groups+, +:block_device_mappings+, +:key_name+,
    # +:user_data+, +:kernel_id+, +:ramdisk_id+
    #
    #  aass.create_launch_configuration('CentOS.5.1', 'ami-08f41161', 'm1.small',
    #                                   :key_name        => 'default',
    #                                   :security_groups => ['default','kd1'],
    #                                   :user_data       => 'Olalah!!!!' ) #=> true
    #
    def create_launch_configuration(launch_configuration_name, image_id, instance_type, options={})
      availability_zones = availability_zones.to_a
      request_hash = { 'LaunchConfigurationName' => launch_configuration_name,
                       'ImageId'                 => image_id,
                       'InstanceType'            => instance_type }
      request_hash.merge!(amazonize_list('AccessPointNames.member',    options[:access_point_names]))    unless options[:access_point_names].blank?
      request_hash.merge!(amazonize_list('SecurityGroups.member',      options[:security_groups]))       unless options[:security_groups].blank?
      request_hash.merge!(amazonize_list('BlockDeviceMappings.member', options[:block_device_mappings])) unless options[:block_device_mappings].blank?
      request_hash['KeyName']   = options[:key_name]   if options[:key_name]
      request_hash['UserData']  = options[:user_data]  if options[:user_data]
      request_hash['KernelId']  = options[:kernel_id]  if options[:kernel_id]
      request_hash['RamdiskId'] = options[:ramdisk_id] if options[:ramdisk_id]
      link = generate_request("CreateLaunchConfiguration", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Returns a full description of the launch configurations given the specified names. If no names
    # are specified, then the full details of all launch configurations are returned.
    # 
    #  aass.ass.describe_launch_configurations #=>
    #    [{:key_name                  => "default",
    #      :user_data                 => "Olalah!!!!",
    #      :block_device_mappings     => [],
    #      :image_id                  => "ami-08f41161",
    #      :launch_configuration_name => "CentOS.5.1",
    #      :created_time              => Fri Feb 20 08:09:58 UTC 2009,
    #      :instance_type             => "m1.small",
    #      :kernel_id                 => "",
    #      :access_point_names        => [],
    #      :ramdisk_id                => "",
    #      :security_groups           => ["default", "kd1"] }]
    #
    def describe_launch_configurations(*launch_configuration_names)
      launch_configuration_names = launch_configuration_names.flatten.compact
      link = generate_request('DescribeLaunchConfigurations', amazonize_list('LaunchConfigurationNames.member', launch_configuration_names))
      request_cache_or_info(:describe_launch_configurations, link,  DescribeLaunchConfigurationsParser, @@bench, launch_configuration_names.blank?)
    end

    # Delete launch configuration.
    # Returns +true+ or an exception.
    #
    #   aass.delete_launch_configuration('CentOS.5.1') #=> true
    #
    def delete_launch_configuration(launch_configuration_name)
      link = generate_request('DeleteLaunchConfiguration', 'LaunchConfigurationName' => launch_configuration_name)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Trigger Operations
    #-----------------------------------------------------------------

    # Create or update specified trigger.
    #
    # This call sets the parameters that govern when and how to scale a Capacity Group (p. 7). Once a
    # scaling out activity completes, there will be a specified cooldown period before incrementing breach
    # counts for scale in or scale out actions. The cooldown period is set during creation of the capacity
    # group (or during an update call to the capacity group).
    #
    # If the Trigger (p. 7), within the scope of the caller's Amazon Web Services (AWS) account, specified
    # already exists, it will be updated. If a trigger with a different name already exists, this call will fail.
    #
    # Returns +true+ or an exception.
    #
    # Options: +:measure_name+, +:statistic+, +:period+, +:lower_threshold+, +:lower_breach_scale_increment+,
    # +:upper_threshold+, +:upper_breach_scale_increment+, +:dimentions+, +:breach_duration+, +:unit+, +:custom_unit+
    #
    #  aass.create_or_update_scaling_trigger('kd.tr.1', 'kd.CentOS.array',
    #                                        :measure_name => 'CPUUtilization',
    #                                        :statistic => :average,
    #                                        :dimentions => {
    #                                           'CapacityGroupName' => 'kd.CentOS.array',
    #                                           'Namespace' => 'AWS',
    #                                           'Service' => 'EC2' },
    #                                        :period => 60,
    #                                        :lower_threshold => 0,
    #                                        :lower_breach_scale_increment => -1,
    #                                        :upper_threshold => 60,
    #                                        :upper_breach_scale_increment => 1,
    #                                        :breach_duration => 300 ) #=> true
    #
    def create_or_update_scaling_trigger(trigger_name, capacity_group_name, options={})
      request_hash = { 'TriggerName'               => trigger_name,
                       'CapacityGroupName'         => capacity_group_name,
                       'MeasureName'               => options[:measure_name],
                       'Statistic'                 => options[:statistic].to_s.capitalize,
                       'Period'                    => options[:period],
                       'LowerThreshold'            => options[:lower_threshold],
                       'LowerBreachScaleIncrement' => options[:lower_breach_scale_increment],
                       'UpperThreshold'            => options[:upper_threshold],
                       'UpperBreachScaleIncrement' => options[:upper_breach_scale_increment],
                       'BreachDuration'            => options[:breach_duration] }
      request_hash['Unit']       = options[:unit]        if options[:unit]
      request_hash['CustomUnit'] = options[:custom_unit] if options[:custom_unit]
      dimentions = []
      (options[:dimentions] || {}).each do |key, values|
        values.to_a.each { |value| dimentions << [key, value] }
      end
      request_hash.merge!(amazonize_list(['Dimensions.member.?.Name', 'Dimensions.member.?.Value'], dimentions))
      #
      link = generate_request("CreateOrUpdateScalingTrigger", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Describe tringgers.
    # Returns a full description of the trigger in the specified Capacity Group.
    #
    #  aass.describe_triggers('kd.CentOS.array') #=>
    #    [{:dimensions =>
    #         {"Namespace"         => "AWS",
    #          "CapacityGroupName" => "kd.CentOS.array",
    #          "Service"           => "EC2"},
    #      :lower_threshold              => 0,
    #      :lower_breach_scale_increment => -1,
    #      :capacity_group_name          => "kd.CentOS.array",
    #      :statistic                    => "Average",
    #      :status                       => "NoData",
    #      :upper_threshold              => 60.0,
    #      :period                       => 60,
    #      :created_time                 => Fri Feb 20 09:00:10 UTC 2009,
    #      :upper_breach_scale_increment => 1,
    #      :breach_duration              => 300,
    #      :trigger_name                 => "kd.tr.1",
    #      :measure_name                 => "CPUUtilization"}]

    def describe_triggers(capacity_group_name)
      link = generate_request("DescribeTriggers", 'CapacityGroupName' => capacity_group_name)
      request_info(link, DescribeTriggersParser.new(:logger => @logger))
    end

    # Delete specified trigger.
    # Returns +true+ or an exception.
    #
    #  aass.delete_trigger('kd.tr.1', 'kd.CentOS.array') #=> true
    #
    def delete_trigger(trigger_name, capacity_group_name)
      link = generate_request('DeleteTrigger', 'TriggerName'       => trigger_name,
                                               'CapacityGroupName' => capacity_group_name)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS: Capacity Activity
    #-----------------------------------------------------------------

    class DescribeCapacityActivitiesParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @item = {} if name == 'member'
      end
      def tagend(name)
        case name
        when 'ActivityId'    then @item[:activity_id]    = @text
        when 'StartTime'     then @item[:start_time]     = Time::parse(@text)
        when 'EndTime'       then @item[:end_time]       = Time::parse(@text)
        when 'Progress'      then @item[:progress]       = @text.to_i
        when 'StatusCode'    then @item[:status_code]    = @text
        when 'StatusMessage' then @item[:status_message] = @text
        when 'Cause'         then @item[:cause]          = @text
        when 'Description'   then @item[:description]    = @text
        when 'member'        then @result << @item
        end
      end
      def reset
        @result = []
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Capacity Groups
    #-----------------------------------------------------------------

    class DescribeCapacityGroupsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when 'member'
          case @xmlpath
            when 'DescribeCapacityGroupsResponse/DescribeCapacityGroupsResult/CapacityGroups'
              @item = { :availability_zones => [],
                        :instances          => [] }
            when 'DescribeCapacityGroupsResponse/DescribeCapacityGroupsResult/CapacityGroups/member/Instances'
              @instance = {}
          end
        end
      end
      def tagend(name)
        case name
        when 'CreatedTime'             then @item[:created_time]              = Time::parse(@text)
        when 'MinSize'                 then @item[:min_size]                  = @text.to_i
        when 'MaxSize'                 then @item[:max_size]                  = @text.to_i
        when 'DesiredCapacity'         then @item[:desired_capacity]          = @text.to_i
        when 'DefaultCooldown'         then @item[:default_cooldown]          = @text.to_i
        when 'LaunchConfigurationName' then @item[:launch_configuration_name] = @text
        when 'CapacityGroupName'       then @item[:capacity_group_name]       = @text
        when 'InstanceId'              then @instance[:instance_id]     = @text
        when 'LifecycleState'          then @instance[:lifecycle_state] = @text
        when 'member'
          case @xmlpath
          when 'DescribeCapacityGroupsResponse/DescribeCapacityGroupsResult/CapacityGroups/member/Instances'
            @item[:instances] << @instance
          when 'DescribeCapacityGroupsResponse/DescribeCapacityGroupsResult/CapacityGroups/member/AvailabilityZones'
            @item[:availability_zones] << @text
          when 'DescribeCapacityGroupsResponse/DescribeCapacityGroupsResult/CapacityGroups'
            @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Launch Configurations
    #-----------------------------------------------------------------

    class DescribeLaunchConfigurationsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when 'member'
          case @xmlpath
            when 'DescribeLaunchConfigurationsResponse/DescribeLaunchConfigurationsResult/LaunchConfigurations'
              @item = { :access_point_names    => [],
                        :block_device_mappings => [],
                        :security_groups       => [] }
          end
        end
      end
      def tagend(name)
        case name
        when 'CreatedTime'             then @item[:created_time]              = Time::parse(@text)
        when 'InstanceType'            then @item[:instance_type]             = @text
        when 'KeyName'                 then @item[:key_name]                  = @text
        when 'ImageId'                 then @item[:image_id]                  = @text
        when 'KernelId'                then @item[:kernel_id]                 = @text
        when 'RamdiskId'               then @item[:ramdisk_id]                = @text
        when 'LaunchConfigurationName' then @item[:launch_configuration_name] = @text
        when 'UserData'                then @item[:user_data]                 = @text
        when 'member'
          case @xmlpath
          when 'DescribeLaunchConfigurationsResponse/DescribeLaunchConfigurationsResult/LaunchConfigurations/member/BlockDeviceMappings'
            @item[:block_device_mappings] << @text
          when 'DescribeLaunchConfigurationsResponse/DescribeLaunchConfigurationsResult/LaunchConfigurations/member/SecurityGroups'
            @item[:security_groups] << @text
          when 'DescribeLaunchConfigurationsResponse/DescribeLaunchConfigurationsResult/LaunchConfigurations/member/AccessPointNames'
            @item[:access_point_names] << @text
          when 'DescribeLaunchConfigurationsResponse/DescribeLaunchConfigurationsResult/LaunchConfigurations'
            @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Triggers
    #-----------------------------------------------------------------

    class DescribeTriggersParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when 'member'
          case @xmlpath
          when 'DescribeTriggersResponse/DescribeTriggersResult/Triggers'
            @item = { :dimensions => {} }
          when 'DescribeTriggersResponse/DescribeTriggersResult/Triggers/member/Dimensions'
            @dimension = {}
          end
        end
      end
      def tagend(name)
        case name
        when 'CapacityGroupName'         then @item[:capacity_group_name]          = @text
        when 'MeasureName'               then @item[:measure_name]                 = @text
        when 'CreatedTime'               then @item[:created_time]                 = Time::parse(@text)
        when 'BreachDuration'            then @item[:breach_duration]              = @text.to_i
        when 'UpperBreachScaleIncrement' then @item[:upper_breach_scale_increment] = @text.to_i
        when 'UpperThreshold'            then @item[:upper_threshold]              = @text.to_f
        when 'LowerThreshold'            then @item[:lower_threshold]              = @text.to_f
        when 'LowerBreachScaleIncrement' then @item[:lower_breach_scale_increment] = @text.to_i
        when 'Period'                    then @item[:period]                       = @text.to_i
        when 'Status'                    then @item[:status]                       = @text
        when 'TriggerName'               then @item[:trigger_name]                 = @text
        when 'Statistic'                 then @item[:statistic]                    = @text
        when 'Unit'                      then @item[:unit]                         = @text
        when 'Name'                      then @dimension[:name]                    = @text
        when 'Value'                     then @dimension[:value]                   = @text
        when 'member'
          case @xmlpath
          when 'DescribeTriggersResponse/DescribeTriggersResult/Triggers/member/Dimensions'
            @item[:dimensions][@dimension[:name]] = @dimension[:value]
          when 'DescribeTriggersResponse/DescribeTriggersResult/Triggers'
            @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end
  end

end
