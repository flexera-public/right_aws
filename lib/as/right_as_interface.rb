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

  # = RightAWS::AsInterface -- RightScale Amazon Auto Scaling interface
  # The RightAws::AsInterface class provides a complete interface to Amazon Auto Scaling service.
  #
  # For explanations of the semantics of each call, please refer to Amazon's documentation at
  # http://docs.amazonwebservices.com/AutoScaling/latest/DeveloperGuide/
  #
  # Create an interface handle:
  #
  #  as = RightAws::AsInterface.new(aws_access_key_id, aws_security_access_key)
  #
  # Create a launch configuration:
  #
  #  as.create_launch_configuration('CentOS.5.1-c', 'ami-08f41161', 'm1.small',
  #                                 :key_name        => 'kd-moo-test',
  #                                 :security_groups => ['default'],
  #                                 :user_data       => "Woohoo: CentOS.5.1-c" )
  #
  # Create an AutoScaling group:
  #
  #  as.create_auto_scaling_group('CentOS.5.1-c-array', 'CentOS.5.1-c', 'us-east-1c',
  #                               :min_size => 2,
  #                               :max_size => 5)
  #
  # Create a new trigger:
  # 
  #  as.create_or_update_scaling_trigger('kd.tr.1', 'CentOS.5.1-c-array',
  #                                      :measure_name => 'CPUUtilization',
  #                                      :statistic => :average,
  #                                      :dimensions => {
  #                                         'AutoScalingGroupName' => 'CentOS.5.1-c-array',
  #                                         'Namespace' => 'AWS',
  #                                         'Service' => 'EC2' },
  #                                      :period => 60,
  #                                      :lower_threshold => 5,
  #                                      :lower_breach_scale_increment => -1,
  #                                      :upper_threshold => 60,
  #                                      :upper_breach_scale_increment => 1,
  #                                      :breach_duration => 300 )
  #
  # Describe scaling activity:
  #
  #  as.incrementally_describe_scaling_activities('CentOS.5.1-c-array') #=> List of activities
  #
  # Describe the Auto Scaling group status:
  #
  #  as.describe_auto_scaling_groups('CentOS.5.1-c-array') #=> Current group status
  #
  class AsInterface < RightAwsBase
    include RightAwsBaseInterface

    # Amazon AS API version being used
    API_VERSION       = '2009-05-15'
    DEFAULT_HOST      = 'autoscaling.amazonaws.com'
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

    # Create a new handle to an CSLS account. All handles share the same per process or per thread
    # HTTP connection to Amazon CSLS. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol). Example: 'https://autoscaling.amazonaws.com/'
    # * <tt>:server</tt>: AS service host, default: DEFAULT_HOST
    # * <tt>:port</tt>: AS service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:multi_thread</tt>: true=HTTP connection per thread, false=per process
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    # * <tt>:signature_version</tt>:  The signature version : '0','1' or '2'(default)
    # * <tt>:cache</tt>: true/false(default): describe_auto_scaling_groups
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'AS',
             :default_host        => ENV['AS_URL'] ? URI.parse(ENV['AS_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['AS_URL'] ? URI.parse(ENV['AS_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['AS_URL'] ? URI.parse(ENV['AS_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['AS_URL'] ? URI.parse(ENV['AS_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['AS_API_VERSION'] || API_VERSION },
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
    #      Auto Scaling Groups
    #-----------------------------------------------------------------

    # Describe auto scaling groups.
    # Returns a full description of the AutoScalingGroups from the given list.
    # This includes all EC2 instances that are members of the group. If a list
    # of names is not provided, then the full details of all AutoScalingGroups
    # is returned. This style conforms to the EC2 DescribeInstances API behavior.
    #
    def describe_auto_scaling_groups(*auto_scaling_group_names)
      auto_scaling_group_names = auto_scaling_group_names.flatten.compact
      request_hash = amazonize_list('AutoScalingGroupNames.member', auto_scaling_group_names)
      link = generate_request("DescribeAutoScalingGroups", request_hash)
      request_cache_or_info(:describe_auto_scaling_groups, link,  DescribeAutoScalingGroupsParser, @@bench, auto_scaling_group_names.blank?)
    end

    # Creates a new auto scaling group with the specified name.
    # Returns +true+ or raises an exception.
    #
    # Options: +:min_size+, +:max_size+, +:cooldown+, +:load_balancer_names+
    #
    #  as.create_auto_scaling_group('CentOS.5.1-c-array', 'CentOS.5.1-c', 'us-east-1c',
    #                               :min_size => 2,
    #                               :max_size => 5)  #=> true
    #
    # Amazon's notice: Constraints: Restricted to one Availability Zone
    def create_auto_scaling_group(auto_scaling_group_name, launch_configuration_name, availability_zones, options={})
      options[:min_size] ||= 1
      options[:max_size] ||= 20
      options[:cooldown] ||= 0
      request_hash = amazonize_list('AvailabilityZones.member', availability_zones)
      request_hash.merge!( amazonize_list('LoadBalancerNames', options[:load_balancer_names]) )
      request_hash.merge!( 'AutoScalingGroupName'    => auto_scaling_group_name,
                           'LaunchConfigurationName' => launch_configuration_name,
                           'MinSize'                 => options[:min_size],
                           'MaxSize'                 => options[:max_size],
                           'Cooldown'                => options[:cooldown] )
      link = generate_request("CreateAutoScalingGroup", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Deletes all configuration for this auto scaling group and also deletes the group.
    # Returns +true+ or raises an exception.
    #
    def delete_auto_scaling_group(auto_scaling_group_name)
      link = generate_request('DeleteAutoScalingGroup', 'AutoScalingGroupName' => auto_scaling_group_name)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Adjusts the desired size of the Capacity Group by using scaling actions, as necessary. When
    # adjusting the size of the group downward, it is not possible to define which EC2 instances will be
    # terminated. This also applies to any auto-scaling decisions that might result in the termination of
    # instances.
    #
    # Returns +true+ or raises an exception.
    #
    #  as.set_desired_capacity('CentOS.5.1-c',3) #=> 3
    #
    def set_desired_capacity(auto_scaling_group_name, desired_capacity)
      link = generate_request('SetDesiredCapacity', 'AutoScalingGroupName' => auto_scaling_group_name,
                                                    'DesiredCapacity'      => desired_capacity )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Updates the configuration for the given AutoScalingGroup. If MaxSize is lower than the current size,
    # then there will be an implicit call to SetDesiredCapacity to set the group to the new MaxSize. The
    # same is true for MinSize there will also be an implicit call to SetDesiredCapacity. All optional
    # parameters are left unchanged if not passed in the request.
    #
    # The new settings are registered upon the completion of this call. Any launch configuration settings
    # will take effect on any triggers after this call returns. However, triggers that are currently in
    # progress can not be affected. See key term Trigger.
    # 
    # Returns +true+ or raises an exception.
    #
    # Options: +:launch_configuration_name+, +:min_size+, +:max_size+, +:cooldown+, +:availability_zones+.
    # (Amazon's notice: +:availability_zones+ is reserved for future use.)
    #
    #  as.update_auto_scaling_group('CentOS.5.1-c', :min_size => 1, :max_size => 4) #=> true
    #
    def update_auto_scaling_group(auto_scaling_group_name, options={})
      request_hash = amazonize_list('AvailabilityZones.member', options[:availability_zones])
      request_hash['AutoScalingGroupName']    = auto_scaling_group_name
      request_hash['LaunchConfigurationName'] = options[:launch_configuration_name] if options[:launch_configuration_name]
      request_hash['MinSize']  = options[:min_size] if options[:min_size]
      request_hash['MaxSize']  = options[:max_size] if options[:max_size]
      request_hash['Cooldown'] = options[:cooldown] if options[:cooldown]
      link = generate_request("UpdateAutoScalingGroup", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Scaling Activities
    #-----------------------------------------------------------------

    # Describe all Scaling Activities.
    #
    #  describe_scaling_activities('CentOS.5.1-c-array') #=>
    #        [{:cause=>
    #            "At 2009-05-28 10:11:35Z trigger kd.tr.1 breached high threshold value for
    #             CPUUtilization, 10.0, adjusting the desired capacity from 1 to 2.  At 2009-05-28 10:11:35Z
    #             a breaching trigger explicitly set group desired capacity changing the desired capacity
    #             from 1 to 2.  At 2009-05-28 10:11:40Z an instance was started in response to a difference
    #             between desired and actual capacity, increasing the capacity from 1 to 2.",
    #          :activity_id=>"067c9abb-f8a7-4cf8-8f3c-dc6f280457c4",
    #          :progress=>0,
    #          :description=>"Launching a new EC2 instance",
    #          :status_code=>"InProgress",
    #          :start_time=>Thu May 28 10:11:40 UTC 2009},
    #         {:end_time=>Thu May 28 09:35:23 UTC 2009,
    #          :cause=>
    #            "At 2009-05-28 09:31:21Z a user request created an AutoScalingGroup changing the desired
    #             capacity from 0 to 1.  At 2009-05-28 09:32:35Z an instance was started in response to a
    #             difference between desired and actual capacity, increasing the capacity from 0 to 1.",
    #          :activity_id=>"90d506ba-1b75-4d29-8739-0a75b1ba8030",
    #          :progress=>100,
    #          :description=>"Launching a new EC2 instance",
    #          :status_code=>"Successful",
    #          :start_time=>Thu May 28 09:32:35 UTC 2009}]}
    #
    def describe_scaling_activities(auto_scaling_group_name, *activity_ids)
      result = []
      incrementally_describe_scaling_activities(auto_scaling_group_name, *activity_ids) do |response|
        result += response[:scaling_activities]
        true
      end
      result
    end

    # Incrementally describe Scaling Activities.
    # Returns the scaling activities specified for the given group. If the input list is empty, all the
    # activities from the past six weeks will be returned. Activities will be sorted by completion time.
    # Activities that have no completion time will be considered as using the most recent possible time.
    #
    # Optional params: +:max_records+, +:next_token+.
    #
    #  # get max 100 first activities
    #  as.incrementally_describe_scaling_activities('CentOS.5.1-c-array') #=>
    #      {:scaling_activities=>
    #        [{:cause=>
    #            "At 2009-05-28 10:11:35Z trigger kd.tr.1 breached high threshold value for
    #             CPUUtilization, 10.0, adjusting the desired capacity from 1 to 2.  At 2009-05-28 10:11:35Z
    #             a breaching trigger explicitly set group desired capacity changing the desired capacity
    #             from 1 to 2.  At 2009-05-28 10:11:40Z an instance was started in response to a difference
    #             between desired and actual capacity, increasing the capacity from 1 to 2.",
    #          :activity_id=>"067c9abb-f8a7-4cf8-8f3c-dc6f280457c4",
    #          :progress=>0,
    #          :description=>"Launching a new EC2 instance",
    #          :status_code=>"InProgress",
    #          :start_time=>Thu May 28 10:11:40 UTC 2009},
    #         {:end_time=>Thu May 28 09:35:23 UTC 2009,
    #          :cause=>
    #            "At 2009-05-28 09:31:21Z a user request created an AutoScalingGroup changing the desired
    #             capacity from 0 to 1.  At 2009-05-28 09:32:35Z an instance was started in response to a
    #             difference between desired and actual capacity, increasing the capacity from 0 to 1.",
    #          :activity_id=>"90d506ba-1b75-4d29-8739-0a75b1ba8030",
    #          :progress=>100,
    #          :description=>"Launching a new EC2 instance",
    #          :status_code=>"Successful",
    #          :start_time=>Thu May 28 09:32:35 UTC 2009}]}
    #
    #  # list by 5 records
    #  incrementally_describe_scaling_activities('CentOS.5.1-c-array', :max_records => 5) do |response|
    #    puts response.inspect
    #    true
    #  end
    #
    def incrementally_describe_scaling_activities(auto_scaling_group_name, *activity_ids, &block)
      activity_ids = activity_ids.flatten.compact
      params = activity_ids.last.kind_of?(Hash) ? activity_ids.pop : {}
      request_hash = amazonize_list('ActivityIds.member', activity_ids)
      request_hash['AutoScalingGroupName'] = auto_scaling_group_name
      request_hash['MaxRecords'] = params[:max_records] if params[:max_records]
      request_hash['NextToken']  = params[:next_token]  if params[:next_token]
      last_response = nil
      loop do
        link = generate_request("DescribeScalingActivities", request_hash)
        last_response = request_info( link,  DescribeScalingActivitiesParser.new(:logger => @logger))
        request_hash['NextToken'] = last_response[:next_token]
        break unless block && block.call(last_response) && !last_response[:next_token].blank?
      end
      last_response
    end

    #-----------------------------------------------------------------
    #      Instance and Instance Workflow Operations
    #-----------------------------------------------------------------

    # This call will terminate the specified Instance. Optionally, the desired group size can be adjusted.
    # If set to true, the default, the AutoScalingGroup size will decrease by one. If the AutoScalingGroup
    # is associated with a LoadBalancer, the system will deregister the instance before terminating it.
    # This call simply registers a termination request. The termination of the instance can not happen
    # immediately.
    #
    # Returns the activity to terminate the instance.
    #
    def terminate_instance_in_auto_scaling_group(instance_id, should_decrement_desired_capacity=true)
      request_hash = { 'InstanceId' => instance_id }
      request_hash['ShouldDecrementDesiredCapacity'] = should_decrement_desired_capacity
      link = generate_request('TerminateInstanceInAutoScalingGroup', request_hash )
      request_info(link, DescribeScalingActivitiesParser.new(:logger => @logger))[:scaling_activities].first
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
    # Options: +:security_groups+, +:block_device_mappings+, +:key_name+,
    # +:user_data+, +:kernel_id+, +:ramdisk_id+
    #
    #  as.create_launch_configuration('kd: CentOS.5.1-c.1', 'ami-08f41161', 'c1.medium',
    #    :key_name        => 'tim',
    #    :security_groups => ['default'],
    #    :user_data       => "Woohoo: CentOS.5.1-c",
    #    :block_device_mappings => [ { :device_name     => '/dev/sdk',
    #                                  :ebs_snapshot_id => 'snap-145cbc7d',
    #          :ebs_delete_on_termination => true,
    #          :ebs_volume_size => 3,
    #          :virtual_name => 'ephemeral2'
    #                                } ]
    #    ) #=> true
    #
    def create_launch_configuration(launch_configuration_name, image_id, instance_type, options={})
      request_hash = { 'LaunchConfigurationName' => launch_configuration_name,
                       'ImageId'                 => image_id,
                       'InstanceType'            => instance_type }
      request_hash.merge!(amazonize_list('SecurityGroups.member',      options[:security_groups]))       unless options[:security_groups].blank?
      request_hash.merge!(amazonize_block_device_mappings(options[:block_device_mappings], 'BlockDeviceMappings.member'))
      request_hash['KeyName']   = options[:key_name]   if options[:key_name]
      request_hash['UserData']  = Base64.encode64(options[:user_data]).delete("\n") unless options[:user_data].blank? if options[:user_data]
      request_hash['KernelId']  = options[:kernel_id]  if options[:kernel_id]
      request_hash['RamdiskId'] = options[:ramdisk_id] if options[:ramdisk_id]
      link = generate_request("CreateLaunchConfiguration", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end


    # Describe all Launch Configurations.
    # Returns an array of configurations.
    #
    #  as.describe_launch_configurations #=>
    #    [{:security_groups=>["default"],
    #      :ramdisk_id=>"",
    #      :user_data=>"V29vaG9vOiBDZW50T1MuNS4xLWM=",
    #      :instance_type=>"c1.medium",
    #      :block_device_mappings=>
    #       [{:virtual_name=>"ephemeral2", :device_name=>"/dev/sdk"}],
    #      :launch_configuration_name=>"kd: CentOS.5.1-c.1",
    #      :created_time=>"2010-03-29T10:00:32.742Z",
    #      :image_id=>"ami-08f41161",
    #      :key_name=>"tim",
    #      :kernel_id=>""}, ...]
    #
    def describe_launch_configurations(*launch_configuration_names)
      result = []
      incrementally_describe_launch_configurations(*launch_configuration_names) do |response|
        result += response[:launch_configurations]
        true
      end
      result
    end

    # Incrementally describe Launch Configurations.
    # Returns a full description of the launch configurations given the specified names. If no names
    # are specified, then the full details of all launch configurations are returned.
    # 
    # Optional params: +:max_records+, +:next_token+.
    #
    #  # get max 100 first configurations
    #  as.incrementally_describe_launch_configurations #=>
    #      {:launch_configurations=>
    #        [{:created_time=>Thu May 28 09:31:20 UTC 2009,
    #          :kernel_id=>"",
    #          :launch_configuration_name=>"CentOS.5.1-c",
    #          :ramdisk_id=>"",
    #          :security_groups=>["default"],
    #          :key_name=>"kd-moo-test",
    #          :user_data=>"Woohoo: CentOS.5.1-c-array",
    #          :image_id=>"ami-08f41161",
    #          :block_device_mappings=>[],
    #          :instance_type=>"m1.small"}, ... ]}
    #
    #  # list by 5 records
    #  incrementally_describe_launch_configurations(:max_records => 5) do |response|
    #    puts response.inspect
    #    true
    #  end
    #
    def incrementally_describe_launch_configurations(*launch_configuration_names, &block)
      launch_configuration_names = launch_configuration_names.flatten.compact
      params = launch_configuration_names.last.kind_of?(Hash) ? launch_configuration_names.pop : {}
      request_hash = amazonize_list('LaunchConfigurationNames.member', launch_configuration_names)
      request_hash['MaxRecords'] = params[:max_records] if params[:max_records]
      request_hash['NextToken']  = params[:next_token]  if params[:next_token]
      last_response = nil
      loop do
        link = generate_request("DescribeLaunchConfigurations", request_hash)
        last_response = request_info( link, DescribeLaunchConfigurationsParser.new(:logger => @logger) )
        request_hash['NextToken'] = last_response[:next_token]
        break unless block && block.call(last_response) && !last_response[:next_token].blank?
      end
      last_response
    end

    # Delete launch configuration.
    # Returns +true+ or an exception.
    #
    #   as.delete_launch_configuration('CentOS.5.1') #=> true
    #
    def delete_launch_configuration(launch_configuration_name)
      link = generate_request('DeleteLaunchConfiguration', 'LaunchConfigurationName' => launch_configuration_name)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Trigger Operations
    #-----------------------------------------------------------------

    # Create or update specified trigger.
    # This call sets the parameters that governs when and how to scale an AutoScalingGroup.
    # If the Trigger, within the scope of the caller's AWS account, specified already exists,
    # it will be updated. If a trigger with a different name already exists, this call will fail.
    #
    # Returns +true+ or an exception.
    #
    # Options: +:measure_name+, +:statistic+, +:period+, +:lower_threshold+, +:lower_breach_scale_increment+,
    # +:upper_threshold+, +:upper_breach_scale_increment+, +:dimensions+, +:breach_duration+, +:unit+, +:custom_unit+
    #
    #  as.create_or_update_scaling_trigger('kd.tr.1', 'CentOS.5.1-c-array',
    #                                      :measure_name => 'CPUUtilization',
    #                                      :statistic => :average,
    #                                      :dimensions => {
    #                                         'AutoScalingGroupName' => 'CentOS.5.1-c-array',
    #                                         'Namespace' => 'AWS',
    #                                         'Service' => 'EC2' },
    #                                      :period => 60,
    #                                      :lower_threshold => 5,
    #                                      :lower_breach_scale_increment => -1,
    #                                      :upper_threshold => 60,
    #                                      :upper_breach_scale_increment => 1,
    #                                      :breach_duration => 300 ) #=> true
    #
    def create_or_update_scaling_trigger(trigger_name, auto_scaling_group_name, options={})
      request_hash = { 'TriggerName'               => trigger_name,
                       'AutoScalingGroupName'      => auto_scaling_group_name,
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
      dimensions = []
      (options[:dimensions] || {}).each do |key, values|
        Array(values).each { |value| dimensions << [key, value] }
      end
      request_hash.merge!(amazonize_list(['Dimensions.member.?.Name', 'Dimensions.member.?.Value'], dimensions))
      link = generate_request("CreateOrUpdateScalingTrigger", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Describe triggers.
    # Returns a full description of the trigger in the specified Auto Scaling Group.
    #
    #  as.describe_triggers('CentOS.5.1-c-array') #=>
    #      [{:status=>"HighBreaching",
    #        :breach_duration=>300,
    #        :measure_name=>"CPUUtilization",
    #        :trigger_name=>"kd.tr.1",
    #        :period=>60,
    #        :lower_threshold=>0.0,
    #        :lower_breach_scale_increment=>-1,
    #        :dimensions=>
    #         {"Namespace"=>"AWS",
    #          "AutoScalingGroupName"=>"CentOS.5.1-c-array",
    #          "Service"=>"EC2"},
    #        :statistic=>"Average",
    #        :upper_threshold=>10.0,
    #        :created_time=>Thu May 28 09:48:46 UTC 2009,
    #        :auto_scaling_group_name=>"CentOS.5.1-c-array",
    #        :upper_breach_scale_increment=>1}]
    #
    def describe_triggers(auto_scaling_group_name)
      link = generate_request("DescribeTriggers", 'AutoScalingGroupName' => auto_scaling_group_name)
      request_info(link, DescribeTriggersParser.new(:logger => @logger))
    end

    # Delete specified trigger.
    # Returns +true+ or an exception.
    #
    #  as.delete_trigger('kd.tr.1', 'CentOS.5.1-c-array') #=> true
    #
    def delete_trigger(trigger_name, auto_scaling_group_name)
      link = generate_request('DeleteTrigger', 'TriggerName'          => trigger_name,
                                               'AutoScalingGroupName' => auto_scaling_group_name)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS: Scaling Activity
    #-----------------------------------------------------------------

    class DescribeScalingActivitiesParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when 'member', 'Activity' then @item = {}
        end
      end
      def tagend(name)
        case name
        when 'ActivityId'    then @item[:activity_id]    = @text
        when 'StartTime'     then @item[:start_time]     = @text
        when 'EndTime'       then @item[:end_time]       = @text
        when 'Progress'      then @item[:progress]       = @text.to_i
        when 'StatusCode'    then @item[:status_code]    = @text
        when 'Cause'         then @item[:cause]          = @text
        when 'Description'   then @item[:description]    = @text
        when 'member', 'Activity'  then @result[:scaling_activities] << @item
        when 'NextToken' then @result[:next_token] = @text
        end
      end
      def reset
        @result = { :scaling_activities => []}
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Auto Scaling Groups
    #-----------------------------------------------------------------

    class DescribeAutoScalingGroupsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when 'member'
          case @xmlpath
            when @p then @item = { :instances => [ ],
                                   :availability_zones => [],
                                   :load_balancer_names => [] }
            when "#@p/member/Instances" then @instance = { }
          end
        end
      end
      def tagend(name)
        case name
        when 'CreatedTime'             then @item[:created_time]              = @text
        when 'MinSize'                 then @item[:min_size]                  = @text.to_i
        when 'MaxSize'                 then @item[:max_size]                  = @text.to_i
        when 'DesiredCapacity'         then @item[:desired_capacity]          = @text.to_i
        when 'Cooldown'                then @item[:cooldown]                  = @text.to_i
        when 'LaunchConfigurationName' then @item[:launch_configuration_name] = @text
        when 'AutoScalingGroupName'    then @item[:auto_scaling_group_name]   = @text
        when 'InstanceId'              then @instance[:instance_id]       = @text
        when 'LifecycleState'          then @instance[:lifecycle_state]   = @text
        when 'AvailabilityZone'        then @instance[:availability_zone] = @text
        when 'member'
          case @xmlpath
          when @p then
            @item[:availability_zones].sort!
            @result << @item
          when "#@p/member/AvailabilityZones" then @item[:availability_zones] << @text
          when "#@p/member/LoadBalancerNames" then @item[:load_balancer_names] << @text
          when "#@p/member/Instances"         then @item[:instances] << @instance
          end
        end
      end
      def reset
        @p      = 'DescribeAutoScalingGroupsResponse/DescribeAutoScalingGroupsResult/AutoScalingGroups'
        @result = []
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Launch Configurations
    #-----------------------------------------------------------------

    class DescribeLaunchConfigurationsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/LaunchConfigurations/member$}
          @item = { :block_device_mappings => [],
                    :security_groups       => [] }
        when %r{/BlockDeviceMappings/member$}
          @block_device_mapping = {}
        end
      end
      def tagend(name)
        case name
        when 'CreatedTime'             then @item[:created_time]              = @text
        when 'InstanceType'            then @item[:instance_type]             = @text
        when 'KeyName'                 then @item[:key_name]                  = @text
        when 'ImageId'                 then @item[:image_id]                  = @text
        when 'KernelId'                then @item[:kernel_id]                 = @text
        when 'RamdiskId'               then @item[:ramdisk_id]                = @text
        when 'LaunchConfigurationName' then @item[:launch_configuration_name] = @text
        when 'UserData'                then @item[:user_data]                 = @text
        when 'NextToken'               then @result[:next_token]              = @text
        else
          case full_tag_name
          when %r{/BlockDeviceMappings/member} # no trailing $
            case name
            when 'DeviceName'          then @block_device_mapping[:device_name]  = @text
            when 'VirtualName'         then @block_device_mapping[:virtual_name] = @text
            when 'member'              then @item[:block_device_mappings]        << @block_device_mapping
            end
          when %r{member/SecurityGroups/member$} 
            @item[:security_groups] << @text
          when %r{/LaunchConfigurations/member$}
            @item[:security_groups].sort!
            @result[:launch_configurations] << @item
          end
        end
      end
      def reset
        @result = { :launch_configurations => []}
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
        when 'AutoScalingGroupName'      then @item[:auto_scaling_group_name]      = @text
        when 'MeasureName'               then @item[:measure_name]                 = @text
        when 'CreatedTime'               then @item[:created_time]                 = @text
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
          when "#@p/member/Dimensions" then @item[:dimensions][@dimension[:name]] = @dimension[:value]
          when @p                      then @result << @item
          end
        end
      end
      def reset
        @p      = 'DescribeTriggersResponse/DescribeTriggersResult/Triggers'
        @result = []
      end
    end
  end

end
