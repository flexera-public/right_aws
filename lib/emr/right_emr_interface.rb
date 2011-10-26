#
# Copyright (c) 2011 RightScale Inc
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

  # = RightAWS::EmrInterface -- RightScale Amazon Elastic Map Reduce interface
  #
  # The RightAws::EmrInterface class provides a complete interface to Amazon
  # Elastic Map Reduce service.
  #
  # For explanations of the semantics of each call, please refer to Amazon's
  # documentation at
  # http://aws.amazon.com/documentation/elasticmapreduce/
  #
  # Create an interface handle:
  #
  #  emr = RightAws::EmrInterface.new(aws_access_key_id, aws_secret_access_key)
  #
  # Create a job flow:
  #
  #  emr.run_job_flow(
  #    :name => 'job flow 1',
  #    :master_instance_type => 'm1.large',
  #    :slave_instance_type => 'm1.large',
  #    :instance_count => 5,
  #    :log_uri => 's3n://bucket/path/to/logs',
  #    :steps => [{
  #      :name => 'step 1',
  #      :jar => 's3n://bucket/path/to/code.jar',
  #      :main_class => 'com.foobar.emr.Step1',
  #      :args => ['arg', 'arg'],
  #    }]) #=> "j-9K18HM82Q0AE7"
  #
  # Describe a job flow:
  #
  #  emr.describe_job_flows('j-9K18HM82Q0AE7') #=> {...}
  #
  # Terminate a job flow:
  #
  #  emr.terminate_job_flows('j-9K18HM82Q0AE7') #=> true
  #
  class EmrInterface < RightAwsBase
    include RightAwsBaseInterface

    # Amazon EMR API version being used
    API_VERSION       = '2009-03-31'
    DEFAULT_HOST      = 'elasticmapreduce.amazonaws.com'
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

    # Create a new handle to a EMR service.
    #
    # All handles share the same per process or per thread HTTP connection
    # to EMR. Each handle is for a specific account. The params have
    # the following options:
    #
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint
    #   (this overwrites: :server, :port, :service, :protocol). Example:
    #   'https://elasticmapreduce.amazonaws.com'
    # * <tt>:server</tt>: EMR service host, default: DEFAULT_HOST
    # * <tt>:port</tt>: EMR service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    #
    #  emr = RightAws::EmrInterface.new('xxxxxxxxxxxxxxxxxxxxx','xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    #    {:logger => Logger.new('/tmp/x.log')}) #=> #<RightAws::EmrInterface::0xb7b3c30c>
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'EMR',
             :default_host        => ENV['EMR_URL'] ? URI.parse(ENV['EMR_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['EMR_URL'] ? URI.parse(ENV['EMR_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['EMR_URL'] ? URI.parse(ENV['EMR_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['EMR_URL'] ? URI.parse(ENV['EMR_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['EMR_API_VERSION'] || API_VERSION },
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
      request_info_impl(:emr_connection, @@bench, request, parser)
    end

    #-----------------------------------------------------------------
    #      Job Flows
    #-----------------------------------------------------------------

    EMR_INSTANCES_KEY_MAPPING = {                                                           # :nodoc:
      :additional_info => 'AdditionalInfo',
      :log_uri => 'LogUri',
      :name => 'Name',
      # JobFlowInstancesConfig
      :ec2_key_name          => 'Instances.Ec2KeyName',
      :hadoop_version => 'Instances.HadoopVersion',
      :instance_count        => 'Instances.InstanceCount',
      :keep_job_flow_alive_when_no_steps   => 'Instances.KeepJobFlowAliveWhenNoSteps',
      :master_instance_type  => 'Instances.MasterInstanceType',
      :slave_instance_type   => 'Instances.SlaveInstanceType',
      :termination_protected => 'Instances.TerminationProtected',
      # PlacementType
      :availability_zone     => 'Instances.Placement.AvailabilityZone',
    }

    BOOTSTRAP_ACTION_KEY_MAPPING = {                                                           # :nodoc:
      :name => 'Name',
      # ScriptBootstrapActionConfig
      :args => 'ScriptBootstrapAction.Args',
      :path => 'ScriptBootstrapAction.Path',
    }

    INSTANCE_GROUP_KEY_MAPPING = {                                                           # :nodoc:
      :bid_price => 'BidPrice',
      :instance_count => 'InstanceCount',
      :instance_role => 'InstanceRole',
      :instance_type => 'InstanceType',
      :market => 'Market',
      :name => 'Name',
    }

    STEP_CONFIG_KEY_MAPPING = {                                                           # :nodoc:
      :action_on_failure => 'ActionOnFailure',
      :name => 'Name',
      # HadoopJarStepConfig
      :args => 'HadoopJarStep.Args',
      :jar => 'HadoopJarStep.Jar',
      :main_class => 'HadoopJarStep.MainClass',
      :properties => 'HadoopJarStep.Properties',
    }
    
    KEY_VALUE_KEY_MAPPINGS = {
      :key => 'Key',
      :value => 'Value',
    }

    # Creates and starts running a new job flow.
    #
    # The job flow will run the steps specified and terminate (unless
    # keep alive option is set).
    #
    # A maximum of 256 steps are allowed in a job flow.
    #
    # At least the name, instance types, instance count and one step
    # must be specified.
    #
    #  # simple usage:
    #  emr.run_job_flow(
    #    :name => 'job flow 1',
    #    :master_instance_type => 'm1.large',
    #    :slave_instance_type => 'm1.large',
    #    :instance_count => 5,
    #    :log_uri => 's3n://bucket/path/to/logs',
    #    :steps => [{
    #      :name => 'step 1',
    #      :jar => 's3n://bucket/path/to/code.jar',
    #      :main_class => 'com.foobar.emr.Step1',
    #      :args => ['arg', 'arg'],
    #    }]) #=> "j-9K18HM82Q0AE7"
    #
    #  # advanced usage:
    #  emr.run_job_flow(
    #    :name => 'job flow 1',
    #    :ec2_key_name => 'gsg-keypair',
    #    :hadoop_version => '0.20',
    #    :instance_groups => [{
    #      :bid_price => '0.1',
    #      :instance_count => '1',
    #      :instance_role => 'MASTER',
    #      :instance_type => 'm1.small',
    #      :market => 'SPOT',
    #      :name => 'master group',
    #    }, {
    #      :bid_price => '0.1',
    #      :instance_count => '2',
    #      :instance_role => 'CORE',
    #      :instance_type => 'm1.small',
    #      :market => 'SPOT',
    #      :name => 'core group',
    #    }, {
    #      :bid_price => '0.1',
    #      :instance_count => '2',
    #      :instance_role => 'TASK',
    #      :instance_type => 'm1.small',
    #      :market => 'SPOT',
    #      :name => 'task group',
    #    }],
    #    :keep_job_flow_alive_when_no_steps => true,
    #    :availability_zone => 'us-east-1a',
    #    :termination_protected => true,
    #    :log_uri => 's3n://bucket/path/to/logs',
    #    :steps => [{
    #      :name => 'step 1',
    #      :jar => 's3n://bucket/path/to/code.jar',
    #      :main_class => 'com.foobar.emr.Step1',
    #      :args => ['arg', 'arg'],
    #      :properties => {
    #        'property' => 'value',
    #      },
    #      :action_on_failure => 'TERMINATE_JOB_FLOW',
    #    }],
    #    :additional_info => '',
    #    :bootstrap_actions => [{
    #      :name => 'bootstrap action 1',
    #      :path => 's3n://bucket/path/to/bootstrap',
    #      :args => ['hello', 'world'],
    #    }],
    #  ) #=> "j-9K18HM82Q0AE7"
    #
    def run_job_flow(options={})
      request_hash = amazonize_run_job_flow(options)
      request_hash.update(amazonize_bootstrap_actions(options[:bootstrap_actions]))
      request_hash.update(amazonize_instance_groups(options[:instance_groups]))
      request_hash.update(amazonize_steps(options[:steps]))
      link = generate_request("RunJobFlow", request_hash)
      request_info(link, RunJobFlowParser.new(:logger => @logger))
    rescue
      on_exception
    end

    # Returns a list of job flows that match all of supplied parameters.
    #
    # Without parameters, returns job flows started in the last two weeks
    # or running job flows started in the last two months.
    #
    # Regardless of parameters, only jobs started in the last two months
    # are returned.
    #
    #  # default list:
    #  emr.describe_job_flows #=> [
    #    {:keep_job_flow_alive_when_no_steps=>false,
    #      :log_uri=>"s3n://bucket/path/to/logs",
    #      :master_instance_type=>"m1.small",
    #      :availability_zone=>"us-east-1d",
    #      :last_state_change_reason=>"Steps completed",
    #      :termination_protected=>false,
    #      :master_instance_id=>"i-1fe51278",
    #      :instance_count=>1,
    #      :ready_date_time=>"2011-08-31T18:58:58Z",
    #      :bootstrap_actions=>[],
    #      :master_public_dns_name=>"ec2-184-78-29-127.compute-1.amazonaws.com",
    #      :instance_groups=>
    #       [{:instance_request_count=>1,
    #         :last_state_change_reason=>"Job flow terminated",
    #         :instance_role=>"MASTER",
    #         :ready_date_time=>"2011-08-31T18:58:56Z",
    #         :instance_running_count=>0,
    #         :start_date_time=>"2011-08-31T18:58:19Z",
    #         :market=>"ON_DEMAND",
    #         :creation_date_time=>"2011-08-31T18:55:36Z",
    #         :name=>"master",
    #         :instance_group_id=>"ig-1D91GQR7A9H2K",
    #         :state=>"ENDED",
    #         :instance_type=>"m1.small",
    #         :end_date_time=>"2011-08-31T19:01:09Z"}],
    #      :start_date_time=>"2011-08-31T18:58:58Z",
    #      :steps=>
    #       [{:jar=>"s3n://bucket/path/to/code.jar",
    #         :main_class=>"com.foobar.emr.Step1",
    #         :start_date_time=>"2011-08-31T18:58:58Z",
    #         :properties=>{},
    #         :args=>[],
    #         :creation_date_time=>"2011-08-31T18:55:36Z",
    #         :action_on_failure=>"TERMINATE_JOB_FLOW",
    #         :name=>"step 1",
    #         :state=>"COMPLETED",
    #         :end_date_time=>"2011-08-31T19:00:34Z"}],
    #      :normalized_instance_hours=>1,
    #      :ami_version=>"1.0",
    #      :creation_date_time=>"2011-08-31T18:55:36Z",
    #      :name=>"jobflow 1",
    #      :hadoop_version=>"0.18",
    #      :job_flow_id=>"j-9K18HM82Q0AE7",
    #      :state=>"COMPLETED",
    #      :end_date_time=>"2011-08-31T19:01:09Z"}]
    #
    #  # describe specific job flows:
    #  emr.describe_job_flows('j-9K18HM82Q0AE7', 'j-2QE0KHA1LP4GS') #=> [...]
    #
    #  # specify parameters:
    #  emr.describe_job_flows(
    #    :created_after => Time.now - 86400,
    #    :created_before => Time.now - 3600,
    #    :job_flow_ids => ['j-9K18HM82Q0AE7', 'j-2QE0KHA1LP4GS'],
    #    :job_flow_states => ['RUNNING']
    #  ) #=> [...]
    #
    #  # combined job flow list and parameters syntax:
    #  emr.describe_job_flows('j-9K18HM82Q0AE7', 'j-2QE0KHA1LP4GS',
    #    :job_flow_states => ['RUNNING']
    #  ) #=> [...]
    #
    def describe_job_flows(*job_flow_ids_and_options)
      job_flow_ids, options = AwsUtils::split_items_and_params(job_flow_ids_and_options)
      # merge job flow ids passed in as arguments and in options
      unless job_flow_ids.empty?
        # do not modify passed in options
        options = options.dup
        if job_flow_ids_in_options = options[:job_flow_ids]
          # allow the same ids to be passed in either location;
          # remove duplicates
          options[:job_flow_ids] = (job_flow_ids_in_options + job_flow_ids).uniq
        else
          options[:job_flow_ids] = job_flow_ids
        end
      end
      request_hash = {}
      unless (job_flow_ids = options[:job_flow_ids]).right_blank?
        request_hash.update(amazonize_list("JobFlowIds.member", job_flow_ids))
      end
      unless (job_flow_states = options[:job_flow_states]).right_blank?
        request_hash = amazonize_list("JobFlowStates.member", job_flow_states)
      end
      request_hash['CreatedAfter'] = AwsUtils::utc_iso8601(options[:created_after]) unless options[:created_after].right_blank?
      request_hash['CreatedBefore'] = AwsUtils::utc_iso8601(options[:created_before]) unless options[:created_before].right_blank?
      link = generate_request("DescribeJobFlows", request_hash)
      request_cache_or_info(:describe_job_flows, link,  DescribeJobFlowsParser, @@bench, nil)
    rescue
      on_exception
    end

    # Terminates specified job flows.
    #
    #  emr.terminate_job_flows('j-9K18HM82Q0AE7') #=> true
    #
    def terminate_job_flows(*job_flow_ids)
      link = generate_request("TerminateJobFlows", amazonize_list('JobFlowIds.member', job_flow_ids))
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue
      on_exception
    end

    # Locks a job flow so the EC2 instances in the cluster cannot be
    # terminated by user intervention, an API call, or in the event of a
    # job flow error. Cluster will still terminate upon successful completion
    # of the job flow.
    #
    #  emr.set_termination_protection(
    #    'j-9K18HM82Q0AE7', 'j-2QE0KHA1LP4GS', :termination_protected => true
    #  ) #=> true
    #
    # Protection can be enabled using the shortcut syntax:
    #
    #  emr.set_termination_protection('j-9K18HM82Q0AE7') #=> true
    #
    def set_termination_protection(*job_flow_ids_and_options)
      job_flow_ids, options = AwsUtils::split_items_and_params(job_flow_ids_and_options)
      request_hash = amazonize_list('JobFlowIds.member', job_flow_ids)
      request_hash['TerminationProtected'] = case value = options[:termination_protected]
      when true
        'true'
      when false
        'false'
      when nil
        # if :termination_protected => nil was given, then unprotect;
        # if no :termination_protected option was given, protect
        if options.has_key?(:termination_protected)
          'false'
        else
          'true'
        end
      else
        # pass value through
        value
      end
      link = generate_request("SetTerminationProtection", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue
      on_exception
    end

    #-----------------------------------------------------------------
    #      Steps
    #-----------------------------------------------------------------

    # Adds steps to a running job flow.
    #
    # A maximum of 256 steps are allowed in a job flow. Steps can only be
    # added to job flows that are starting, bootstrapping, running or waiting.
    #
    # Step configuration options are the same as the ones accepted by
    # run_job_flow.
    #
    #  emr.add_job_flow_steps('j-2QE0KHA1LP4GS', {
    #    :name => 'step 1',
    #    :jar => 's3n://bucket/path/to/code.jar',
    #    :main_class => 'com.foobar.emr.Step1',
    #    :args => ['arg', 'arg'],
    #    :properties => {
    #      'property' => 'value',
    #    },
    #    :action_on_failure => 'TERMINATE_JOB_FLOW',
    #  }) #=> true
    #
    def add_job_flow_steps(job_flow_id, *steps)
      request_hash = amazonize_steps(steps)
      request_hash['JobFlowId'] = job_flow_id
      link = generate_request("AddJobFlowSteps", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue
      on_exception
    end

    #-----------------------------------------------------------------
    #      Instance Groups
    #-----------------------------------------------------------------

    # Adds instance groups to a running job flow.
    #
    # Instance group configuration options are the same as the ones accepted
    # by run_job_flow.
    #
    # Only task instance groups may be added at runtime.
    # Instance groups cannot be added to job flows that have only a master
    # instance (i.e. 1 instance in total).
    #
    #  emr.add_instance_groups('j-2QE0KHA1LP4GS', {
    #    :bid_price => '0.1',
    #    :instance_count => '2',
    #    :instance_role => 'TASK',
    #    :instance_type => 'm1.small',
    #    :market => 'SPOT',
    #    :name => 'core group',
    #  }) #=> true
    #
    def add_instance_groups(job_flow_id, *instance_groups)
      request_hash = amazonize_instance_groups(instance_groups, 'InstanceGroups')
      request_hash['JobFlowId'] = job_flow_id
      link = generate_request("AddInstanceGroups", request_hash)
      request_info(link, AddInstanceGroupsParser.new(:logger => @logger))
    rescue
      on_exception
    end
    
    MODIFY_INSTANCE_GROUP_KEY_MAPPINGS = {
      :instance_group_id => 'InstanceGroupId',
      :instance_count => 'InstanceCount',
    }

    # Modifies instance groups.
    #
    # The only modifiable parameter is instance count.
    #
    # An instance group may only be modified when the job flow is running
    # or waiting. Additionally, hadoop 0.20 is required to resize job flows.
    #
    #  # general syntax
    #  emr.modify_instance_groups(
    #    {:instance_group_id => 'ig-P2OPM2L9ZQ4P', :instance_count => 5},
    #    {:instance_group_id => 'ig-J82ML0M94A7E', :instance_count => 1}
    #  ) #=> true
    #
    #  # shortcut syntax
    #  emr.modify_instance_groups('ig-P2OPM2L9ZQ4P', 5) #=> true
    #
    # Shortcut syntax supports modifying only one instance group at a time.
    #
    def modify_instance_groups(*args)
      unless args.first.is_a?(Hash)
        if args.length != 2
          raise ArgumentError, "Must be given two arguments if arguments are not hashes"
        end
        args = [{:instance_group_id => args.first, :instance_count => args.last}]
      end
      request_hash = amazonize_list_with_key_mapping('InstanceGroups.member', MODIFY_INSTANCE_GROUP_KEY_MAPPINGS, args)
      link = generate_request("ModifyInstanceGroups", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue
      on_exception
    end
    
    private

    def amazonize_run_job_flow(options) # :nodoc:
      result = {}
      unless options.right_blank?
        EMR_INSTANCES_KEY_MAPPING.each do |local_name, remote_name|
          value = options[local_name]
          result[remote_name] = value unless value.nil?
        end
      end
      result
    end

    def amazonize_bootstrap_actions(bootstrap_actions, key = 'BootstrapActions.member') # :nodoc:
      result = {}
      unless bootstrap_actions.right_blank?
        bootstrap_actions.each_with_index do |item, index|
          BOOTSTRAP_ACTION_KEY_MAPPING.each do |local_name, remote_name|
            value = item[local_name]
            case local_name
            when :args
              result.update(amazonize_list("#{key}.#{index+1}.#{remote_name}.member", value))
            else
              next if value.nil?
              result["#{key}.#{index+1}.#{remote_name}"] = value
            end
          end
        end
      end
      result
    end

    def amazonize_instance_groups(instance_groups, key = 'Instances.InstanceGroups') # :nodoc:
      result = {}
      unless instance_groups.right_blank?
        instance_groups.each_with_index do |item, index|
          INSTANCE_GROUP_KEY_MAPPING.each do |local_name, remote_name|
            value = item[local_name]
            case local_name
            when :instance_groups
              result.update(amazonize_list_with_key_mapping("#{key}.member.#{index+1}.#{remote_name}", INSTANCE_GROUP_KEY_MAPPING, value))
            else
              next if value.nil?
              result["#{key}.member.#{index+1}.#{remote_name}"] = value
            end
          end
        end
      end
      result
    end

    def amazonize_steps(steps, key = 'Steps.member') # :nodoc:
      result = {}
      unless steps.right_blank?
        steps.each_with_index do |item, index|
          STEP_CONFIG_KEY_MAPPING.each do |local_name, remote_name|
            value = item[local_name]
            case local_name
            when :args
              result.update(amazonize_list("#{key}.#{index+1}.#{remote_name}.member", value))
            when :properties
              next if value.right_blank?
              list = value.inject([]) do |l, (k, v)|
                l << {:key => k, :value => v}
              end
              result.update(amazonize_list_with_key_mapping("#{key}.#{index+1}.#{remote_name}.member", KEY_VALUE_KEY_MAPPINGS, list))
            else
              next if value.nil?
              result["#{key}.#{index+1}.#{remote_name}"] = value
            end
          end
        end
      end
      result
    end

    #-----------------------------------------------------------------
    #      PARSERS: Run Job Flow
    #-----------------------------------------------------------------

    class RunJobFlowParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'JobFlowId' then @result = @text
        end
      end
      def reset
        @result = nil
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Describe Job Flows
    #-----------------------------------------------------------------

    class DescribeJobFlowsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/JobFlows/member$}
          @item = { :instance_groups => [],
                    :steps       => [],
                    :bootstrap_actions => [] }
        when %r{/BootstrapActionConfig$}
          @bootstrap_action = {}
        when %r{/InstanceGroups/member$}
          @instance_group = {}
        when %r{/Steps/member$}
          @step = { :args => [],
                    :properties => {} }
        end
      end
      def tagend(name)
        case full_tag_name
        when %r{/BootstrapActionConfig} # no trailing $
          case name
          when 'Name'
            @bootstrap_action[:name] = @text
          when 'ScriptBootstrapAction'
            @bootstrap_action[:script_bootstrap_action] = @text
          when 'BootstrapActionConfig'
            @step[:bootstrap_actions] << @bootstrap_action
          end
        when %r{/InstanceGroups/member} # no trailing $
          case name
          when 'BidPrice' then @instance_group[:bid_price] = @text
          when 'CreationDateTime' then @instance_group[:creation_date_time] = @text
          when 'EndDateTime' then @instance_group[:end_date_time] = @text
          when 'InstanceGroupId' then @instance_group[:instance_group_id] = @text
          when 'InstanceRequestCount' then @instance_group[:instance_request_count] = @text.to_i
          when 'InstanceRole' then @instance_group[:instance_role] = @text
          when 'InstanceRunningCount' then @instance_group[:instance_running_count] = @text.to_i
          when 'InstanceType' then @instance_group[:instance_type] = @text
          when 'LastStateChangeReason' then @instance_group[:last_state_change_reason] = @text
          when 'Market' then @instance_group[:market] = @text
          when 'Name' then @instance_group[:name] = @text
          when 'ReadyDateTime' then @instance_group[:ready_date_time] = @text
          when 'StartDateTime' then @instance_group[:start_date_time] = @text
          when 'State' then @instance_group[:state] = @text
          when 'member' then @item[:instance_groups]        << @instance_group
          end
        when %r{/Steps/member/StepConfig/HadoopJarStepConfig/Args/member}
          @steps[:args] << @text
        when %r{/Steps/member/StepConfig/HadoopJarStepConfig/Properties}
          case name
          when 'Key'
            @key = @text
          when 'Value'
            @steps[:properties][@key] = @text
          end
        when %r{/Steps/member$}
          @item[:steps] << @step
        when %r{/Steps/member} # no trailing $
          case name
          # ExecutionStatusDetail
          when 'CreationDateTime' then @step[:creation_date_time] = @text
          when 'EndDateTime' then @step[:end_date_time] = @text
          when 'LastStateChangeReason' then @step[:last_state_change_reason] = @text
          when 'StartDateTime' then @step[:start_date_time] = @text
          when 'State' then @step[:state] = @text
          # StepConfig
          when 'ActionOnFailure' then @step[:action_on_failure] = @text
          when 'Name' then @step[:name] = @text
          # HadoopJarStepConfig
          when 'Jar' then @step[:jar] = @text
          when 'MainClass' then @step[:main_class] = @text
          end
        when %r{/JobFlows/member$}
          @result << @item
        else
          case name
          when 'AmiVersion' then @item[:ami_version] = @text
          when 'JobFlowId' then @item[:job_flow_id] = @text
          when 'LogUri' then @item[:log_uri] = @text
          when 'Name' then @item[:name] = @text
          
          # JobFlowExecutionStatusDetail
          when 'CreationDateTime' then @item[:creation_date_time] = @text
          when 'EndDateTime' then @item[:end_date_time] = @text
          when 'LastStateChangeReason' then @item[:last_state_change_reason] = @text
          when 'ReadyDateTime' then @item[:ready_date_time] = @text
          when 'StartDateTime' then @item[:start_date_time] = @text
          when 'State' then @item[:state] = @text
          
          # JobFlowInstancesDetail
          when 'Ec2KeyName' then @item[:ec2_key_name] = @text
          when 'HadoopVersion' then @item[:hadoop_version] = @text
          when 'InstanceCount' then @item[:instance_count] = @text.to_i
          when 'KeepJobFlowAliveWhenNoSteps' then @item[:keep_job_flow_alive_when_no_steps] = case @text when 'true' then true when 'false' then false else @text end
          when 'MasterInstanceId' then @item[:master_instance_id] = @text
          when 'MasterInstanceType' then @item[:master_instance_type] = @text
          when 'MasterPublicDnsName' then @item[:master_public_dns_name] = @text
          when 'NormalizedInstanceHours' then @item[:normalized_instance_hours] = @text.to_i
          # Placement
          when 'AvailabilityZone' then @item[:availability_zone] = @text
          when 'SlaveInstanceType' then @item[:slave_instance_type] = @text
          when 'TerminationProtected' then @item[:termination_protected] = case @text when 'true' then true when 'false' then false else @text end
          end
        end
      end
      def reset
        @result = []
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Add Instance Groups
    #-----------------------------------------------------------------

    class AddInstanceGroupsParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'InstanceGroupIds' then @result << @text.strip
        end
      end
      def reset
        @result = []
      end
    end
  end

end
