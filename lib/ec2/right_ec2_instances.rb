#
# Copyright (c) 2009 RightScale Inc
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
  #      Instances
  #-----------------------------------------------------------------

    def get_desc_instances(instances)  # :nodoc:
      result = []
      instances.each do |reservation|
        reservation[:instances_set].each do |instance|
          # Parse and remove timestamp from the reason string. The timestamp is of
          # the request, not when EC2 took action, thus confusing & useless...
          instance[:aws_reason]         = instance[:aws_reason].sub(/\(\d[^)]*GMT\) */, '')
          instance[:aws_owner]          = reservation[:aws_owner]
          instance[:aws_reservation_id] = reservation[:aws_reservation_id]
          # Security Groups
          instance[:groups]             = instance[:groups].right_blank? ? reservation[:aws_groups] : instance[:groups]
          result << instance
        end
      end
      result
    rescue Exception
      on_exception
    end

    # Retrieve information about EC2 instances.
    #
    # Accepts a list of instances and/or a set of filters as the last parameter.
    # 
    # Filters: architecture, availability-zone, block-device-mapping.attach-time, block-device-mapping.delete-on-termination,
    # block-device-mapping.device-name, block-device-mapping.status, block-device-mapping.volume-id, client-token, dns-name,
    # group-id, image-id, instance-id, instance-lifecycle, instance-state-code, instance-state-name, instance-type, ip-address,
    # kernel-id, key-name, launch-index, launch-time, monitoring-state, owner-id, placement-group-name, platform,
    # private-dns-name, private-ip-address, product-code, ramdisk-id, reason, requester-id, reservation-id, root-device-name,
    # root-device-type, spot-instance-request-id, state-reason-code, state-reason-message, subnet-id, tag-key, tag-value,
    # tag:key, virtualization-type, vpc-id,
    #
    #
    #  ec2.describe_instances #=>
    #    [{:source_dest_check=>true,
    #        :subnet_id=>"subnet-da6cf9b3",
    #        :aws_kernel_id=>"aki-3932d150",
    #        :ami_launch_index=>"0",
    #        :tags=>{},
    #        :aws_reservation_id=>"r-7cd25c11",
    #        :aws_owner=>"826693181925",
    #        :state_reason_code=>"Client.UserInitiatedShutdown",
    #        :aws_instance_id=>"i-2d898e41",
    #        :hypervisor=>"xen",
    #        :root_device_name=>"/dev/sda1",
    #        :aws_ramdisk_id=>"ari-c515f6ac",
    #        :aws_instance_type=>"m1.large",
    #        :groups=>[{:group_name=>"2009-07-15-default", :group_id=>"sg-90c5d6fc"}],
    #        :block_device_mappings=>
    #          [{:device_name=>"/dev/sda1",
    #            :ebs_status=>"attached",
    #            :ebs_attach_time=>"2011-03-04T18:51:58.000Z",
    #            :ebs_delete_on_termination=>true,
    #            :ebs_volume_id=>"vol-38f2bd50"}],
    #        :state_reason_message=>
    #          "Client.UserInitiatedShutdown: User initiated shutdown",
    #        :aws_image_id=>"ami-a3638cca",
    #        :virtualization_type=>"paravirtual",
    #        :aws_launch_time=>"2011-03-04T18:13:59.000Z",
    #        :private_dns_name=>"",
    #        :aws_product_codes=>[],
    #        :aws_availability_zone=>"us-east-1a",
    #        :aws_state_code=>80,
    #        :architecture=>"x86_64",
    #        :dns_name=>"",
    #        :client_token=>"1299262447-684266-NNgyH-ouPTI-MzG6h-5AIRk",
    #        :root_device_type=>"ebs",
    #        :vpc_id=>"vpc-e16cf988",
    #        :monitoring_state=>"disabled",
    #        :ssh_key_name=>"default",
    #        :private_ip_address=>"192.168.0.52",
    #        :aws_reason=>"User initiated ",
    #        :aws_state=>"stopped"}, ...]
    #
    #   ec2.describe_instances("i-8ce84ae6", "i-8ce84ae8", "i-8ce84ae0")
    #   ec2.describe_instances(:filters => { 'availability-zone' => 'us-east-1a', 'instance-type' => 'c1.medium' })
    #
    # P.S. filters: http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-DescribeInstances.html
    #
    def describe_instances(*list_and_options)
      describe_resources_with_list_and_options('DescribeInstances', 'InstanceId', QEc2DescribeInstancesParser, list_and_options) do |parser|
        get_desc_instances(parser.result)
      end
    end

    # Return the product code attached to instance or +nil+ otherwise.
    #
    #  ec2.confirm_product_instance('ami-e444444d','12345678') #=> nil
    #  ec2.confirm_product_instance('ami-e444444d','00001111') #=> "000000000888"
    #
    def confirm_product_instance(instance, product_code)
      link = generate_request("ConfirmProductInstance", { 'ProductCode' => product_code,
                                'InstanceId'  => instance })
      request_info(link, QEc2ConfirmProductInstanceParser.new(:logger => @logger))
    end

    # Launch new EC2 instances. Returns a list of launched instances or an exception.
    #
    #  ec2.run_instances('ami-e444444d',1,1,['2009-07-15-default'],'my_awesome_key', 'Woohoo!!!', 'public') #=>
    #   [{:aws_image_id       => "ami-e444444d",
    #     :aws_reason         => "",
    #     :aws_state_code     => "0",
    #     :aws_owner          => "000000000888",
    #     :aws_instance_id    => "i-123f1234",
    #     :aws_reservation_id => "r-aabbccdd",
    #     :aws_state          => "pending",
    #     :dns_name           => "",
    #     :ssh_key_name       => "my_awesome_key",
    #     :groups             => [{:group_name=>"2009-07-15-default", :group_id=>"sg-90c5d6fc"}],
    #     :private_dns_name   => "",
    #     :aws_instance_type  => "m1.small",
    #     :aws_launch_time    => "2008-1-1T00:00:00.000Z"
    #     :aws_ramdisk_id     => "ari-8605e0ef"
    #     :aws_kernel_id      => "aki-9905e0f0",
    #     :ami_launch_index   => "0",
    #     :aws_availability_zone => "us-east-1b"
    #     }]
    #
    def run_instances(image_id, min_count, max_count, group_names, key_name, user_data='',
                      addressing_type = nil, instance_type = nil,
                      kernel_id = nil, ramdisk_id = nil, availability_zone = nil,
                      monitoring_enabled = nil, subnet_id = nil, disable_api_termination = nil,
                      instance_initiated_shutdown_behavior = nil, block_device_mappings = nil,
                      placement_group_name = nil, client_token = nil)
 	    launch_instances(image_id, { :min_count                            => min_count,
 	                                 :max_count                            => max_count,
 	                                 :user_data                            => user_data,
                                   :group_names                          => group_names,
                                   :key_name                             => key_name,
                                   :instance_type                        => instance_type,
                                   :addressing_type                      => addressing_type,
                                   :kernel_id                            => kernel_id,
                                   :ramdisk_id                           => ramdisk_id,
                                   :availability_zone                    => availability_zone,
                                   :monitoring_enabled                   => monitoring_enabled,
                                   :subnet_id                            => subnet_id,
                                   :disable_api_termination              => disable_api_termination,
                                   :instance_initiated_shutdown_behavior => instance_initiated_shutdown_behavior,
                                   :block_device_mappings                => block_device_mappings,
                                   :placement_group_name                 => placement_group_name,
                                   :client_token                         => client_token
                                 })
    end

    # Launch new EC2 instances.
    # 
    # Options: :image_id, :addressing_type, :min_count, max_count, :key_name, :kernel_id, :ramdisk_id,
    # :availability_zone, :monitoring_enabled, :subnet_id, :disable_api_termination, :instance_initiated_shutdown_behavior,
    # :block_device_mappings, :placement_group_name, :license_pool, :group_ids, :group_names, :private_ip_address
    # 
    # Returns a list of launched instances or an exception.
    #
    #  ec2.launch_instances( "ami-78779511",
    #                        :min_count => 1,
    #                        :group_names => ["default", "eugeg223123123"],
    #                        :user_data => 'Ohoho!',
    #                        :availability_zone => "us-east-1a",
    #                        :disable_api_termination => false,
    #                        :instance_initiated_shutdown_behavior => 'terminate',
    #                        :block_device_mappings => [ {:ebs_snapshot_id=>"snap-e40fd188",
    #                                                     :ebs_delete_on_termination=>true,
    #                                                     :device_name => "/dev/sdk",
    #                                                     :virtual_name => "mystorage"} ] ) #=>
    #    [{:hypervisor=>"xen",
    #      :private_dns_name=>"",
    #      :client_token=>"1309532374-551037-gcsBj-gEypk-piG06-ODfQm",
    #      :monitoring_state=>"disabled",
    #      :aws_availability_zone=>"us-east-1a",
    #      :root_device_name=>"/dev/sda1",
    #      :state_reason_code=>"pending",
    #      :dns_name=>"",
    #      :tags=>{},
    #      :aws_reason=>"",
    #      :virtualization_type=>"paravirtual",
    #      :state_reason_message=>"pending",
    #      :aws_reservation_id=>"r-6fada703",
    #      :aws_ramdisk_id=>"ari-a51cf9cc",
    #      :ami_launch_index=>"0",
    #      :groups=>
    #       [{:group_id=>"sg-a0b85dc9", :group_name=>"default"},
    #        {:group_id=>"sg-70733019", :group_name=>"eugeg223123123"}],
    #      :aws_owner=>"826693181925",
    #      :aws_instance_type=>"m1.small",
    #      :aws_state=>"pending",
    #      :root_device_type=>"ebs",
    #      :aws_image_id=>"ami-78779511",
    #      :aws_kernel_id=>"aki-a71cf9ce",
    #      :aws_launch_time=>"2011-07-01T14:59:35.000Z",
    #      :aws_state_code=>0,
    #      :aws_instance_id=>"i-4f202621",
    #      :aws_product_codes=>[]}]
    #
    def launch_instances(image_id, options={})
      options[:user_data] = options[:user_data].to_s
      params = map_api_keys_and_values( options,
        :key_name, :addressing_type, :kernel_id,
        :ramdisk_id, :subnet_id, :instance_initiated_shutdown_behavior,
        :private_ip_address, :additional_info, :license_pool,
        :image_id                => { :value => image_id },
        :min_count               => { :value => options[:min_count] || 1 },
        :max_count               => { :value => options[:max_count] || options[:min_count] || 1 },
        :placement_tenancy       => 'Placement.Tenancy',
        :placement_group_name    => 'Placement.GroupName',
        :availability_zone       => 'Placement.AvailabilityZone',
        :group_names             => { :amazonize_list => 'SecurityGroup' },
        :group_ids               => { :amazonize_list => 'SecurityGroupId' },
        :block_device_mappings   => { :amazonize_bdm  => 'BlockDeviceMapping' },
        :instance_type           => { :value => options[:instance_type] || DEFAULT_INSTANCE_TYPE },
        :disable_api_termination => { :value => Proc.new{ !options[:disable_api_termination].nil? && options[:disable_api_termination].to_s }},
        :client_token            => { :value => !@params[:eucalyptus] && (options[:client_token] || AwsUtils::generate_unique_token)},
        :user_data               => { :value => Proc.new { !options[:user_data].empty? && Base64.encode64(options[:user_data]).delete("\n") }},
        :monitoring_enabled      => { :name  => 'Monitoring.Enabled',
                                      :value => Proc.new{ options[:monitoring_enabled] && options[:monitoring_enabled].to_s }})
      # Log debug information
      @logger.info("Launching instance of image #{image_id}. Options: #{params.inspect}")
      link = generate_request("RunInstances", params)
      instances = request_info(link, QEc2DescribeInstancesParser.new(:logger => @logger))
      get_desc_instances(instances)
    rescue Exception
      on_exception
    end

    # Start instances.
    #
    #  ec2.start_instances("i-36e84a5e") #=>
    #    [{:aws_prev_state_name=>"stopped",
    #      :aws_instance_id=>"i-36e84a5e",
    #      :aws_current_state_code=>16,
    #      :aws_current_state_name=>"running",
    #      :aws_prev_state_code=>80}]
    #
    def start_instances(*instance_aws_ids)
      instance_aws_ids = instance_aws_ids.flatten
      link = generate_request("StartInstances", amazonize_list('InstanceId', instance_aws_ids))
      request_info(link, QEc2TerminateInstancesParser.new(:logger => @logger))
     end

    # Stop instances.
    #
    # Options: :force => true|false
    #
    #  ec2.stop_instances("i-36e84a5e") #=>
    #    [{:aws_prev_state_code=>16,
    #      :aws_prev_state_name=>"running",
    #      :aws_instance_id=>"i-36e84a5e",
    #      :aws_current_state_code=>64,
    #      :aws_current_state_name=>"stopping"}]
    #
    def stop_instances(*instance_aws_ids_and_options)
      list, options = AwsUtils::split_items_and_params(instance_aws_ids_and_options)
      request_hash = {}
      request_hash['Force'] = true if options[:force]
      request_hash.merge!(amazonize_list('InstanceId', list))
      link = generate_request("StopInstances", request_hash)
      request_info(link, QEc2TerminateInstancesParser.new(:logger => @logger))
    end

    # Terminates EC2 instances. Returns a list of termination params or an exception.
    #
    #  ec2.terminate_instances(['i-cceb49a4']) #=>
    #    [{:aws_instance_id=>"i-cceb49a4",
    #      :aws_current_state_code=>32,
    #      :aws_current_state_name=>"shutting-down",
    #      :aws_prev_state_code=>16,
    #      :aws_prev_state_name=>"running"}]
    #
    def terminate_instances(*instance_aws_ids)
      instance_aws_ids = instance_aws_ids.flatten
      link = generate_request("TerminateInstances", amazonize_list('InstanceId', instance_aws_ids))
      request_info(link, QEc2TerminateInstancesParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Retreive EC2 instance OS logs. Returns a hash of data or an exception.
    #
    #  ec2.get_console_output('i-f222222d') =>
    #    {:aws_instance_id => 'i-f222222d',
    #     :aws_timestamp   => "2007-05-23T14:36:07.000-07:00",
    #     :timestamp       => Wed May 23 21:36:07 UTC 2007,          # Time instance
    #     :aws_output      => "Linux version 2.6.16-xenU (builder@patchbat.amazonsa) (gcc version 4.0.1 20050727 ..."
    def get_console_output(instance_id)
      link = generate_request("GetConsoleOutput", { 'InstanceId.1' => instance_id })
      request_info(link, QEc2GetConsoleOutputParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Reboot an EC2 instance. Returns +true+ or an exception.
    #
    #  ec2.reboot_instances(['i-f222222d','i-f222222e']) #=> true
    #
    def reboot_instances(*instances)
      instances = instances.flatten
      link = generate_request("RebootInstances", amazonize_list('InstanceId', instances))
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Describe instance attribute.
    #
    # Attributes: 'instanceType', 'kernel', 'ramdisk', 'userData', 'rootDeviceName', 'disableApiTermination',
    # 'instanceInitiatedShutdownBehavior', 'sourceDestCheck', 'blockDeviceMapping', 'groupSet'
    #
    #  ec2.describe_instance_attribute(instance, "blockDeviceMapping") #=>
    #     [{:ebs_delete_on_termination=>true,
    #       :ebs_volume_id=>"vol-683dc401",
    #       :device_name=>"/dev/sda1"}]
    #
    #  ec2.describe_instance_attribute(instance, "instanceType") #=> "m1.small"
    #
    #  ec2.describe_instance_attribute(instance, "instanceInitiatedShutdownBehavior") #=> "stop"
    #
    def describe_instance_attribute(instance_id, attribute)
      link = generate_request('DescribeInstanceAttribute',
                              'InstanceId' => instance_id,
                              'Attribute'  => attribute)
      value = request_info(link, QEc2DescribeInstanceAttributeParser.new(:logger => @logger))
      value = Base64.decode64(value) if attribute == "userData" && !value.right_blank?
      value
    rescue Exception
      on_exception
    end

    # Describe instance attribute.
    #
    # Attributes: 'kernel', 'ramdisk', 'sourceDestCheck'
    # 
    #  ec2.reset_instance_attribute(instance, 'kernel') #=> true
    #
    def reset_instance_attribute(instance_id, attribute)
      link = generate_request('ResetInstanceAttribute',
                              'InstanceId' => instance_id,
                              'Attribute'  => attribute )
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Modify instance attribute.
    #
    # Attributes: 'InstanceType', 'Kernel', 'Ramdisk', 'UserData', 'DisableApiTermination',
    # 'InstanceInitiatedShutdownBehavior', 'SourceDestCheck', 'GroupId'
    #
    #  ec2.modify_instance_attribute(instance, 'instanceInitiatedShutdownBehavior", "stop") #=> true
    #
    def modify_instance_attribute(instance_id, attribute, value)
      request_hash = {'InstanceId' => instance_id}
      attribute = attribute.to_s.right_underscore.right_camelize
      case attribute
      when 'UserData' then request_hash["#{attribute}.Value"] = Base64.encode64(value).delete("\n")
      when 'GroupId'  then request_hash.merge!(amazonize_list('GroupId', value))
      else                 request_hash["#{attribute}.Value"] = value
      end
      link = generate_request('ModifyInstanceAttribute', request_hash)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #-----------------------------------------------------------------
    #      Instances: Windows addons
    #-----------------------------------------------------------------

    # Get initial Windows Server setup password from an instance console output.
    #
    #  my_awesome_key = ec2.create_key_pair('my_awesome_key') #=>
    #    {:aws_key_name    => "my_awesome_key",
    #     :aws_fingerprint => "01:02:03:f4:25:e6:97:e8:9b:02:1a:26:32:4e:58:6b:7a:8c:9f:03",
    #     :aws_material    => "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAK...Q8MDrCbuQ=\n-----END RSA PRIVATE KEY-----"}
    #
    #  my_awesome_instance = ec2.run_instances('ami-a000000a',1,1,['my_awesome_group'],'my_awesome_key', 'WindowsInstance!!!') #=>
    #   [{:aws_image_id       => "ami-a000000a",
    #     :aws_instance_id    => "i-12345678",
    #     ...
    #     :aws_availability_zone => "us-east-1b"
    #     }]
    #
    #  # wait until instance enters 'operational' state and get it's initial password
    #
    #  puts ec2.get_initial_password(my_awesome_instance[:aws_instance_id], my_awesome_key[:aws_material]) #=> "MhjWcgZuY6"
    #
    def get_initial_password(instance_id, private_key)
      console_output = get_console_output(instance_id)
      crypted_password = console_output[:aws_output][%r{<Password>(.+)</Password>}m] && $1
      unless crypted_password
        raise AwsError.new("Initial password was not found in console output for #{instance_id}")
      else
        OpenSSL::PKey::RSA.new(private_key).private_decrypt(Base64.decode64(crypted_password))
      end
    rescue Exception
      on_exception
    end

    # Get Initial windows instance password using Amazon API call GetPasswordData.
    #
    #  puts ec2.get_initial_password_v2(my_awesome_instance[:aws_instance_id], my_awesome_key[:aws_material]) #=> "MhjWcgZuY6"
    #
    # P.S. To say the truth there is absolutely no any speedup if to compare to the old get_initial_password method... ;(
    #
    def get_initial_password_v2(instance_id, private_key)
      link = generate_request('GetPasswordData',
                              'InstanceId' => instance_id )
      response = request_info(link, QEc2GetPasswordDataParser.new(:logger => @logger))
      if response[:password_data].right_blank?
        raise AwsError.new("Initial password is not yet created for #{instance_id}")
      else
        OpenSSL::PKey::RSA.new(private_key).private_decrypt(Base64.decode64(response[:password_data]))
      end
    rescue Exception
      on_exception
    end

    # Bundle a Windows image.
    # Internally, it queues the bundling task and shuts down the instance.
    # It then takes a snapshot of the Windows volume bundles it, and uploads it to
    # S3. After bundling completes, Rightaws::Ec2#register_image may be used to
    # register the new Windows AMI for subsequent launches.
    #
    #   ec2.bundle_instance('i-e3e24e8a', 'my-awesome-bucket', 'my-win-image-1') #=>
    #    [{:aws_update_time => "2008-10-16T13:58:25.000Z",
    #      :s3_bucket       => "kd-win-1",
    #      :s3_prefix       => "win2pr",
    #      :aws_state       => "pending",
    #      :aws_id          => "bun-26a7424f",
    #      :aws_instance_id => "i-878a25ee",
    #      :aws_start_time  => "2008-10-16T13:58:02.000Z"}]
    #
    def bundle_instance(instance_id, s3_bucket, s3_prefix,
                        s3_owner_aws_access_key_id=nil, s3_owner_aws_secret_access_key=nil,
                        s3_expires = S3Interface::DEFAULT_EXPIRES_AFTER,
                        s3_upload_policy='ec2-bundle-read')
      # S3 access and signatures
      s3_owner_aws_access_key_id     ||= @aws_access_key_id
      s3_owner_aws_secret_access_key ||= @aws_secret_access_key
      s3_expires = Time.now.utc + s3_expires if s3_expires.is_a?(Fixnum) && (s3_expires < S3Interface::ONE_YEAR_IN_SECONDS)
      # policy
      policy = { 'expiration' => AwsUtils::utc_iso8601(s3_expires),
                 'conditions' => [ { 'bucket' => s3_bucket },
                                   { 'acl'    => s3_upload_policy },
                                   [ 'starts-with', '$key', s3_prefix ] ] }.to_json
      policy64        = Base64.encode64(policy).gsub("\n","")
      signed_policy64 = AwsUtils.sign(s3_owner_aws_secret_access_key, policy64)
      # fill request params
      params = { 'InstanceId'                       => instance_id,
                 'Storage.S3.AWSAccessKeyId'        => s3_owner_aws_access_key_id,
                 'Storage.S3.UploadPolicy'          => policy64,
                 'Storage.S3.UploadPolicySignature' => signed_policy64,
                 'Storage.S3.Bucket'                => s3_bucket,
                 'Storage.S3.Prefix'                => s3_prefix,
                 }
      link = generate_request("BundleInstance", params)
      request_info(link, QEc2BundleInstanceParser.new)
    rescue Exception
      on_exception
    end

    # Describe the status of the Windows AMI bundlings.
    #
    # Accepts a list of tasks and/or a set of filters as the last parameter.
    #
    # Filters" bundle-id, error-code, error-message, instance-id, progress, s3-aws-access-key-id, s3-bucket, s3-prefix,
    # start-time, state, update-time
    #
    #  ec2.describe_bundle_tasks('bun-4fa74226') #=>
    #    [{:s3_bucket         => "my-awesome-bucket"
    #      :aws_id            => "bun-0fa70206",
    #      :s3_prefix         => "win1pr",
    #      :aws_start_time    => "2008-10-14T16:27:57.000Z",
    #      :aws_update_time   => "2008-10-14T16:37:10.000Z",
    #      :aws_error_code    => "Client.S3Error",
    #      :aws_error_message =>
    #       "AccessDenied(403)- Invalid according to Policy: Policy Condition failed: [\"eq\", \"$acl\", \"aws-exec-read\"]",
    #      :aws_state         => "failed",
    #      :aws_instance_id   => "i-e3e24e8a"}]
    #
    #   ec2.describe_bundle_tasks(:filters => { 'state' => 'pending' })
    #
    # P.S. filters: http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DescribeBundleTasks.html
    #
    def describe_bundle_tasks(*list_and_options)
      describe_resources_with_list_and_options('DescribeBundleTasks', 'BundleId', QEc2DescribeBundleTasksParser, list_and_options)
    end

    # Cancel an in‐progress or pending bundle task by id.
    #
    #  ec2.cancel_bundle_task('bun-73a7421a') #=>
    #   [{:s3_bucket         => "my-awesome-bucket"
    #     :aws_id            => "bun-0fa70206",
    #     :s3_prefix         => "win02",
    #     :aws_start_time    => "2008-10-14T13:00:29.000Z",
    #     :aws_error_message => "User has requested bundling operation cancellation",
    #     :aws_state         => "failed",
    #     :aws_update_time   => "2008-10-14T13:01:31.000Z",
    #     :aws_error_code    => "Client.Cancelled",
    #     :aws_instance_id   => "i-e3e24e8a"}
    #
    def cancel_bundle_task(bundle_id)
      link = generate_request("CancelBundleTask", { 'BundleId' => bundle_id })
      request_info(link, QEc2BundleInstanceParser.new)
    rescue Exception
      on_exception
    end

    #-----------------------------------------------------------------
    #      PARSERS: Instances
    #-----------------------------------------------------------------

    class QEc2DescribeInstancesParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{(RunInstancesResponse|DescribeInstancesResponse/reservationSet/item)$}
          @reservation = { :aws_groups    => [],
                           :instances_set => [] }
        when %r{(/groupSet/item|instancesSet/item/placement)$}
          @group = {}
        when %r{instancesSet/item$}
            # the optional params (sometimes are missing and we dont want them to be nil)
          @item = { :aws_product_codes => [],
                    :groups            => [],
                    :tags              => {} }
        when %r{blockDeviceMapping/item$}
          @item[:block_device_mappings] ||= []
          @block_device_mapping = {}
        when %r{/tagSet/item$}
          @aws_tag = {}
        end
      end
      def tagend(name)
        case name
        when 'reservationId'    then @reservation[:aws_reservation_id] = @text
        when 'ownerId'          then @reservation[:aws_owner]          = @text
        when 'instanceId'       then @item[:aws_instance_id]       = @text
        when 'imageId'          then @item[:aws_image_id]          = @text
        when 'privateDnsName'   then @item[:private_dns_name]      = @text
        when 'dnsName'          then @item[:dns_name]              = @text
        when 'reason'           then @item[:aws_reason]            = @text
        when 'keyName'          then @item[:ssh_key_name]          = @text
        when 'amiLaunchIndex'   then @item[:ami_launch_index]      = @text
        when 'productCode'      then @item[:aws_product_codes]    << @text
        when 'instanceType'     then @item[:aws_instance_type]     = @text
        when 'launchTime'       then @item[:aws_launch_time]       = @text
        when 'availabilityZone' then @item[:aws_availability_zone] = @text
        when 'kernelId'         then @item[:aws_kernel_id]         = @text
        when 'ramdiskId'        then @item[:aws_ramdisk_id]        = @text
        when 'platform'         then @item[:aws_platform]          = @text
        when 'subnetId'         then @item[:subnet_id]             = @text
        when 'vpcId'            then @item[:vpc_id]                = @text
        when 'privateIpAddress' then @item[:private_ip_address]    = @text
        when 'ipAddress'        then @item[:ip_address]            = @text
        when 'architecture'     then @item[:architecture]          = @text
        when 'rootDeviceType'   then @item[:root_device_type]      = @text
        when 'rootDeviceName'   then @item[:root_device_name]      = @text
        when 'instanceClass'    then @item[:instance_class]        = @text
        when 'instanceLifecycle'     then @item[:instance_lifecycle]       = @text
        when 'spotInstanceRequestId' then @item[:spot_instance_request_id] = @text
        when 'requesterId'           then @item[:requester_id]             = @text
        when 'virtualizationType'    then @item[:virtualization_type]      = @text
        when 'clientToken'           then @item[:client_token]      = @text
        when 'sourceDestCheck'       then @item[:source_dest_check] = @text == 'true' ? true : false
        when 'tenancy'               then @item[:placement_tenancy] = @text
        when 'hypervisor'            then @item[:hypervisor]        = @text
        else
          case full_tag_name
          # EC2 Groups
          when %r{(RunInstancesResponse|/reservationSet/item)/groupSet/item/groupId$}   then @group[:group_id]          = @text
          when %r{(RunInstancesResponse|/reservationSet/item)/groupSet/item/groupName$} then @group[:group_name]        = @text
          when %r{(RunInstancesResponse|/reservationSet/item)/groupSet/item$}           then @reservation[:aws_groups] << @group
          # VPC Groups
          # KD: It seems that these groups are always present when the groups above present for non VPC instances only
          when %r{/instancesSet/item/groupSet/item/groupId$}   then @group[:group_id]   = @text
          when %r{/instancesSet/item/groupSet/item/groupName$} then @group[:group_name] = @text
          when %r{/instancesSet/item/groupSet/item$}           then @item[:groups]     << @group
          # Placement Group Name
          when %r{/placement/groupName$} then @group[:placement_group_name]= @text
          # Codes
          when %r{/stateReason/code$}    then @item[:state_reason_code]    = @text
          when %r{/stateReason/message$} then @item[:state_reason_message] = @text
          when %r{/instanceState/code$}  then @item[:aws_state_code]       = @text.to_i
          when %r{/instanceState/name$}  then @item[:aws_state]            = @text
          when %r{/monitoring/state$}    then @item[:monitoring_state]     = @text
          when %r{/license/pool$}        then @item[:license_pool]         = @text
          when %r{/blockDeviceMapping/item} # no trailing $
            case name
            when 'deviceName'          then @block_device_mapping[:device_name]                = @text
            when 'virtualName'         then @block_device_mapping[:virtual_name]               = @text
            when 'volumeId'            then @block_device_mapping[:ebs_volume_id]              = @text
            when 'status'              then @block_device_mapping[:ebs_status]                 = @text
            when 'attachTime'          then @block_device_mapping[:ebs_attach_time]            = @text
            when 'deleteOnTermination' then @block_device_mapping[:ebs_delete_on_termination]  = @text == 'true' ? true : false
            when 'item'                then @item[:block_device_mappings]                     << @block_device_mapping
            end
          when %r{/instancesSet/item$} then @reservation[:instances_set] << @item
          when %r{/tagSet/item/key$}   then @aws_tag[:key]               = @text
          when %r{/tagSet/item/value$} then @aws_tag[:value]             = @text
          when %r{/tagSet/item$}       then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
          when %r{(RunInstancesResponse|DescribeInstancesResponse/reservationSet/item)$} then @result << @reservation
          end
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2ConfirmProductInstanceParser < RightAWSParser #:nodoc:
      def tagend(name)
        @result = @text if name == 'ownerId'
      end
    end

    class QEc2TerminateInstancesParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @instance = {} if name == 'item'
      end
      def tagend(name)
        case full_tag_name
        when %r{/instanceId$}         then @instance[:aws_instance_id]        = @text
        when %r{/currentState/code$}  then @instance[:aws_current_state_code] = @text.to_i
        when %r{/currentState/name$}  then @instance[:aws_current_state_name] = @text
        when %r{/previousState/code$} then @instance[:aws_prev_state_code]    = @text.to_i
        when %r{/previousState/name$} then @instance[:aws_prev_state_name]    = @text
        when %r{/item$}               then @result << @instance
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2DescribeInstanceAttributeParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{groupSet$}                then @result = []
        when %r{groupSet/item$}           then @group  = {}
        when %r{blockDeviceMapping$}      then @result = []
        when %r{blockDeviceMapping/item$} then @block_device_mapping = {}
        end
      end
      def tagend(name)
        case full_tag_name
        when %r{/instanceType/value$}   then @result = @text
        when %r{/kernel/value$}         then @result = @text
        when %r{/ramdisk/value$}        then @result = @text
        when %r{/userData/value$}       then @result = @text
        when %r{/rootDeviceName/value$} then @result = @text
        when %r{/disableApiTermination/value}              then @result = @text == 'true' ? true : false
        when %r{/instanceInitiatedShutdownBehavior/value$} then @result = @text
        when %r{/sourceDestCheck/value$}                   then @result = @text == 'true' ? true : false
        when %r{/groupSet/item} # no trailing $
          case name
          when 'groupId'   then @group[:group_id]   = @text
          when 'groupName' then @group[:group_name] = @text
          when 'item'      then @result << @group
          end
        when %r{/blockDeviceMapping/item} # no trailing $
          case name
          when 'deviceName'          then @block_device_mapping[:device_name]                = @text
          when 'virtualName'         then @block_device_mapping[:virtual_name]               = @text
          when 'noDevice'            then @block_device_mapping[:no_device]                  = @text
          when 'volumeId'            then @block_device_mapping[:ebs_volume_id]              = @text
          when 'status'              then @block_device_mapping[:ebs_status]                 = @text
          when 'attachTime'          then @block_device_mapping[:ebs_attach_time]            = @text
          when 'deleteOnTermination' then @block_device_mapping[:ebs_delete_on_termination]  = @text == 'true' ? true : false
          when 'item'                then @result                                           << @block_device_mapping
          end
        end
      end
      def reset
        @result = nil
      end
    end

  #-----------------------------------------------------------------
  #      PARSERS: Console
  #-----------------------------------------------------------------

    class QEc2GetConsoleOutputParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'instanceId' then @result[:aws_instance_id] = @text
        when 'timestamp'  then @result[:aws_timestamp]   = @text
                               @result[:timestamp]       = (Time.parse(@text)).utc
        when 'output'     then @result[:aws_output]      = Base64.decode64(@text)
        end
      end
      def reset
        @result = {}
      end
    end

  #-----------------------------------------------------------------
  #      Instances: Windows related part
  #-----------------------------------------------------------------

    class QEc2DescribeBundleTasksParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @bundle = {} if name == 'item'
      end
      def tagend(name)
        case name
#        when 'requestId'  then @bundle[:request_id]    = @text
        when 'instanceId' then @bundle[:aws_instance_id]   = @text
        when 'bundleId'   then @bundle[:aws_id]            = @text
        when 'bucket'     then @bundle[:s3_bucket]         = @text
        when 'prefix'     then @bundle[:s3_prefix]         = @text
        when 'startTime'  then @bundle[:aws_start_time]    = @text
        when 'updateTime' then @bundle[:aws_update_time]   = @text
        when 'state'      then @bundle[:aws_state]         = @text
        when 'progress'   then @bundle[:aws_progress]      = @text
        when 'code'       then @bundle[:aws_error_code]    = @text
        when 'message'    then @bundle[:aws_error_message] = @text
        when 'item'       then @result                    << @bundle
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2BundleInstanceParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
#        when 'requestId'  then @result[:request_id]    = @text
        when 'instanceId' then @result[:aws_instance_id]   = @text
        when 'bundleId'   then @result[:aws_id]            = @text
        when 'bucket'     then @result[:s3_bucket]         = @text
        when 'prefix'     then @result[:s3_prefix]         = @text
        when 'startTime'  then @result[:aws_start_time]    = @text
        when 'updateTime' then @result[:aws_update_time]   = @text
        when 'state'      then @result[:aws_state]         = @text
        when 'progress'   then @result[:aws_progress]      = @text
        when 'code'       then @result[:aws_error_code]    = @text
        when 'message'    then @result[:aws_error_message] = @text
        end
      end
      def reset
        @result = {}
      end
    end

    class QEc2GetPasswordDataParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'instanceId'   then @result[:aws_instance_id] = @text
        when 'timestamp'    then @result[:timestamp]       = @text
        when 'passwordData' then @result[:password_data]   = @text
        end
      end
      def reset
        @result = {}
      end
    end

  end

end