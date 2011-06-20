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
    #      Spot Instances
    #-----------------------------------------------------------------

    # Describe Spot Price history.
    #
    # Options: :start_time, :end_time, instance_types, product_description
    # 
    # Filters: instance-type, product-description, spot-price, timestamp
    #
    #  ec2.describe_spot_price_history #=>
    #    [{:spot_price=>0.054,
    #      :timestamp=>"2009-12-07T12:12:58.000Z",
    #      :product_description=>"Windows",
    #      :instance_type=>"m1.small"},
    #     {:spot_price=>0.06,
    #      :timestamp=>"2009-12-07T12:18:32.000Z",
    #      :product_description=>"Linux/UNIX",
    #      :instance_type=>"c1.medium"},
    #     {:spot_price=>0.198,
    #      :timestamp=>"2009-12-07T12:58:00.000Z",
    #      :product_description=>"Windows",
    #      :instance_type=>"m1.large"},
    #     {:spot_price=>0.028,
    #      :timestamp=>"2009-12-07T13:48:50.000Z",
    #      :product_description=>"Linux/UNIX",
    #      :instance_type=>"m1.small"}, ... ]
    #
    #  ec2.describe_spot_price_history(:start_time => 1.day.ago,
    #                                  :end_time => 10.minutes.ago,
    #                                  :instance_types => ["c1.medium", "m1.small"],
    #                                  :product_description => "Linux/UNIX" ) #=>
    #    [{:product_description=>"Linux/UNIX",
    #      :timestamp=>"2010-02-04T05:44:36.000Z",
    #      :spot_price=>0.031,
    #      :instance_type=>"m1.small"},
    #     {:product_description=>"Linux/UNIX",
    #      :timestamp=>"2010-02-04T17:56:25.000Z",
    #      :spot_price=>0.058,
    #      :instance_type=>"c1.medium"}, ... ]
    #
    #  ec2.describe_spot_price_history(:filters => {'spot-price' => '0.2' })
    #
    #  ec2.describe_spot_price_history(:instance_types => ["c1.medium"], :filters => {'spot-price' => '0.2' })
    #
    #
    # P.S. filters: http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-DescribeSpotPriceHistory.html
    #
    def describe_spot_price_history(options={})
      options = options.dup
      request_hash = {}
      request_hash.merge!(amazonize_list(['Filter.?.Name', 'Filter.?.Value.?'], options[:filters])) unless options[:filters].right_blank?
      request_hash['StartTime']          = AwsUtils::utc_iso8601(options[:start_time])      unless options[:start_time].right_blank?
      request_hash['EndTime']            = AwsUtils::utc_iso8601(options[:end_time])        unless options[:end_time].right_blank?
      request_hash['ProductDescription'] = options[:product_description]                   unless options[:product_description].right_blank?
      request_hash.merge!(amazonize_list('InstanceType', Array(options[:instance_types]))) unless options[:instance_types].right_blank?
      link = generate_request("DescribeSpotPriceHistory", request_hash, :api_version => '2011-05-15')
      request_info(link, QEc2DescribeSpotPriceHistoryParser.new)
    rescue Exception
      on_exception
    end

    # Describe Spot Instance requests.
    #
    # Accepts a list of requests and/or a set of filters as the last parameter.
    #
    # Filters: availability-zone-group, create-time, fault-code, fault-message, instance-id, launch-group,
    # launch.block-device-mapping.delete-on-termination, launch.block-device-mapping.device-name,
    # launch.block-device-mapping.snapshot-id, launch.group-id, launch.image-id, launch.instance-type,
    # launch.kernel-id, launch.key-name, launch.monitoring-enabled, launch.ramdisk-id, product-description,
    # spot-instance-request-id, spot-price, state, tag-key, tag-value, tag:key, type, valid-from, valid-until
    #
    #  ec2.describe_spot_instance_requests #=>
    #    [{:product_description=>"Linux/UNIX",
    #      :type=>"one-time",
    #      :availability_zone=>"us-east-1b",
    #      :monitoring_enabled=>false,
    #      :tags=>{},
    #      :image_id=>"ami-08f41161",
    #      :groups=>[{:group_id=>"sg-a0b85dc9", :group_name=>"default"}],
    #      :spot_price=>0.01,
    #      :create_time=>"2010-03-24T10:41:28.000Z",
    #      :instance_type=>"c1.medium",
    #      :state=>"open",
    #      :spot_instance_request_id=>"sir-9652a604",
    #      :key_name=>"rightscale_test"},
    #     {:product_description=>"Linux/UNIX",
    #      :type=>"one-time",
    #      :availability_zone=>"us-east-1b",
    #      :monitoring_enabled=>false,
    #      :tags=>{},
    #      :image_id=>"ami-08f41161",
    #      :groups=>[{:group_id=>"sg-a0b85dc9", :group_name=>"default"}],
    #      :spot_price=>0.01,
    #      :create_time=>"2010-03-24T11:40:27.000Z",
    #      :instance_type=>"c1.medium",
    #      :state=>"open",
    #      :spot_instance_request_id=>"sir-fa912802",
    #      :key_name=>"rightscale_test"}, ... ]
    #
    #  ec2.describe_spot_instance_requests(:filters => {'type'=>"one-time", 'state'=>"open"})
    #  
    # P.S. filters: http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-DescribeSpotInstanceRequests.html
    #
    def describe_spot_instance_requests(*list_and_options)
      describe_resources_with_list_and_options('DescribeSpotInstanceRequests', 'SpotInstanceRequestId', QEc2DescribeSpotInstanceParser, list_and_options)
    end

    # Create a Spot Instance request.
    #
    # Mandatory params: :image_id, :spot_price, :instance_type
    # Optional params: :valid_from, :valid_until, :instance_count, :type, :launch_group,
    # :availability_zone_group, :key_name, :user_data, :addressing_type, :kernel_id,
    # :ramdisk_id, :subnet_id, :availability_zone, :monitoring_enabled, :groups,
    # :block_device_mappings
    #
    #  ec2.request_spot_instances(
    #    :image_id => 'ami-08f41161',
    #    :spot_price => 0.01,
    #    :key_name => 'tim',
    #    :instance_count => 2,
    #    :group_ids => ["sg-a0b85dc9"],
    #    :instance_type => 'c1.medium') #=>
    #    
    #    [{:product_description=>"Linux/UNIX",
    #      :type=>"one-time",
    #      :spot_instance_requestId=>"sir-7a893003",
    #      :monitoring_enabled=>false,
    #      :image_id=>"ami-08f41161",
    #      :state=>"open",
    #      :spot_price=>0.01,
    #      :groups=>[{:group_id=>"sg-a0b85dc9", :group_name=>"default"}],
    #      :key_name=>"tim",
    #      :create_time=>"2010-03-10T10:33:09.000Z",
    #      :instance_type=>"c1.medium"},
    #     {:product_description=>"Linux/UNIX",
    #      :type=>"one-time",
    #      :spot_instance_requestId=>"sir-13dc9a03",
    #      :monitoring_enabled=>false,
    #      :image_id=>"ami-08f41161",
    #      :state=>"open",
    #      :spot_price=>0.01,
    #      :groups=>[{:group_id=>"sg-a0b85dc9", :group_name=>"default"}],
    #      :key_name=>"tim",
    #      :create_time=>"2010-03-10T10:33:09.000Z",
    #      :instance_type=>"c1.medium"}]
    #
    #  ec2.request_spot_instances(
    #    :image_id => 'ami-08f41161',
    #    :spot_price => 0.01,
    #    :instance_type => 'm1.small',
    #    :valid_from => 10.minutes.since,
    #    :valid_until => 1.hour.since,
    #    :instance_count => 1,
    #    :key_name => 'tim',
    #    :group_names => ['default'],
    #    :availability_zone => 'us-east-1a',
    #    :monitoring_enabled => true,
    #    :launch_group => 'lg1',
    #    :availability_zone_group => 'azg1',
    #    :block_device_mappings => [ { :device_name => '/dev/sdk',
    #                                  :ebs_snapshot_id => 'snap-145cbc7d',
    #                                  :ebs_delete_on_termination => true,
    #                                  :ebs_volume_size => 3,
    #                                  :virtual_name => 'ephemeral2'
    #                                 } ] ) #=>
    #    [{:type=>"one-time",
    #      :image_id=>"ami-08f41161",
    #      :availability_zone_group=>"azg1",
    #      :key_name=>"default",
    #      :spot_instance_request_id=>"sir-66c79a12",
    #      :block_device_mappings=>
    #       [{:ebs_volume_size=>3,
    #         :virtual_name=>"ephemeral2",
    #         :device_name=>"/dev/sdk",
    #         :ebs_snapshot_id=>"snap-145cbc7d",
    #         :ebs_delete_on_termination=>true}],
    #      :spot_price=>0.01,
    #      :product_description=>"Linux/UNIX",
    #      :state=>"open",
    #      :instance_type=>"m1.small",
    #      :availability_zone=>"us-east-1a",
    #      :groups=>[{:group_id=>"sg-a0b85dc9", :group_name=>"default"}],
    #      :valid_from=>"2011-07-01T14:26:33.000Z",
    #      :tags=>{},
    #      :monitoring_enabled=>true,
    #      :valid_until=>"2011-07-01T14:28:03.000Z",
    #      :create_time=>"2011-07-01T14:26:24.000Z",
    #      :launch_group=>"lg1"}]
    #
    def request_spot_instances(options)
      options[:user_data] = options[:user_data].to_s
      request_hash = map_api_keys_and_values( options,
        :spot_price, :availability_zone_group, :launch_group, :type, :instance_count,
        :image_id              => 'LaunchSpecification.ImageId',
        :instance_type         => 'LaunchSpecification.InstanceType',
        :key_name              => 'LaunchSpecification.KeyName',
        :addressing_type       => 'LaunchSpecification.AddressingType',
        :kernel_id             => 'LaunchSpecification.KernelId',
        :ramdisk_id            => 'LaunchSpecification.RamdiskId',
        :subnet_id             => 'LaunchSpecification.SubnetId',
        :availability_zone     => 'LaunchSpecification.Placement.AvailabilityZone',
        :monitoring_enabled    => 'LaunchSpecification.Monitoring.Enabled',
        :valid_from            => { :value => Proc.new { !options[:valid_from].right_blank?  && AwsUtils::utc_iso8601(options[:valid_from]) }},
        :valid_until           => { :value => Proc.new { !options[:valid_until].right_blank? && AwsUtils::utc_iso8601(options[:valid_until]) }},
        :user_data             => { :name  => 'LaunchSpecification.UserData',
                                    :value => Proc.new { !options[:user_data].empty? && Base64.encode64(options[:user_data]).delete("\n") }},
        :group_names           => { :amazonize_list => 'LaunchSpecification.SecurityGroup'},
        :group_ids             => { :amazonize_list => 'LaunchSpecification.SecurityGroupId'},
        :block_device_mappings => { :amazonize_bdm  => 'LaunchSpecification.BlockDeviceMapping'})
      link = generate_request("RequestSpotInstances", request_hash)
      request_info(link, QEc2DescribeSpotInstanceParser.new(:logger => @logger))
    end

    # Cancel one or more Spot Instance requests.
    #
    #  ec2.cancel_spot_instance_requests('sir-60662c03',"sir-d3c96e04", "sir-4fa8d804","sir-6992ce04") #=>
    #    [{:state=>"cancelled", :spot_instance_request_id=>"sir-60662c03"},
    #     {:state=>"cancelled", :spot_instance_request_id=>"sir-6992ce04"},
    #     {:state=>"cancelled", :spot_instance_request_id=>"sir-4fa8d804"},
    #     {:state=>"cancelled", :spot_instance_request_id=>"sir-d3c96e04"}]
    #
    def cancel_spot_instance_requests(*spot_instance_request_ids)
      link = generate_request("CancelSpotInstanceRequests", amazonize_list('SpotInstanceRequestId', spot_instance_request_ids.flatten))
      request_info(link, QEc2CancelSpotInstanceParser.new(:logger => @logger))
    end

    # Create the data feed for Spot Instances
    # (Enables to view Spot Instance usage logs)
    #
    #  ec2.create_spot_datafeed_subscription('bucket-for-konstantin-eu', 'splogs/') #=>
    #    { :owner_id=>"826693181925",
    #      :bucket=>"bucket-for-konstantin-eu",
    #      :prefix=>"splogs/",
    #      :state=>"Active"}
    #
    def create_spot_datafeed_subscription(bucket, prefix=nil)
      request_hash = { 'Bucket' => bucket }
      request_hash['Prefix'] = prefix unless prefix.right_blank?
      link = generate_request("CreateSpotDatafeedSubscription", request_hash)
      request_info(link, QEc2DescribeSpotDatafeedSubscriptionParser.new(:logger => @logger))
    end

    # Describe the data feed for Spot Instances.
    #
    #  ec2.describe_spot_datafeed_subscription #=>
    #    { :owner_id=>"826693181925",
    #      :bucket=>"bucket-for-konstantin-eu",
    #      :prefix=>"splogs/",
    #      :state=>"Active"}
    #
    def describe_spot_datafeed_subscription
      link = generate_request("DescribeSpotDatafeedSubscription")
      request_info(link, QEc2DescribeSpotDatafeedSubscriptionParser.new(:logger => @logger))
    end

    # Delete the data feed for Spot Instances.
    #
    #  ec2.delete_spot_datafeed_subscription #=> true
    #
    def delete_spot_datafeed_subscription()
      link = generate_request("DeleteSpotDatafeedSubscription")
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS: Spot Instances
    #-----------------------------------------------------------------

    class QEc2DescribeSpotPriceHistoryParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @item = {} if name == 'item'
      end
      def tagend(name)
        case name
        when 'instanceType'       then @item[:instance_type]       = @text
        when 'productDescription' then @item[:product_description] = @text
        when 'spotPrice'          then @item[:spot_price]          = @text.to_f
        when 'timestamp'          then @item[:timestamp]           = @text
        when 'availabilityZone'   then @item[:availability_zone]   = @text
        when 'item'               then @result                    << @item
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2DescribeSpotInstanceParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{spotInstanceRequestSet/item$}
          @item = { :tags => {} }
        when %r{groupSet$}
          @item[:groups] = []
        when %r{groupSet/item$}
          @group  = {}
        when %r{/blockDeviceMapping/item$}
          @item[:block_device_mappings] ||= []
          @block_device_mapping = {}
        when %r{/tagSet/item$}
          @aws_tag = {}
        end
      end
      def tagend(name)
        case name
        when 'spotInstanceRequestId' then @item[:spot_instance_request_id]= @text
        when 'spotPrice'             then @item[:spot_price]              = @text.to_f
        when 'type'                  then @item[:type]                    = @text
        when 'state'                 then @item[:state]                   = @text
        when 'code'                  then @item[:fault_code]              = @text
        when 'message'               then @item[:fault_message]           = @text
        when 'validFrom'             then @item[:valid_from]              = @text
        when 'validUntil'            then @item[:valid_until]             = @text
        when 'launchGroup'           then @item[:launch_group]            = @text
        when 'availabilityZoneGroup' then @item[:availability_zone_group] = @text
        when 'imageId'               then @item[:image_id]                = @text
        when 'keyName'               then @item[:key_name]                = @text
        when 'userData'              then @item[:userData]                = @text
        when 'data'                  then @item[:data]                    = @text
        when 'addressingType'        then @item[:addressing_type]         = @text
        when 'instanceType'          then @item[:instance_type]           = @text
        when 'availabilityZone'      then @item[:availability_zone]       = @text
        when 'kernelId'              then @item[:kernel_id]               = @text
        when 'ramdiskId'             then @item[:ramdisk_id]              = @text
        when 'subnetId'              then @item[:subnet_id]               = @text
        when 'instanceId'            then @item[:instance_id]             = @text
        when 'createTime'            then @item[:create_time]             = @text
        when 'productDescription'    then @item[:product_description]     = @text
        else
          case full_tag_name
          when %r{/groupSet/item} # no trailing $
            case name
            when 'groupId'   then @group[:group_id]   = @text
            when 'groupName' then @group[:group_name] = @text
            when 'item'      then @item[:groups]     << @group
            end
          when %r{monitoring/enabled$}
            @item[:monitoring_enabled] = @text == 'true'
          when %r{/blockDeviceMapping/item} # no trailing $
            case name
            when 'deviceName'          then @block_device_mapping[:device_name]                = @text
            when 'virtualName'         then @block_device_mapping[:virtual_name]               = @text
            when 'volumeSize'          then @block_device_mapping[:ebs_volume_size]            = @text.to_i
            when 'snapshotId'          then @block_device_mapping[:ebs_snapshot_id]            = @text
            when 'deleteOnTermination' then @block_device_mapping[:ebs_delete_on_termination]  = @text == 'true' ? true : false
            when 'item'                then @item[:block_device_mappings]                     << @block_device_mapping
            end
          when %r{/tagSet/item/key$}   then @aws_tag[:key]               = @text
          when %r{/tagSet/item/value$} then @aws_tag[:value]             = @text
          when %r{/tagSet/item$}       then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
          when %r{spotInstanceRequestSet/item$} then @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2CancelSpotInstanceParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @item = {} if name == 'item'
      end
      def tagend(name)
        case name
        when 'spotInstanceRequestId' then @item[:spot_instance_request_id] = @text
        when 'state'                 then @item[:state]                    = @text
        when 'item'                  then @result                         << @item
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2DescribeSpotDatafeedSubscriptionParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'ownerId' then @result[:owner_id] = @text
        when 'bucket'  then @result[:bucket]   = @text
        when 'prefix'  then @result[:prefix]   = @text
        when 'state'   then @result[:state]    = @text
        when 'code'    then @result[:fault_code]     = @text
        when 'message' then @result[:fault_message]  = @text
        end
      end
      def reset
        @result = {}
      end
    end
    
  end

end