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
    # Options: :start_time, :end_time, instance_types, product_description
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
    def describe_spot_price_history(options={})
      options = options.dup
      request_hash = {}
      request_hash['StartTime']          = AwsUtils::utc_iso8601(options[:start_time])     unless options[:start_time].blank?
      request_hash['EndTime']            = AwsUtils::utc_iso8601(options[:end_time])       unless options[:end_time].blank?
      request_hash['ProductDescription'] = options[:product_description]                   unless options[:product_description].blank?
      request_hash.merge!(amazonize_list('InstanceType', Array(options[:instance_types]))) unless options[:instance_types].blank?
      link = generate_request("DescribeSpotPriceHistory", request_hash)
      request_info(link, QEc2DescribeSpotPriceHistoryParser.new)
    rescue Exception
      on_exception
    end

    # Describe Spot Instance requests.
    #
    #  ec2.describe_spot_instance_requests #=>
    #    [{:type=>"one-time",
    #      :create_time=>"2010-03-10T10:30:32.000Z",
    #      :instance_type=>"c1.medium",
    #      :state=>"cancelled",
    #      :groups=>["default"],
    #      :product_description=>"Linux/UNIX",
    #      :spot_instance_request_id=>"sir-bfa06804",
    #      :image_id=>"ami-08f41161",
    #      :spot_price=>0.01,
    #      :monitoring_enabled=>false},
    #     {:type=>"one-time",
    #      :create_time=>"2010-03-10T10:33:29.000Z",
    #      :instance_type=>"c1.medium",
    #      :state=>"open",
    #      :groups=>["default", "33"],
    #      :product_description=>"Linux/UNIX",
    #      :spot_instance_request_id=>"sir-b1713a03",
    #      :image_id=>"ami-08f41161",
    #      :spot_price=>0.01,
    #      :monitoring_enabled=>false,
    #      :key_name=>"tim"},
    #     {:type=>"one-time",
    #      :instance_id=>"i-c516ceae",
    #      :create_time=>"2010-03-10T10:43:48.000Z",
    #      :instance_type=>"c1.medium",
    #      :state=>"active",
    #      :groups=>["default", "33"],
    #      :product_description=>"Linux/UNIX",
    #      :spot_instance_request_id=>"sir-5eb6c604",
    #      :image_id=>"ami-08f41161",
    #      :spot_price=>0.2,
    #      :monitoring_enabled=>false,
    #      :key_name=>"tim"}]
    #
    def describe_spot_instance_requests(*spot_instance_request_ids)
      link = generate_request("DescribeSpotInstanceRequests", amazonize_list('SpotInstanceRequestId', spot_instance_request_ids.flatten))
      request_info(link, QEc2DescribeSpotInstanceParser.new(:logger => @logger))
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
    #    :groups => ['33','default'],
    #    :instance_type => 'c1.medium') #=>
    #    
    #    [{:product_description=>"Linux/UNIX",
    #      :type=>"one-time",
    #      :spot_instance_requestId=>"sir-7a893003",
    #      :monitoring_enabled=>false,
    #      :image_id=>"ami-08f41161",
    #      :state=>"open",
    #      :spot_price=>0.01,
    #      :groups=>["default", "33"],
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
    #      :groups=>["default", "33"],
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
    #    :groups => ['33','default'],
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
    #
    #    [{:monitoring_enabled=>true,
    #      :type=>"one-time",
    #      :image_id=>"ami-08f41161",
    #      :launch_group=>"lg1",
    #      :state=>"open",
    #      :valid_until=>"2010-02-05T19:13:44.000Z",
    #      :create_time=>"2010-02-05T18:13:46.000Z",
    #      :availability_zone_group=>"azg1",
    #      :spot_price=>0.01,
    #      :block_device_mappings=>
    #       [{:ebs_delete_on_termination=>true,
    #         :ebs_volume_size=>3,
    #         :virtual_name=>"ephemeral2",
    #         :device_name=>"/dev/sdk",
    #         :ebs_snapshot_id=>"snap-145cbc7d"}],
    #      :instance_type=>"m1.small",
    #      :groups=>["default", "33"],
    #      :product_description=>"Linux/UNIX",
    #      :key_name=>"tim",
    #      :valid_from=>"2010-02-05T18:23:44.000Z",
    #      :availability_zone=>"us-east-1a",
    #      :spot_instance_request_id=>"sir-32da8a03"}]
    #
    def request_spot_instances(options)
      options = options.dup
      request_hash = { 'SpotPrice'                        => options[:spot_price],
                       'LaunchSpecification.ImageId'      => options[:image_id],
                       'LaunchSpecification.InstanceType' => options[:instance_type]}
      request_hash['ValidFrom']                      = AwsUtils::utc_iso8601(options[:valid_from])  unless options[:valid_from].blank?
      request_hash['ValidUntil']                     = AwsUtils::utc_iso8601(options[:valid_until]) unless options[:valid_until].blank?
      request_hash['InstanceCount']                      = options[:instance_count]                 unless options[:instance_count].blank?
      request_hash['Type']                               = options[:type]                           unless options[:type].blank?
      request_hash['LaunchGroup']                        = options[:launch_group]                   unless options[:launch_group].blank?
      request_hash['AvailabilityZoneGroup']              = options[:availability_zone_group]        unless options[:availability_zone_group].blank?
      request_hash['LaunchSpecification.KeyName']        = options[:key_name]                       unless options[:key_name].blank?
      request_hash['LaunchSpecification.AddressingType'] = options[:addressing_type]                unless options[:addressing_type].blank?
      request_hash['LaunchSpecification.KernelId']       = options[:kernel_id]                      unless options[:kernel_id].blank?
      request_hash['LaunchSpecification.RamdiskId']      = options[:ramdisk_id]                     unless options[:ramdisk_id].blank?
      request_hash['LaunchSpecification.SubnetId']       = options[:subnet_id]                      unless options[:subnet_id].blank?
      request_hash['LaunchSpecification.Placement.AvailabilityZone'] = options[:availability_zone]  unless options[:availability_zone].blank?
      request_hash['LaunchSpecification.Monitoring.Enabled']         = options[:monitoring_enabled] unless options[:monitoring_enabled].blank?
      request_hash.merge!(amazonize_list('LaunchSpecification.SecurityGroup', options[:groups]))    unless options[:groups].blank?
      request_hash.merge!(amazonize_block_device_mappings(options[:block_device_mappings], 'LaunchSpecification.BlockDeviceMapping'))
      unless options[:user_data].blank?
        # See RightAws::Ec2#run_instances
        options[:user_data].strip!
        request_hash['LaunchSpecification.UserData'] = Base64.encode64(options[:user_data]).delete("\n") unless options[:user_data].blank?
      end
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
      request_hash['Prefix'] = prefix unless prefix.blank?
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
          @item = {}
        when %r{/blockDeviceMapping/item$}
          @item[:block_device_mappings] ||= []
          @block_device_mapping = {}
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
        when 'groupId'               then (@item[:groups] ||= [])        << @text
        else
          case full_tag_name
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
          when %r{spotInstanceRequestSet/item$}
            @result << @item
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
        when 'fault'   then @result[:fault]    = @text
        when 'code'    then @result[:code]     = @text
        when 'message' then @result[:message]  = @text
        end
      end
      def reset
        @result = {}
      end
    end
    
  end

end