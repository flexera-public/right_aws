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
    #      Images
    #-----------------------------------------------------------------

    # Describe images helper
    # params:
    #   { 'ImageId'      => ['id1', ..., 'idN'],
    #     'Owner'        => ['self', ..., 'userN'],
    #     'ExecutableBy' => ['self', 'all', ..., 'userN']
    #   }
    def ec2_describe_images(params={}, image_type=nil, cache_for=nil) #:nodoc:
      request_hash = {}
      params.each do |list_by, list|
        request_hash.merge! amazonize_list(list_by, Array(list))
      end
      request_hash['ImageType'] = image_type if image_type
      link = generate_request("DescribeImages", request_hash)
      request_cache_or_info cache_for, link,  QEc2DescribeImagesParser, @@bench, cache_for
    rescue Exception
      on_exception
    end

    # Retrieve a list of images. Returns array of hashes describing the images or an exception:
    # +image_type+ = 'machine' || 'kernel' || 'ramdisk'
    #
    #  ec2.describe_images #=>
    #    [{:aws_id=>"ami-b0a1f7a6",
    #      :aws_image_type=>"machine",
    #      :root_device_name=>"/dev/sda1",
    #      :image_class=>"static",
    #      :aws_owner=>"826693181925",
    #      :aws_location=>"bucket_for_k_dzreyev/image_bundles/kd__CentOS_1_10_2009_10_21_13_30_43_MSD/image.manifest.xml",
    #      :aws_state=>"available",
    #      :aws_is_public=>false,
    #      :aws_architecture=>"i386"},
    #     {:description=>"EBS backed Fedora core 8 i386",
    #      :aws_architecture=>"i386",
    #      :aws_id=>"ami-c2a3f5d4",
    #      :aws_image_type=>"machine",
    #      :root_device_name=>"/dev/sda1",
    #      :image_class=>"elastic",
    #      :aws_owner=>"937766719418",
    #      :aws_location=>"937766719418/EBS backed FC8 i386",
    #      :aws_state=>"available",
    #      :block_device_mappings=>
    #       [{:ebs_snapshot_id=>"snap-829a20eb",
    #         :ebs_delete_on_termination=>true,
    #         :device_name=>"/dev/sda1"}],
    #      :name=>"EBS backed FC8 i386",
    #      :aws_is_public=>true}, ... ]
    #      
    # If +list+ param is set, then retrieve information about the listed images only:
    #
    #  ec2.describe_images(['ami-5aa1f74c'])
    #
    def describe_images(images=[], image_type=nil)
      images = Array(images)
      cache_for = images.empty? && !image_type ? :describe_images : nil
      ec2_describe_images({ 'ImageId' => images }, image_type, cache_for)
    end

    #  Example:
    #
    #   ec2.describe_images_by_owner('522821470517')
    #   ec2.describe_images_by_owner('self')
    #
    def describe_images_by_owner(owners=['self'], image_type=nil)
      owners = Array(owners)
      cache_for = (owners == ['self']) && (!image_type ? :describe_images_by_owner : nil)
      ec2_describe_images({ 'Owner' => owners }, image_type, cache_for)
    end

    #  Example:
    #
    #   ec2.describe_images_by_executable_by('522821470517')
    #   ec2.describe_images_by_executable_by('self')
    #   ec2.describe_images_by_executable_by('all')
    #
    def describe_images_by_executable_by(executable_by=['self'], image_type=nil)
      executable_by = Array(executable_by)
      cache_for = (executable_by==['self']) && (!image_type ? :describe_images_by_executable_by : nil)
      ec2_describe_images({ 'ExecutableBy' => executable_by }, image_type, cache_for)
    end


    # Register new image at Amazon.
    # Options: :image_location, :name, :description, :architecture, :kernel_id, :ramdisk_id, :root_device_name, :block_device_mappings.
    #
    # Returns new image id.
    #
    #  # Register S3 image
    #  ec2.register_image('bucket_for_k_dzreyev/image_bundles/kd__CentOS_1_10_2009_10_21_13_30_43_MSD/image.manifest.xml') #=> 'ami-e444444d'
    #
    #  # or
    #  image_reg_params = {  :image_location => 'bucket_for_k_dzreyev/image_bundles/kd__CentOS_1_10_2009_10_21_13_30_43_MSD/image.manifest.xml',
    #                        :name => 'my-test-one-1',
    #                        :description => 'My first test image' }
    #  ec2.register_image(image_reg_params) #=> "ami-bca1f7aa"
    #
    #  # Register EBS image
    #  image_reg_params = { :name        => 'my-test-image',
    #                       :description => 'My first test image',
    #                       :root_device_name => "/dev/sda1",
    #                       :block_device_mappings => [ { :ebs_snapshot_id=>"snap-7360871a",
    #                                                     :ebs_delete_on_termination=>true,
    #                                                     :device_name=>"/dev/sda1"} ] }
    #  ec2.register_image(image_reg_params) #=> "ami-b2a1f7a4"
    #
    def register_image(options)
      case
      when options.is_a?(String)
        options = { :image_location => options }
      when !options.is_a?(Hash)
        raise "Unsupported options type"
      end
      params = {}
      params['ImageLocation']  = options[:image_location]   if options[:image_location]
      params['Name']           = options[:name]             if options[:name]
      params['Description']    = options[:description]      if options[:description]
      params['Architecture']   = options[:architecture]     if options[:architecture]
      params['KernelId']       = options[:kernel_id]        if options[:kernel_id]
      params['RamdiskId']      = options[:ramdisk_id]       if options[:ramdisk_id]
      params['RootDeviceName'] = options[:root_device_name] if options[:root_device_name]
#      params['SnapshotId']     = options[:snapshot_id]      if options[:snapshot_id]
      params.merge!(amazonize_block_device_mappings(options[:block_device_mappings]))
      link = generate_request("RegisterImage", params)
      request_info(link, QEc2RegisterImageParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Deregister image at Amazon. Returns +true+ or an exception.
    #
    #  ec2.deregister_image('ami-e444444d') #=> true
    #
    def deregister_image(image_id)
      link = generate_request("DeregisterImage",
                              'ImageId' => image_id.to_s)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Describe image attributes. Currently 'launchPermission', 'productCodes', 'kernel', 'ramdisk' and 'blockDeviceMapping'  are supported.
    #
    #  ec2.describe_image_attribute('ami-e444444d') #=> {:groups=>["all"], :users=>["000000000777"]}
    #
    def describe_image_attribute(image_id, attribute='launchPermission')
      link = generate_request("DescribeImageAttribute",
                              'ImageId'   => image_id,
                              'Attribute' => attribute)
      request_info(link, QEc2DescribeImageAttributeParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Reset image attribute. Currently, only 'launchPermission' is supported. Returns +true+ or an exception.
    #
    #  ec2.reset_image_attribute('ami-e444444d') #=> true
    #
    def reset_image_attribute(image_id, attribute='launchPermission')
      link = generate_request("ResetImageAttribute",
                              'ImageId'   => image_id,
                              'Attribute' => attribute)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Modify an image's attributes. It is recommended that you use
    # modify_image_launch_perm_add_users, modify_image_launch_perm_remove_users, etc.
    # instead of modify_image_attribute because the signature of
    # modify_image_attribute may change with EC2 service changes.
    #
    #  attribute      : currently, only 'launchPermission' is supported.
    #  operation_type : currently, only 'add' & 'remove' are supported.
    #  vars:
    #    :user_group  : currently, only 'all' is supported.
    #    :user_id
    #    :product_code
    def modify_image_attribute(image_id, attribute, operation_type = nil, vars = {})
      params =  {'ImageId'   => image_id,
                 'Attribute' => attribute}
      params['OperationType'] = operation_type if operation_type
      params.update(amazonize_list('UserId',      vars[:user_id]))      if vars[:user_id]
      params.update(amazonize_list('UserGroup',   vars[:user_group]))   if vars[:user_group]
      params.update(amazonize_list('ProductCode', vars[:product_code])) if vars[:product_code]
      link = generate_request("ModifyImageAttribute", params)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Grant image launch permissions to users.
    # Parameter +user_id+ is a list of user AWS account ids.
    # Returns +true+ or an exception.
    #
    #  ec2.modify_image_launch_perm_add_users('ami-e444444d',['000000000777','000000000778']) #=> true
    def modify_image_launch_perm_add_users(image_id, user_id=[])
      modify_image_attribute(image_id, 'launchPermission', 'add', :user_id => user_id)
    end

    # Revokes image launch permissions for users. +user_id+ is a list of users AWS accounts ids. Returns +true+ or an exception.
    #
    #  ec2.modify_image_launch_perm_remove_users('ami-e444444d',['000000000777','000000000778']) #=> true
    #
    def modify_image_launch_perm_remove_users(image_id, user_id=[])
      modify_image_attribute(image_id, 'launchPermission', 'remove', :user_id => user_id)
    end

    # Add image launch permissions for users groups (currently only 'all' is supported, which gives public launch permissions).
    # Returns +true+ or an exception.
    #
    #  ec2.modify_image_launch_perm_add_groups('ami-e444444d') #=> true
    #
    def modify_image_launch_perm_add_groups(image_id, user_group=['all'])
      modify_image_attribute(image_id, 'launchPermission', 'add', :user_group => user_group)
    end

    # Remove image launch permissions for users groups (currently only 'all' is supported, which gives public launch permissions).
    #
    #  ec2.modify_image_launch_perm_remove_groups('ami-e444444d') #=> true
    #
    def modify_image_launch_perm_remove_groups(image_id, user_group=['all'])
      modify_image_attribute(image_id, 'launchPermission', 'remove', :user_group => user_group)
    end

    # Add product code to image
    #
    #  ec2.modify_image_product_code('ami-e444444d','0ABCDEF') #=> true
    #
    def modify_image_product_code(image_id, product_code=[])
      modify_image_attribute(image_id, 'productCodes', nil, :product_code => product_code)
    end

    # Create a new image.
    # Options: :name, :description, :no_reboot(bool)
    #
    #  ec2.create_image(instance, :description => 'KD: test#1',
    #                             :no_reboot => true,
    #                             :name => 'kd-1' ) #=> "ami-84a1f792"
    #
    def create_image(instance_aws_id, options={})
      params = { 'InstanceId' => instance_aws_id }
      params['Name']        = options[:name]            unless options[:name].blank?
      params['Description'] = options[:description]     unless options[:description].blank?
      params['NoReboot']    = options[:no_reboot].to_s  unless options[:no_reboot].nil?
      link = generate_request("CreateImage", params)
      request_info(link, QEc2RegisterImageParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS: Images
    #-----------------------------------------------------------------

    class QEc2DescribeImagesParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/imagesSet/item$}          then @item = {}
        when %r{/blockDeviceMapping/item$}
          @item[:block_device_mappings] ||= []
          @block_device_mapping = {}
        end
      end
      def tagend(name)
        case name
        when 'imageId'         then @item[:aws_id]            = @text
        when 'imageLocation'   then @item[:aws_location]      = @text
        when 'imageState'      then @item[:aws_state]         = @text
        when 'imageOwnerId'    then @item[:aws_owner]         = @text
        when 'isPublic'        then @item[:aws_is_public]     = @text == 'true' ? true : false
        when 'productCode'     then (@item[:aws_product_codes] ||= []) << @text
        when 'architecture'    then @item[:aws_architecture]  = @text
        when 'imageType'       then @item[:aws_image_type]    = @text
        when 'kernelId'        then @item[:aws_kernel_id]     = @text
        when 'ramdiskId'       then @item[:aws_ramdisk_id]    = @text
        when 'platform'        then @item[:aws_platform]      = @text
        when 'imageOwnerAlias' then @item[:image_owner_alias] = @text
        when 'name'            then @item[:name]              = @text
        when 'description'     then @item[:description]       = @text
        when 'rootDeviceType'  then @item[:root_device_type]  = @text
        when 'rootDeviceName'  then @item[:root_device_name]  = @text
        when 'imageClass'      then @item[:image_class]       = @text
        else
          case full_tag_name
          when %r{/stateReason/code$}    then @item[:state_reason_code]    = @text.to_i
          when %r{/stateReason/message$} then @item[:state_reason_message] = @text
          when %r{/blockDeviceMapping/item} # no trailing $
            case name
            when 'deviceName'          then @block_device_mapping[:device_name]                = @text
            when 'virtualName'         then @block_device_mapping[:virtual_name]               = @text
            when 'volumeSize'          then @block_device_mapping[:ebs_volume_size]            = @text.to_i
            when 'snapshotId'          then @block_device_mapping[:ebs_snapshot_id]            = @text
            when 'deleteOnTermination' then @block_device_mapping[:ebs_delete_on_termination]  = @text == 'true' ? true : false
            when 'item'                then @item[:block_device_mappings]                    << @block_device_mapping
            end
          when %r{/imagesSet/item$}    then @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2RegisterImageParser < RightAWSParser #:nodoc:
      def tagend(name)
        @result = @text if name == 'imageId'
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: Image Attribute
    #-----------------------------------------------------------------

    class QEc2DescribeImageAttributeParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
          when 'launchPermission'
            @result[:groups] = []
            @result[:users]  = []
          when 'productCodes'
            @result[:aws_product_codes] = []
        end
      end
      def tagend(name)
          # right now only 'launchPermission' is supported by Amazon.
          # But nobody know what will they xml later as attribute. That is why we
          # check for 'group' and 'userId' inside of 'launchPermission/item'
        case name
          when 'imageId'            then @result[:aws_id] = @text
          when 'group'              then @result[:groups] << @text if @xmlpath == 'DescribeImageAttributeResponse/launchPermission/item'
          when 'userId'             then @result[:users]  << @text if @xmlpath == 'DescribeImageAttributeResponse/launchPermission/item'
          when 'productCode'        then @result[:aws_product_codes] << @text
          when 'kernel'             then @result[:aws_kernel]  = @text
          when 'ramdisk'            then @result[:aws_ramdisk] = @text
        end
      end
      def reset
        @result = {}
      end
    end

  end
  
end