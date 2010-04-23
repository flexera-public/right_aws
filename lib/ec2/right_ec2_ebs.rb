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
    #      EBS: Volumes
    #-----------------------------------------------------------------

    # Describe all EBS volumes.
    #
    #  ec2.describe_volumes #=>
    #      [{:aws_size              => 94,
    #        :aws_device            => "/dev/sdc",
    #        :aws_attachment_status => "attached",
    #        :zone                  => "merlot",
    #        :snapshot_id           => nil,
    #        :aws_attached_at       => "2008-06-18T08:19:28.000Z",
    #        :aws_status            => "in-use",
    #        :aws_id                => "vol-60957009",
    #        :aws_created_at        => "2008-06-18T08:19:20.000Z",
    #        :aws_instance_id       => "i-c014c0a9"},
    #       {:aws_size       => 1,
    #        :zone           => "merlot",
    #        :snapshot_id    => nil,
    #        :aws_status     => "available",
    #        :aws_id         => "vol-58957031",
    #        :aws_created_at => Wed Jun 18 08:19:21 UTC 2008,}, ... ]
    #
    def describe_volumes(*volumes)
      volumes = volumes.flatten
      link = generate_request("DescribeVolumes", amazonize_list('VolumeId', volumes))
      request_cache_or_info :describe_volumes, link,  QEc2DescribeVolumesParser, @@bench, volumes.blank?
    rescue Exception
      on_exception
    end

    # Create new EBS volume based on previously created snapshot.
    # +Size+ in Gigabytes.
    #
    #  ec2.create_volume('snap-000000', 10, zone) #=>
    #      {:snapshot_id    => "snap-e21df98b",
    #       :aws_status     => "creating",
    #       :aws_id         => "vol-fc9f7a95",
    #       :zone           => "merlot",
    #       :aws_created_at => "2008-06-24T18:13:32.000Z",
    #       :aws_size       => 94}
    #
    def create_volume(snapshot_id, size, zone)
      hash = { "Size"              => size.to_s,
               "AvailabilityZone"  => zone.to_s }
      # Get rig of empty snapshot: e8s guys do not like it
      hash["SnapshotId"] = snapshot_id.to_s unless snapshot_id.blank?
      link = generate_request("CreateVolume", hash )
      request_info(link, QEc2CreateVolumeParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Delete the specified EBS volume.
    # This does not deletes any snapshots created from this volume.
    #
    #  ec2.delete_volume('vol-b48a6fdd') #=> true
    #
    def delete_volume(volume_id)
      link = generate_request("DeleteVolume",
                              "VolumeId" => volume_id.to_s)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Attach the specified EBS volume to a specified instance, exposing the
    # volume using the specified device name.
    #
    #  ec2.attach_volume('vol-898a6fe0', 'i-7c905415', '/dev/sdh') #=>
    #    { :aws_instance_id => "i-7c905415",
    #      :aws_device      => "/dev/sdh",
    #      :aws_status      => "attaching",
    #      :aws_attached_at => "2008-03-28T14:14:39.000Z",
    #      :aws_id          => "vol-898a6fe0" }
    #
    def attach_volume(volume_id, instance_id, device)
      link = generate_request("AttachVolume",
                              "VolumeId"   => volume_id.to_s,
                              "InstanceId" => instance_id.to_s,
                              "Device"     => device.to_s)
      request_info(link, QEc2AttachAndDetachVolumeParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Detach the specified EBS volume from the instance to which it is attached.
    #
    #   ec2.detach_volume('vol-898a6fe0') #=>
    #     { :aws_instance_id => "i-7c905415",
    #       :aws_device      => "/dev/sdh",
    #       :aws_status      => "detaching",
    #       :aws_attached_at => "2008-03-28T14:38:34.000Z",
    #       :aws_id          => "vol-898a6fe0"}
    #
    def detach_volume(volume_id, instance_id=nil, device=nil, force=nil)
      hash = { "VolumeId" => volume_id.to_s }
      hash["InstanceId"] = instance_id.to_s unless instance_id.blank?
      hash["Device"]     = device.to_s      unless device.blank?
      hash["Force"]      = 'true'           if     force
      #
      link = generate_request("DetachVolume", hash)
      request_info(link, QEc2AttachAndDetachVolumeParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end


    #-----------------------------------------------------------------
    #      EBS: Snapshots
    #-----------------------------------------------------------------

    # Describe all EBS snapshots.
    #
    # ec2.describe_snapshots #=>
    #   [ {:aws_volume_id=>"vol-545fac3d",
    #      :aws_description=>"Wikipedia XML Backups (Linux)",
    #      :aws_progress=>"100%",
    #      :aws_started_at=>"2009-09-28T23:49:50.000Z",
    #      :aws_owner=>"amazon",
    #      :aws_id=>"snap-8041f2e9",
    #      :aws_volume_size=>500,
    #      :aws_status=>"completed"},
    #     {:aws_volume_id=>"vol-185fac71",
    #      :aws_description=>"Sloan Digital Sky Survey DR6 Subset (Linux)",
    #      :aws_progress=>"100%",
    #      :aws_started_at=>"2009-09-28T23:56:10.000Z",
    #      :aws_owner=>"amazon",
    #      :aws_id=>"snap-3740f35e",
    #      :aws_volume_size=>180,
    #      :aws_status=>"completed"}, ...]
    #
    def describe_snapshots(*snapshots)
      snapshots = snapshots.flatten
      link = generate_request("DescribeSnapshots", amazonize_list('SnapshotId', snapshots))
      request_cache_or_info :describe_snapshots, link,  QEc2DescribeSnapshotsParser, @@bench, snapshots.blank?
    rescue Exception
      on_exception
    end

    # Create a snapshot of specified volume.
    #
    #  ec2.create_snapshot('vol-898a6fe0', 'KD: WooHoo!!') #=>
    #    {:aws_volume_id=>"vol-e429db8d",
    #     :aws_started_at=>"2009-10-01T09:23:38.000Z",
    #     :aws_description=>"KD: WooHoo!!",
    #     :aws_owner=>"648770000000",
    #     :aws_progress=>"",
    #     :aws_status=>"pending",
    #     :aws_volume_size=>1,
    #     :aws_id=>"snap-3df54854"}
    #
    def create_snapshot(volume_id, description='')
      link = generate_request("CreateSnapshot",
                              "VolumeId" => volume_id.to_s,
                              "Description" => description)
      request_info(link, QEc2DescribeSnapshotsParser.new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    # Create a snapshot of specified volume, but with the normal retry algorithms disabled.
    # This method will return immediately upon error.  The user can specify connect and read timeouts (in s)
    # for the connection to AWS.  If the user does not specify timeouts, try_create_snapshot uses the default values
    # in Rightscale::HttpConnection.
    #
    #  ec2.try_create_snapshot('vol-898a6fe0', 'KD: WooHoo!!') #=>
    #    {:aws_volume_id=>"vol-e429db8d",
    #     :aws_started_at=>"2009-10-01T09:23:38.000Z",
    #     :aws_description=>"KD: WooHoo!!",
    #     :aws_owner=>"648770000000",
    #     :aws_progress=>"",
    #     :aws_status=>"pending",
    #     :aws_volume_size=>1,
    #     :aws_id=>"snap-3df54854"}
    #
    def try_create_snapshot(volume_id, connect_timeout = nil, read_timeout = nil, description='')
      # For safety in the ensure block...we don't want to restore values
      # if we never read them in the first place
      orig_reiteration_time = nil
      orig_http_params = nil

      orig_reiteration_time = RightAws::AWSErrorHandler::reiteration_time
      RightAws::AWSErrorHandler::reiteration_time = 0

      orig_http_params = Rightscale::HttpConnection::params()
      new_http_params = orig_http_params.dup
      new_http_params[:http_connection_retry_count] = 0
      new_http_params[:http_connection_open_timeout] = connect_timeout if !connect_timeout.nil?
      new_http_params[:http_connection_read_timeout] = read_timeout if !read_timeout.nil?
      Rightscale::HttpConnection::params = new_http_params

      link = generate_request("CreateSnapshot",
                              "VolumeId"    => volume_id.to_s,
                              "Description" => description)
      request_info(link, QEc2DescribeSnapshotsParser.new(:logger => @logger)).first

    rescue Exception
      on_exception
    ensure
      RightAws::AWSErrorHandler::reiteration_time = orig_reiteration_time if orig_reiteration_time
      Rightscale::HttpConnection::params = orig_http_params if orig_http_params
    end

    # Describe snapshot attribute.
    #
    #  ec2.describe_snapshot_attribute('snap-36fe435f') #=>
    #    {:create_volume_permission=>
    #       {:users=>["826690000000", "826690000001"], :groups=>['all']}}
    #
    def describe_snapshot_attribute(snapshot_id, attribute='createVolumePermission')
      link = generate_request("DescribeSnapshotAttribute",
                              'SnapshotId'=> snapshot_id,
                              'Attribute' => attribute)
      request_info(link, QEc2DescribeSnapshotAttributeParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Reset permission settings for the specified snapshot.
    #
    #  ec2.reset_snapshot_attribute('snap-cecd29a7') #=> true
    #
    def reset_snapshot_attribute(snapshot_id, attribute='createVolumePermission')
      link = generate_request("ResetSnapshotAttribute",
                              'SnapshotId' => snapshot_id,
                              'Attribute'  => attribute)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Modify snapshot attribute.
    #
    #  attribute      : currently, only 'createVolumePermission' is supported.
    #  operation_type : currently, only 'add' & 'remove' are supported.
    #  vars:
    #    :user_group  : currently, only 'all' is supported.
    #    :user_id     : an array of user ids
    #
    def modify_snapshot_attribute(snapshot_id, attribute='createVolumePermission', operation_type='add', vars = {})
      params =  {'SnapshotId'    => snapshot_id,
                 'Attribute'     => attribute,
                 'OperationType' => operation_type}
      params.update(amazonize_list('UserId',    Array(vars[:user_id])))    if vars[:user_id]
      params.update(amazonize_list('UserGroup', Array(vars[:user_group]))) if vars[:user_group]
      link = generate_request("ModifySnapshotAttribute", params)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Grant create volume permission for a list of users.
    #
    #  ec2.modify_snapshot_attribute_create_volume_permission_add_users('snap-36fe435f', '000000000000', '000000000001') #=> true
    #
    def modify_snapshot_attribute_create_volume_permission_add_users(snapshot_id, *user_id)
      modify_snapshot_attribute(snapshot_id, 'createVolumePermission', 'add', :user_id => user_id.flatten )
    end
    
    # Revoke create volume permission for a list of users.
    #
    #  ec2.modify_snapshot_attribute_create_volume_permission_remove_users('snap-36fe435f', '000000000000', '000000000001') #=> true
    #
    def modify_snapshot_attribute_create_volume_permission_remove_users(snapshot_id, *user_id)
      modify_snapshot_attribute(snapshot_id, 'createVolumePermission', 'remove', :user_id => user_id.flatten )
    end

    # Grant create volume permission for user groups (currently only 'all' is supported).
    #
    #  ec2.modify_snapshot_attribute_create_volume_permission_add_groups('snap-36fe435f') #=> true
    #
    def modify_snapshot_attribute_create_volume_permission_add_groups(snapshot_id, *user_group)
      user_group.flatten!
      user_group = ['all'] if user_group.blank?
      modify_snapshot_attribute(snapshot_id, 'createVolumePermission', 'add', :user_group => user_group )
    end

    # Remove create volume permission for user groups (currently only 'all' is supported).
    #
    #  ec2.modify_snapshot_attribute_create_volume_permission_remove_groups('snap-36fe435f') #=> true
    #
    def modify_snapshot_attribute_create_volume_permission_remove_groups(snapshot_id, *user_group)
      user_group.flatten!
      user_group = ['all'] if user_group.blank?
      modify_snapshot_attribute(snapshot_id, 'createVolumePermission', 'remove', :user_group => user_group )
    end

    # Delete the specified snapshot.
    #
    #  ec2.delete_snapshot('snap-55a5403c') #=> true
    #
    def delete_snapshot(snapshot_id)
      link = generate_request("DeleteSnapshot",
                              "SnapshotId" => snapshot_id.to_s)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #-----------------------------------------------------------------
    #      PARSERS: EBS - Volumes
    #-----------------------------------------------------------------

    class QEc2CreateVolumeParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'volumeId'         then @result[:aws_id]         = @text
        when 'status'           then @result[:aws_status]     = @text
        when 'createTime'       then @result[:aws_created_at] = @text
        when 'size'             then @result[:aws_size]       = @text.to_i ###
        when 'snapshotId'       then @result[:snapshot_id]    = @text.blank? ? nil : @text ###
        when 'availabilityZone' then @result[:zone]           = @text ###
        end
      end
      def reset
        @result = {}
      end
    end

    class QEc2AttachAndDetachVolumeParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'volumeId'   then @result[:aws_id]                = @text
        when 'instanceId' then @result[:aws_instance_id]       = @text
        when 'device'     then @result[:aws_device]            = @text
        when 'status'     then @result[:aws_attachment_status] = @text
        when 'attachTime' then @result[:aws_attached_at]       = @text
        end
      end
      def reset
        @result = {}
      end
    end

    class QEc2DescribeVolumesParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when 'item'
          case @xmlpath
          when 'DescribeVolumesResponse/volumeSet' then @volume = {}
          end
        end
      end
      def tagend(name)
        case name
        when 'volumeId'
          case @xmlpath
          when 'DescribeVolumesResponse/volumeSet/item' then @volume[:aws_id] = @text
          end
        when 'status'
          case @xmlpath
          when 'DescribeVolumesResponse/volumeSet/item' then @volume[:aws_status] = @text
          when 'DescribeVolumesResponse/volumeSet/item/attachmentSet/item' then @volume[:aws_attachment_status] = @text
          end
        when 'size'             then @volume[:aws_size]        = @text.to_i
        when 'createTime'       then @volume[:aws_created_at]  = @text
        when 'instanceId'       then @volume[:aws_instance_id] = @text
        when 'device'           then @volume[:aws_device]      = @text
        when 'attachTime'       then @volume[:aws_attached_at] = @text
        when 'snapshotId'       then @volume[:snapshot_id]     = @text.blank? ? nil : @text
        when 'availabilityZone' then @volume[:zone]            = @text
        when 'deleteOnTermination' then @volume[:delete_on_termination] = (@text == 'true')
        when 'item'
          case @xmlpath
          when 'DescribeVolumesResponse/volumeSet' then @result << @volume
          end
        end
      end
      def reset
        @result = []
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS: EBS - Snapshots
    #-----------------------------------------------------------------

    class QEc2DescribeSnapshotsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when *@each then @snapshot = {}
        end
      end
      def tagend(name)
        case name
        when 'volumeId'    then @snapshot[:aws_volume_id]   = @text
        when 'snapshotId'  then @snapshot[:aws_id]          = @text
        when 'status'      then @snapshot[:aws_status]      = @text
        when 'startTime'   then @snapshot[:aws_started_at]  = @text
        when 'progress'    then @snapshot[:aws_progress]    = @text
        when 'description' then @snapshot[:aws_description] = @text
        when 'ownerId'     then @snapshot[:aws_owner]       = @text
        when 'volumeSize'  then @snapshot[:aws_volume_size] = @text.to_i
        when *@each        then @result << @snapshot
        end
      end
      def reset
        @each = ['item', 'CreateSnapshotResponse']
        @result = []
      end
    end

    class QEc2DescribeSnapshotAttributeParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when 'createVolumePermission' then @result[:create_volume_permission] = { :groups => [], :users => [] }
        end
      end
      def tagend(name)
        case full_tag_name
        when "#{@create_volume_permission}/group"  then @result[:create_volume_permission][:groups] << @text
        when "#{@create_volume_permission}/userId" then @result[:create_volume_permission][:users]  << @text
        end
      end
      def reset
        @create_volume_permission = "DescribeSnapshotAttributeResponse/createVolumePermission/item"
        @result = {}
      end
    end

  end
  
end