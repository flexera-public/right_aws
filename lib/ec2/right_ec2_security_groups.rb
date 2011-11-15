#
# Copyright (c) 2010 RightScale Inc
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
    #      Security groups
    #-----------------------------------------------------------------

    # Retrieve Security Groups information.
    # Options: By default this methods expects security group ids but if you wanna pass their names then :describe_by => :group_name option must be set.
    #
    # Accepts a list of security groups and/or a set of filters as the last parameter.
    #
    # Filters: description, group-name, ip-permission.cidr, ip-permission.from-port, ip-permission.group-name,
    # ip-permission.protocol, ip-permission.to-port, ip-permission.user-id, owner-id
    #
    #  # Amazon cloud:
    #  ec2 = Rightscale::Ec2.new(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #  ec2.describe_security_groups #=>
    #    [{:aws_perms=>
    #        [{:protocol=>"-1", :cidr_ips=>"0.0.0.0/0", :direction=>:egress},
    #        {:protocol=>"tcp",
    #          :cidr_ips=>"127.0.0.2/32",
    #          :direction=>:egress,
    #          :from_port=>"1111",
    #          :to_port=>"1111"},
    #        {:protocol=>"tcp",
    #          :cidr_ips=>"127.0.0.1/32",
    #          :direction=>:egress,
    #          :from_port=>"1111",
    #          :to_port=>"1111"}],
    #      :aws_group_name=>"kd-vpc-egress-test-1",
    #      :vpc_id=>"vpc-e16cf988",
    #      :aws_description=>"vpc test",
    #      :aws_owner=>"826693181925",
    #      :group_id=>"sg-b72032db"}]
    #
    #   # Describe by group ids
    #   ec2.describe_security_groups("sg-a0b85dc9", "sg-00b05d39", "sg-a1b86dc8")
    #
    #   # Describe by group names
    #   ec2.describe_security_groups("default", "default1", "kd", :describe_by => :group_name)
    #
    #  # Eucalyptus cloud:
    #  ec2 = Rightscale::Ec2.new(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, :eucalyptus => true)
    #  ec2.describe_security_groups #=>
    #    [{:aws_perms=>
    #       [{:to_port=>"65535",
    #         :group_name=>"default",
    #         :protocol=>"tcp",
    #         :owner=>"048291609141",
    #         :from_port=>"1"},
    #        {:to_port=>"65535",
    #         :group_name=>"default",
    #         :protocol=>"udp",
    #         :owner=>"048291609141",
    #         :from_port=>"1"},
    #        {:to_port=>"-1",
    #         :group_name=>"default",
    #         :protocol=>"icmp",
    #         :owner=>"048291609141",
    #         :from_port=>"-1"},
    #        {:to_port=>"22",
    #         :protocol=>"tcp",
    #         :from_port=>"22",
    #         :cidr_ip=>"0.0.0.0/0"},
    #        {:to_port=>"9997",
    #         :protocol=>"tcp",
    #         :from_port=>"9997",
    #         :cidr_ip=>"0.0.0.0/0"}],
    #      :aws_group_name=>"photo_us",
    #      :aws_description=>"default group",
    #      :aws_owner=>"826693181925"}]
    #
    #  ec2.describe_security_groups(:filters => {'ip-permission.from-port' => '22'})
    #
    # P.S. filters: http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DescribeSecurityGroups.html
    #
    def describe_security_groups(*list_and_options)
      list, options = AwsUtils::split_items_and_params(list_and_options)
      describe_by   = options.delete(:describe_by) == :group_name ? 'GroupName' : 'GroupId'
      describe_resources_with_list_and_options('DescribeSecurityGroups', describe_by, QEc2DescribeSecurityGroupsParser, list_and_options) do |parser|
        result = []
        parser.result.each do |item|
          result_item = { :aws_owner       => item[:owner_id],
                          :aws_group_name  => item[:group_name],
                          :aws_description => item[:group_description] }
          result_item[:group_id] = item[:group_id] unless item[:group_id].right_blank?
          result_item[:vpc_id]   = item[:vpc_id]   unless item[:vpc_id].right_blank?
          aws_perms = []
          item[:ip_permissions].each do |permission|
            result_perm = {}
            result_perm[:from_port] = permission[:from_port]   unless permission[:from_port].right_blank?
            result_perm[:to_port]   = permission[:to_port]     unless permission[:to_port].right_blank?
            result_perm[:protocol]  = permission[:ip_protocol]
            result_perm[:direction] = permission[:direction]
            # IP permissions
            Array(permission[:ip_ranges]).each do |ip_range|
              perm = result_perm.dup
              # Mhhh... For Eucalyptus we somehow get used to use ":cidr_ip" instead of ":cidr_ips"...
              if @params[:eucalyptus] then  perm[:cidr_ip]  = ip_range
              else                          perm[:cidr_ips] = ip_range
              end
              aws_perms << perm
            end
            # Group permissions
            Array(permission[:groups]).each do |group|
              perm = result_perm.dup
              perm[:group_name] = group[:group_name] unless group[:group_name].right_blank?
              perm[:group_id]   = group[:group_id]   unless group[:group_id].right_blank?
              perm[:owner]      = group[:user_id]    unless group[:user_id].right_blank?
              aws_perms << perm
            end
          end
          result_item[:aws_perms] = aws_perms.uniq
          result << result_item
        end
        result
      end
    end

    def describe_security_groups_by_name(*list)
      describe_security_groups(list, :describe_by => :group_name)
    end

    # Create new Security Group. Returns +true+ or an exception.
    # Options: :vpc_id
    #
    #  ec2.create_security_group('default-1',"Default allowing SSH, HTTP, and HTTPS ingress") #=>
    #    { :group_id=>"sg-f0227599", :return=>true }
    #
    #  ec2.create_security_group('default-2',"my VPC group", :vpc_id => 'vpc-e16c0000') #=>
    #    { :group_id=>"sg-76d1c31a", :return=>true }
    #
    def create_security_group(name, description = nil, options = {})
      options = options.dup
      options[:group_name]        = name      
      options[:group_description] = description.right_blank? ? '-' : description # EC2 rejects an empty description...
      link = generate_request("CreateSecurityGroup", map_api_keys_and_values(options, :group_name, :group_description, :vpc_id))
      request_info(link, QEc2CreateSecurityGroupsParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Remove Security Group. Returns +true+ or an exception.
    # Options: :group_name, :group_id
    #
    #  # Delete security group by group_id:
    #  ec2.delete_security_group('sg-90054ef9') #=> true
    #  ec2.delete_security_group(:group_id => 'sg-90054ef9') #=> true
    #
    #  # Delete security group by name (EC2 only):
    #  ec2.delete_security_group(:group_name => 'my-group']) #=> true
    #
    def delete_security_group(group_id_or_options={})
      options = group_id_or_options.is_a?(Hash) ? group_id_or_options : { :group_id => group_id_or_options } 
      link = generate_request("DeleteSecurityGroup", map_api_keys_and_values(options, :group_name, :group_id))
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    def grant_security_group_ingress(group_id, permissions)
      modify_security_group(:grant, :ingress, group_id, permissions)
    end

    def revoke_security_group_ingress(group_id, permissions)
      modify_security_group(:revoke, :ingress, group_id, permissions)
    end

    def grant_security_group_egress(group_id, permissions)
      modify_security_group(:grant, :egress, group_id, permissions)
    end

    def revoke_security_group_egress(group_id, permissions)
      modify_security_group(:revoke, :egress, group_id, permissions)
    end

    # Modify AWS security group permissions.
    #
    #  Options:
    #    action      - :authorize (or :grant) | :revoke (or :remove)
    #    direction   - :ingress | :egress
    #    group_name  - security group name
    #    permissions - a combination of options below:
    #      # Ports:
    #      :from_port          => from port
    #      :to_port            => to port
    #      :port               => set both :from_port and to_port with the same value
    #      # Protocol
    #      :protocol           => :tcp | :udp | :icmp | -1
    #      # or (ingress)
    #      :groups             => { UserId1 => GroupId1, UserName2 => GroupId2 }
    #      :groups             => [ [ UserId1, GroupId1 ], [ UserName2 => GroupId2 ] ]
    #      # or (egress)
    #      :groups             => [ GroupId1, GroupId2 ]
    #      # CidrIp(s)
    #      :cidr_ip            => '0.0.0.0/0'
    #      :cidr_ips           => ['1.1.1.1/1', '2.2.2.2/2']
    #
    #  # CidrIP based permissions:
    #
    #  ec2.modify_security_group(:authorize, :ingress, 'sg-75d1c319',
    #                            :cidr_ip  =>  "127.0.0.0/31",
    #                            :port     => 811,
    #                            :protocol => 'tcp' ) #=> true
    #
    #  ec2.modify_security_group(:revoke, :ingress, 'sg-75d1c319',
    #                            :cidr_ips =>  ["127.0.0.1/32", "127.0.0.2/32"],
    #                            :port     => 812,
    #                            :protocol => 'tcp' ) #=> true
    #
    #  # Group based permissions:
    #
    #  ec2.modify_security_group(:authorize, :ingress, 'sg-75d1c319',
    #                            :groups   => { "586789340000" => "sg-75d1c300",
    #                                           "635201710000" => "sg-75d1c301" },
    #                            :port     => 801,
    #                            :protocol => 'tcp' ) #=> true
    #
    #  ec2.modify_security_group(:revoke, :ingress, 'sg-75d1c319',
    #                            :groups   => [[ "586789340000", "sg-75d1c300" ],
    #                                          [ "586789340000", "sg-75d1c302" ]],
    #                            :port     => 809,
    #                            :protocol => 'tcp' ) #=> true
    #
    #  # +Permissions+ can be an array of permission hashes:
    #
    #  ec2.modify_security_group(:authorize, :ingress, 'sg-75d1c319',
    #                            [{ :groups   => { "586789340000" => "sg-75d1c300",
    #                                              "635201710000" => "sg-75d1c301" },
    #                                              :port          => 803,
    #                                              :protocol      => 'tcp'},
    #                             { :cidr_ips =>  ["127.0.0.1/32", "127.0.0.2/32"],
    #                               :port     => 812,
    #                               :protocol => 'tcp' }]) #=> true
    #
    def modify_security_group(action, direction, group_id, permissions)
      hash = {}
      raise "Unknown action #{action.inspect}!"       unless [:authorize, :grant, :revoke, :remove].include?(action)
      raise "Unknown direction #{direction.inspect}!" unless [:ingress, :egress].include?(direction)
      # Remote action
      remote_action = case action
                      when :authorize, :grant  then direction == :ingress ? "AuthorizeSecurityGroupIngress" : "AuthorizeSecurityGroupEgress"
                      when :revoke,    :remove then direction == :ingress ? "RevokeSecurityGroupIngress"    : "RevokeSecurityGroupEgress"
                      end
      # Group Name
      hash["GroupId"] = group_id
      # Permissions
      permissions = [permissions] unless permissions.is_a?(Array)
      permissions.each_with_index do |permission, idx|
        pid = idx+1
        # Protocol
        hash["IpPermissions.#{pid}.IpProtocol"] = permission[:protocol]
        # Port
        unless permission[:port].right_blank?
          hash["IpPermissions.#{pid}.FromPort"] = permission[:port]
          hash["IpPermissions.#{pid}.ToPort"]   = permission[:port]
        else
          hash["IpPermissions.#{pid}.FromPort"] = permission[:from_port]
          hash["IpPermissions.#{pid}.ToPort"]   = permission[:to_port]
        end
        # Groups
        case direction
        when :ingress
          #  :groups => {UserId1 => GroupId1, ... UserIdN => GroupIdN}
          #  or (this allows using same UserId multiple times )
          #  :groups => [[UserId1, GroupId1], ... [UserIdN, GroupIdN]]
          #  or even (unset user is == current account user)
          #  :groups => [GroupId1, GroupId2, ... GroupIdN]
          #  :groups => [[UserId1, GroupId1], GroupId2, ... GroupIdN, ... [UserIdM, GroupIdM]]
          #
          index = 1
          unless permission[:group_names].right_blank?
            owner_and_groups = []
            groups_only      = []
            Array(permission[:group_names]).each do |item|
              if item.is_a?(Array) && item.size == 2
                owner_and_groups << item
              else
                groups_only << item
              end
            end
            hash.merge!(amazonize_list( ["IpPermissions.#{pid}.Groups.?.UserId", "IpPermissions.#{pid}.Groups.?.GroupName"], owner_and_groups, :index => index ))
            index += owner_and_groups.size
            groups_only = groups_only.flatten
            hash.merge!(amazonize_list( "IpPermissions.#{pid}.Groups.?.GroupName", groups_only, :index => index ))
            index += groups_only.size
          end
          unless permission[:groups].right_blank?
            owner_and_groups = []
            groups_only      = []
            Array(permission[:groups]).each do |item|
              if item.is_a?(Array) && item.size == 2
                owner_and_groups << item
              else
                groups_only << item
              end
            end
            hash.merge!(amazonize_list( ["IpPermissions.#{pid}.Groups.?.UserId", "IpPermissions.#{pid}.Groups.?.GroupId"], owner_and_groups, :index => index ))
            index += owner_and_groups.size
            groups_only = groups_only.flatten
            hash.merge!(amazonize_list( "IpPermissions.#{pid}.Groups.?.GroupId", groups_only, :index => index ))
          end
        when :egress
          #  :groups => [GroupId1, ... GroupIdN]
          hash.merge!(amazonize_list( "IpPermissions.#{pid}.Groups.?.GroupId", permission[:groups] ))
        end
        # CidrIp(s)
        cidr_ips   = permission[:cidr_ips] unless permission[:cidr_ips].right_blank?
        cidr_ips ||= permission[:cidr_ip]  unless permission[:cidr_ip].right_blank?
        hash.merge!(amazonize_list("IpPermissions.1.IpRanges.?.CidrIp", cidr_ips))
      end
      #
      link = generate_request(remote_action, hash)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #-----------------------------------------------------------------
    #   Eucalyptus
    #-----------------------------------------------------------------

    # Edit AWS/Eucaliptus security group permissions.
    #
    #  Options:
    #    action      - :authorize (or :grant) | :revoke (or :remove)
    #    group_name  - security group name
    #    permissions - a combination of options below:
    #      :source_group_owner => UserId
    #      :source_group       => GroupName
    #      :from_port          => from port
    #      :to_port            => to port
    #      :port               => set both :from_port and to_port with the same value
    #      :protocol           => :tcp | :udp | :icmp
    #      :cidr_ip            => '0.0.0.0/0'
    #
    #  ec2.edit_security_group( :grant,
    #                           'kd-sg-test',
    #                           :source_group       => "sketchy",
    #                           :source_group_owner => "600000000006",
    #                           :protocol           => 'tcp',
    #                           :port               => '80',
    #                           :cidr_ip            => '127.0.0.1/32') #=> true
    #
    # P.S. This method is deprecated for AWS and but still good for Eucaliptus clouds.
    # Use +modify_security_group_ingress+ method for AWS clouds.
    #
    def edit_security_group(action, group_name, params)
      hash = {}
      case action
      when :authorize, :grant then action = "AuthorizeSecurityGroupIngress"
      when :revoke, :remove   then action = "RevokeSecurityGroupIngress"
      else raise "Unknown action #{action.inspect}!"
      end
      hash['GroupName']                  = group_name
      hash['SourceSecurityGroupName']    = params[:source_group]                         unless params[:source_group].right_blank?
      hash['SourceSecurityGroupOwnerId'] = params[:source_group_owner].to_s.gsub(/-/,'') unless params[:source_group_owner].right_blank?
      hash['IpProtocol']                 = params[:protocol]                             unless params[:protocol].right_blank?
      unless params[:port].right_blank?
        hash['FromPort'] = params[:port]
        hash['ToPort']   = params[:port]
      end
      hash['FromPort']   = params[:from_port] unless params[:from_port].right_blank?
      hash['ToPort']     = params[:to_port]   unless params[:to_port].right_blank?
      hash['CidrIp']     = params[:cidr_ip]   unless params[:cidr_ip].right_blank?
      #
      link = generate_request(action, hash)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Authorize named ingress for security group. Allows instances that are member of someone
    # else's security group to open connections to instances in my group.
    #
    #  ec2.authorize_security_group_named_ingress('my_awesome_group', '7011-0219-8268', 'their_group_name') #=> true
    #
    def authorize_security_group_named_ingress(name, owner, group)
      edit_security_group( :authorize, name, :source_group_owner => owner, :source_group => group)
    end

    # Revoke named ingress for security group.
    #
    #  ec2.revoke_security_group_named_ingress('my_awesome_group', aws_user_id, 'another_group_name') #=> true
    #
    def revoke_security_group_named_ingress(name, owner, group)
      edit_security_group( :revoke, name, :source_group_owner => owner, :source_group => group)
    end

    # Add permission to a security group. Returns +true+ or an exception. +protocol+ is one of :'tcp'|'udp'|'icmp'.
    #
    #  ec2.authorize_security_group_IP_ingress('my_awesome_group', 80, 82, 'udp', '192.168.1.0/8') #=> true
    #  ec2.authorize_security_group_IP_ingress('my_awesome_group', -1, -1, 'icmp') #=> true
    #
    def authorize_security_group_IP_ingress(name, from_port, to_port, protocol='tcp', cidr_ip='0.0.0.0/0')
      edit_security_group( :authorize, name, :from_port => from_port, :to_port => to_port, :protocol => protocol, :cidr_ip => cidr_ip )
    end

    # Remove permission from a security group. Returns +true+ or an exception. +protocol+ is one of :'tcp'|'udp'|'icmp' ('tcp' is default).
    #
    #  ec2.revoke_security_group_IP_ingress('my_awesome_group', 80, 82, 'udp', '192.168.1.0/8') #=> true
    #
    def revoke_security_group_IP_ingress(name, from_port, to_port, protocol='tcp', cidr_ip='0.0.0.0/0')
      edit_security_group( :revoke, name, :from_port => from_port, :to_port => to_port, :protocol => protocol, :cidr_ip => cidr_ip )
    end

    #-----------------------------------------------------------------
    #      PARSERS: Security Groups
    #-----------------------------------------------------------------

    class QEc2CreateSecurityGroupsParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'groupId' then @result[:group_id] = @text
        when 'return'  then @result[:return]   = @text == 'true'
        end
      end
      def reset
        @result = {}
      end
    end

    class QEc2DescribeSecurityGroupsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        if name == 'item'
          case full_tag_name
          when %r{securityGroupInfo/item$}                  then @item    = { :ip_permissions => [] }
          when %r{ipPermissions/item$}                      then @ip_perm = { :groups => [], :ip_ranges => [], :direction => :ingress }
          when %r{ipPermissionsEgress/item$}                then @ip_perm = { :groups => [], :ip_ranges => [], :direction => :egress  }
          when %r{ipPermissions(Egress)?/item/groups/item$} then @group   = {}
          end
        end
      end
      def tagend(name)
        case name
        when 'ownerId'          then @item[:owner_id]          = @text
        when 'groupDescription' then @item[:group_description] = @text
        when 'vpcId'            then @item[:vpc_id]            = @text
        else
          case full_tag_name
          when %r{securityGroupInfo/item/groupName$}                  then @item[:group_name]      = @text
          when %r{securityGroupInfo/item/groupId$}                    then @item[:group_id]        = @text
          # ipPermission[Egress]
          when %r{ipPermissions(Egress)?/item/ipProtocol$}            then @ip_perm[:ip_protocol]  = @text
          when %r{ipPermissions(Egress)?/item/fromPort$}              then @ip_perm[:from_port]    = @text
          when %r{ipPermissions(Egress)?/item/toPort$}                then @ip_perm[:to_port]      = @text
          when %r{ipPermissions(Egress)?/item/ipRanges/item/cidrIp$}  then @ip_perm[:ip_ranges]   << @text
          # ipPermissions[Egress]/Groups
          when %r{ipPermissions(Egress)?/item/groups/item/groupName$} then @group[:group_name]     = @text
          when %r{ipPermissions(Egress)?/item/groups/item/groupId$}   then @group[:group_id]       = @text
          when %r{ipPermissions(Egress)?/item/groups/item/userId$}    then @group[:user_id]        = @text
          # Sets
          when %r{ipPermissions(Egress)?/item/groups/item$}           then @ip_perm[:groups]      << @group
          when %r{ipPermissions/item$}                                then @item[:ip_permissions] << @ip_perm
          when %r{ipPermissionsEgress/item$}                          then @item[:ip_permissions] << @ip_perm
          when %r{securityGroupInfo/item$}                            then @result                << @item
          end
        end
      end
      def reset
        @result = []
      end
    end
    
  end
end