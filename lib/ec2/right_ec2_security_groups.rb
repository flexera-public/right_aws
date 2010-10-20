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
    #       [{:group=>"default", :owner=>"048291609141"},
    #        {:to_port=>"22",
    #         :protocol=>"tcp",
    #         :from_port=>"22",
    #         :cidr_ips=>"0.0.0.0/0"},
    #        {:to_port=>"9997",
    #         :protocol=>"tcp",
    #         :from_port=>"9997",
    #         :cidr_ips=>"0.0.0.0/0"}],
    #      :aws_group_name=>"photo_us",
    #      :aws_description=>"default group",
    #      :aws_owner=>"826693181925"}]
    #
    #  # Eucalyptus cloud:
    #  ec2 = Rightscale::Ec2.new(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, :eucalyptus => true)
    #  ec2.describe_security_groups #=>
    #    [{:aws_perms=>
    #       [{:to_port=>"65535",
    #         :group=>"default",
    #         :protocol=>"tcp",
    #         :owner=>"048291609141",
    #         :from_port=>"1"},
    #        {:to_port=>"65535",
    #         :group=>"default",
    #         :protocol=>"udp",
    #         :owner=>"048291609141",
    #         :from_port=>"1"},
    #        {:to_port=>"-1",
    #         :group=>"default",
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
      describe_resources_with_list_and_options('DescribeSecurityGroups', 'GroupName', QEc2DescribeSecurityGroupsParser, list_and_options) do |parser|
        result = []
        parser.result.each do |item|
          result_item = { :aws_owner       => item[:owner_id],
                          :aws_group_name  => item[:group_name],
                          :aws_description => item[:group_description] }
          aws_perms = []
          item[:ip_permissions].each do |permission|
            result_perm = {}
            result_perm[:from_port] = permission[:from_port]
            result_perm[:to_port]   = permission[:to_port]
            result_perm[:protocol]  = permission[:ip_protocol]
            # IP permissions
            Array(permission[:ip_ranges]).each do |ip_range|
              perm = result_perm.dup
              perm[:cidr_ips] = ip_range
              aws_perms << perm
            end
            # Group permissions
            Array(permission[:groups]).each do |group|
              perm = result_perm.dup
              perm[:group] = group[:group_name]
              perm[:owner] = group[:user_id]
              aws_perms << perm
            end
          end
          result_item[:aws_perms] = aws_perms.uniq
          result << result_item
        end
        result
      end
    end

    # Create new Security Group. Returns +true+ or an exception.
    #
    #  ec2.create_security_group('default-1',"Default allowing SSH, HTTP, and HTTPS ingress") #=> true
    #
    def create_security_group(name, description=nil)
      # EC2 doesn't like an empty description...
      description = "-" if description.right_blank?
      link = generate_request("CreateSecurityGroup",
                              'GroupName'        => name.to_s,
                              'GroupDescription' => description.to_s)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Remove Security Group. Returns +true+ or an exception.
    #
    #  ec2.delete_security_group('default-1') #=> true
    #
    def delete_security_group(name)
      link = generate_request("DeleteSecurityGroup",
                              'GroupName' => name.to_s)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

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

    # Modify AWS security group permissions.
    #
    #  Options:
    #    action      - :authorize (or :grant) | :revoke (or :remove)
    #    group_name  - security group name
    #    permissions - a combination of options below:
    #      # Ports:
    #      :from_port          => from port
    #      :to_port            => to port
    #      :port               => set both :from_port and to_port with the same value
    #      # Protocol
    #      :protocol           => :tcp | :udp | :icmp
    #      # Group(s)
    #      :source_group_owner => UserId
    #      :source_group       => GroupName
    #      # or
    #      :source_groups      => { UserId1 => GroupName1, UserName2 => GroupName2 }
    #      :source_groups      => [ [ UserId1, GroupName1 ], [ UserName2 => GroupName2 ] ]
    #      # CidrIp(s)
    #      :cidr_ip            => '0.0.0.0/0'
    #      :cidr_ips           => ['1.1.1.1/1', '2.2.2.2/2']
    #
    #  # CidrIP based permissions:
    #
    #  ec2.modify_security_group_ingress(:authorize, 'my_cool_group',
    #                                    :cidr_ip  =>  "127.0.0.0/31",
    #                                    :port     => 811,
    #                                    :protocol => 'tcp' ) #=> true
    #
    #  ec2.modify_security_group_ingress(:revoke, 'my_cool_group',
    #                                    :cidr_ips =>  ["127.0.0.1/32", "127.0.0.2/32"],
    #                                    :port     => 812,
    #                                    :protocol => 'tcp' ) #=> true
    #
    #  # Group based permissions:
    #
    #  ec2.modify_security_group_ingress(:authorize, 'my_cool_group',
    #                                    :source_group_owner => "586789340000",
    #                                    :source_group =>  "sketchy-us",
    #                                    :port         => 800,
    #                                    :protocol     => 'tcp' ) #=> true
    #
    #  ec2.modify_security_group_ingress(:authorize, 'my_cool_group',
    #                                    :source_groups => { "586789340000" => "sketchy-us",
    #                                                        "635201710000" => "sketchy" },
    #                                    :port          => 801,
    #                                    :protocol      => 'tcp' ) #=> true
    #
    #  ec2.modify_security_group_ingress(:revoke, 'my_cool_group',
    #                                    :source_groups => [[ "586789340000", "sketchy-us" ],
    #                                                       [ "586789340000", "default" ]],
    #                                    :port          => 809,
    #                                    :protocol      => 'tcp' ) #=> true
    #
    #  # +Permissions+ can be an array of permission hashes:
    #
    #  ec2.modify_security_group_ingress(:authorize, 'my_cool_group',
    #                                    [{ :source_groups => { "586789340000" => "sketchy-us",
    #                                                           "635201710000" => "sketchy" },
    #                                       :port          => 803,
    #                                       :protocol      => 'tcp'},
    #                                     { :cidr_ips      =>  ["127.0.0.1/32", "127.0.0.2/32"],
    #                                       :port          => 812,
    #                                       :protocol      => 'tcp' }]) #=> true
    #
    def modify_security_group_ingress(action, group_name, permissions)
      hash = {}
      case action
      when :authorize, :grant then action = "AuthorizeSecurityGroupIngress"
      when :revoke, :remove   then action = "RevokeSecurityGroupIngress"
      else                         raise "Unknown action #{action.inspect}!"
      end
      # Group Name
      hash["GroupName"] = group_name
      #
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
        # Source Group(s)
        # Old way (if it is used):
        # :source_group_owner => UserId, :source_group => GroupName 
        if !permission[:source_group].right_blank? && !permission[:source_group_owner].right_blank?
          permission[:source_groups] = { permission[:source_group_owner] => permission[:source_group]} 
        end
#        # Fix UserId(s): '0000-0000-0000' => '000000000000'
#        permission[:source_groups] = Array(permission[:source_groups])
#        permission[:source_groups].each do |item|
#          item[0] = item[0].to_s.gsub(/-/,'')
#        end
        # New way:
        #  :source_groups => {UserId1 => GroupName1, ... UserIdN => GroupNameN}
        #  or (this allows using same UserId multiple times )
        #  :source_groups => [[UserId1, GroupName1], ... [UserIdN, GroupNameN]]  
        hash.merge!(amazonize_list( ["IpPermissions.#{pid}.Groups.?.UserId",
                                     "IpPermissions.#{pid}.Groups.?.GroupName"],
                                      permission[:source_groups] ))
        # CidrIp(s)
        cidr_ips   = permission[:cidr_ips] unless permission[:cidr_ips].right_blank?
        cidr_ips ||= permission[:cidr_ip]  unless permission[:cidr_ip].right_blank?
        hash.merge!(amazonize_list("IpPermissions.1.IpRanges.?.CidrIp", cidr_ips))
      end
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

    class QEc2DescribeSecurityGroupsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        if name == 'item'
          case
          when @xmlpath[/securityGroupInfo$/] then @item = { :ip_permissions => [] }
          when @xmlpath[/ipPermissions$/]     then @ip_permission = { :groups => [], :ip_ranges => [] }
          when @xmlpath[/groups$/]            then @group = {}
          end
        end
      end
      def tagend(name)
        case name
        when 'ownerId'          then @item[:owner_id]             = @text
        when 'groupDescription' then @item[:group_description]    = @text
        when 'ipProtocol'       then @ip_permission[:ip_protocol] = @text
        when 'fromPort'         then @ip_permission[:from_port]   = @text
        when 'toPort'           then @ip_permission[:to_port]     = @text
        when 'cidrIp'           then @ip_permission[:ip_ranges]  << @text
        when 'userId'           then @group[:user_id]             = @text
        when 'groupName'
          case
          when @xmlpath[/securityGroupInfo\/item$/] then @item[:group_name]  = @text
          when @xmlpath[/groups\/item$/]            then @group[:group_name] = @text
          end
        when 'item'
          case
          when @xmlpath[/groups$/]           then @ip_permission[:groups] << @group
          when @xmlpath[/ipPermissions$/]    then @item[:ip_permissions] << @ip_permission
          when @xmlpath[/securityGroupInfo$/]then @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end
    
  end
end