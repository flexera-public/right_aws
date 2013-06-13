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


    VPC_API_VERSION = (API_VERSION > '2012-10-15') ? API_VERSION : '2012-10-15'

  public

    #-----------------
    # VPC
    #-----------------

    # Describe VPCs.
    #
    # Accepts a list of vpcs and/or a set of filters as the last parameter.
    #
    # Filters: cidr, dchp-options-id, state, tag-key, tag-value, tag:key, vpc-id
    #
    #  ec2.describe_vpcs #=>
    #    [{:instance_tenancy=>"default",
    #      :vpc_id=>"vpc-e16cf988",
    #      :tags=>{},
    #      :dhcp_options_id=>"default",
    #      :cidr_block=>"192.168.0.0/24",
    #      :state=>"available"}]
    #
    #  ec2.describe_vpcs("vpc-890ce2e0")
    #
    #  ec2.describe_vpcs( :filters => {'tag:MyTag' => 'MyValue'} )
    #  
    #  ec2.describe_vpcs( :filters => {'cidr' => "192.168.1.0/24"} )
    #
    # P.S. filters: http://docs.amazonwebservices.com/AmazonVPC/latest/APIReference/index.html?ApiReference-query-DescribeVpcs.html
    #
    def describe_vpcs(*list_and_options)
      list_and_options = merge_new_options_into_list_and_options(list_and_options, :options => {:api_version => VPC_API_VERSION})
      describe_resources_with_list_and_options('DescribeVpcs', 'VpcId', QEc2DescribeVpcsParser, list_and_options)
    end

    # Create VPC.
    #
    #  ec2.create_vpc('10.0.0.0/23') #=>
    #    {:vpc_id=>"vpc-890ce2e0",
    #     :dhcp_options_id=>"default",
    #     :cidr_block=>"10.0.0.0/23",
    #     :state=>"pending"}
    #
    def create_vpc(cidr_block, options = {})
      request_hash = {'CidrBlock' => cidr_block}
      request_hash['InstanceTenancy'] = options[:instance_tenancy] unless options[:instance_tenancy].right_blank?
      link = generate_request("CreateVpc", request_hash )
      request_info(link, QEc2DescribeVpcsParser.new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    # Delete VPC.
    #
    #  ec2.delete_vpc("vpc-890ce2e0") #=> true
    #
    def delete_vpc(vpc_id)
      link = generate_request("DeleteVpc", 'VpcId' => vpc_id )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #-----------------
    # Subnets
    #-----------------

    # Describe Subnet.
    #
    # Accepts a list of subnets and/or a set of filters as the last parameter.
    #
    # Filters: availability-zone, available-ip-address-count, cidr, state, subnet-id, tag-key, tag-value, tag:key, vpc-id
    #
    #  ec2.describe_subnets #=>
    #    [{:available_ip_address_count=>"251",
    #      :vpc_id=>"vpc-890ce2e0",
    #      :availability_zone=>"us-east-1a",
    #      :subnet_id=>"subnet-770de31e",
    #      :cidr_block=>"10.0.1.0/24",
    #      :state=>"available"}]
    #
    #  ec2.describe_subnets(:filters => {'cidr' => "192.168.1.128/25"})
    #
    # P.S. filters: http://docs.amazonwebservices.com/AmazonVPC/latest/APIReference/index.html?ApiReference-query-DescribeSubnets.html
    #
    def describe_subnets(*list_and_options)
      list_and_options = merge_new_options_into_list_and_options(list_and_options, :options => {:api_version => VPC_API_VERSION})
      describe_resources_with_list_and_options('DescribeSubnets', 'SubnetId', QEc2DescribeSubnetsParser, list_and_options)
    end

    # Create Subnet.
    #
    #  ec2.create_subnet("vpc-890ce2e0",'10.0.1.0/24') #=>
    #    {:available_ip_address_count=>"251",
    #     :vpc_id=>"vpc-890ce2e0",
    #     :availability_zone=>"us-east-1a",
    #     :subnet_id=>"subnet-770de31e",
    #     :cidr_block=>"10.0.1.0/24",
    #     :state=>"pending"}
    #
    def create_subnet(vpc_id, cidr_block, availability_zone = nil)
      request_hash = { 'VpcId'     => vpc_id,
                       'CidrBlock' => cidr_block }
      request_hash['AvailabilityZone'] = availability_zone unless availability_zone.right_blank?
      link = generate_request("CreateSubnet", request_hash)
      request_info(link, QEc2DescribeSubnetsParser.new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    # Delete Subnet.
    #
    #  ec2.delete_subnet("subnet-770de31e") #=> true
    #
    def delete_subnet(subnet_id)
      link = generate_request("DeleteSubnet", 'SubnetId' => subnet_id )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #-----------------
    # DHCP Options
    #-----------------

    # Describe DHCP options.
    #
    # Accepts a list of DHCP options and/or a set of filters as the last parameter.
    #
    # Filters: dchp-options-id, key, value, tag-key, tag-value, tag:key
    # 
    #  ec2.describe_dhcp_options #=>
    #    [{:dhcp_options_id=>"dopt-cb0de3a2",
    #    :dhcp_configuration_set=>
    #     {"netbios-node-type"=>["1"], "domain-name"=>["my.awesomesite.ru"]}}]
    #
    #  ec2.describe_dhcp_options(:filters => {'tag:MyTag' => 'MyValue'})
    #
    # P.S. filters: http://docs.amazonwebservices.com/AmazonVPC/latest/APIReference/index.html?ApiReference-query-DescribeDhcpOptions.html
    #
    def describe_dhcp_options(*list_and_options)
      describe_resources_with_list_and_options('DescribeDhcpOptions', 'DhcpOptionsId', QEc2DescribeDhcpOptionsParser, list_and_options)
    end

    # Create DHCP options.
    #
    #  ec2.create_dhcp_options('domain-name' => 'my.awesomesite.ru',
    #                          'netbios-node-type' => 1) #=>
    #    {:dhcp_options_id=>"dopt-cb0de3a2",
    #     :dhcp_configuration_set=>
    #      {"netbios-node-type"=>["1"], "domain-name"=>["my.awesomesite.ru"]}}
    #
    def create_dhcp_options(dhcp_configuration)
      dhcp_configuration.each{ |key, values| dhcp_configuration[key] = Array(values) }
      request_hash = amazonize_list(['DhcpConfiguration.?.Key','DhcpConfiguration.?.Value.?'], dhcp_configuration)
      link = generate_request("CreateDhcpOptions", request_hash)
      request_info(link, QEc2DescribeDhcpOptionsParser.new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    # Associate DHCP options
    #
    # ec2.associate_dhcp_options("dopt-cb0de3a2", "vpc-890ce2e0" ) #=> true
    # ec2.describe_vpcs #=>
    #    [{:vpc_id=>"vpc-890ce2e0",
    #      :dhcp_options_id=>"dopt-cb0de3a2",
    #      :cidr_block=>"10.0.0.0/23",
    #      :state=>"available"}]
    #
    def associate_dhcp_options(dhcp_options_id, vpc_id)
      link = generate_request("AssociateDhcpOptions", 'DhcpOptionsId' => dhcp_options_id,
                                                      'VpcId'         => vpc_id)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Delete DHCP Options.
    #
    #  ec2.delete_dhcp_options("dopt-cb0de3a2") #=> true
    #
    def delete_dhcp_options(dhcp_options_id)
      link = generate_request("DeleteDhcpOptions", 'DhcpOptionsId' => dhcp_options_id )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #-----------------
    # Customer Gateways
    #-----------------

    # Describe customer gateways.
    #
    # Accepts a list of gateways and/or a set of filters as the last parameter.
    #
    # Filters: bgp-asn, customer-gateway-id, state, type, tag-key, tag-value, tag:key
    #
    #  ec2.describe_customer_gateways #=>
    #    [{:type=>"ipsec.1",
    #      :ip_address=>"12.1.2.3",
    #      :bgp_asn=>"65534",
    #      :state=>"available",
    #      :customer_gateway_id=>"cgw-d5a643bc"}]
    #
    #  ec2.describe_customer_gateways(:filters => {'tag:MyTag' => 'MyValue'})
    #
    # P.S. filters: http://docs.amazonwebservices.com/AmazonVPC/latest/APIReference/index.html?ApiReference-query-DescribeCustomerGateways.html
    #
    def describe_customer_gateways(*list_and_options)
      describe_resources_with_list_and_options('DescribeCustomerGateways', 'CustomerGatewayId', QEc2DescribeCustomerGatewaysParser, list_and_options)
    end

    # Create customer gateway.
    # 
    #  ec2.create_customer_gateway('ipsec.1', '12.1.2.3', 65534) #=>
    #    {:type=>"ipsec.1",
    #     :bgp_asn=>"65534",
    #     :ip_address=>"12.1.2.3",
    #     :state=>"pending",
    #     :customer_gateway_id=>"cgw-d5a643bc"}
    #
    def create_customer_gateway(type, ip_address, bgp_asn)
      link = generate_request("CreateCustomerGateway", 'Type'      => type,
                                                       'IpAddress' => ip_address,
                                                       'BgpAsn'    => bgp_asn )
      request_info(link, QEc2DescribeCustomerGatewaysParser.new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    # Delete customer gateway.
    #
    #  ec2.delete_customer_gateway("cgw-d5a643bc") #=> true
    #
    def delete_customer_gateway(customer_gateway_id)
      link = generate_request("DeleteCustomerGateway", 'CustomerGatewayId' => customer_gateway_id )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #-----------------
    # VPN Gateways
    #-----------------

    # Describe VPN gateways.
    #
    # Accepts a list of VPN gateways and/or a set of filters as the last parameter.
    #
    # Filters: attachment.state, attachment.vpc-id, availability-zone, state, tag-key, tag-value, tag:key, type, vpn-gateway-id
    #
    #  ec2.describe_vpn_gateways #=>
    #    [{:type=>"ipsec.1",
    #      :availability_zone=>"us-east-1a",
    #      :attachments=>[{:vpc_id=>"vpc-890ce2e0", :state=>"attached"}],
    #      :vpn_gateway_id=>"vgw-dfa144b6"}]
    #
    #  ec2.describe_vpn_gateways(:filters => {'tag:MyTag' => 'MyValue'})
    #      
    # P.S. filters: http://docs.amazonwebservices.com/AmazonVPC/latest/APIReference/index.html?ApiReference-query-DescribeVpnGateways.html
    #
    def describe_vpn_gateways(*list_and_options)
      describe_resources_with_list_and_options('DescribeVpnGateways', 'VpnGatewayId', QEc2DescribeVpnGatewaysParser, list_and_options)
    end

    # Create VPN gateway.
    #
    #  ec2.create_vpn_gateway('ipsec.1') #=>
    #    {:type=>"ipsec.1",
    #     :availability_zone=>"us-east-1a",
    #     :attachments=>[nil],
    #     :vpn_gateway_id=>"vgw-dfa144b6"}
    #
    def create_vpn_gateway(type, availability_zone=nil)
      request_hash = { 'Type' => type }
      request_hash['AvailabilityZone'] = availability_zone unless availability_zone.right_blank?
      link = generate_request("CreateVpnGateway", request_hash )
      request_info(link, QEc2DescribeVpnGatewaysParser.new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    # Attach VPN gateway.
    #
    #  ec2.attach_vpn_gateway('vgw-dfa144b6','vpc-890ce2e0') #=>
    #     {:vpc_id=>"vpc-890ce2e0", :state=>"attaching"}
    #
    def attach_vpn_gateway(vpn_gateway_id, vpc_id)
      link = generate_request("AttachVpnGateway", 'VpnGatewayId' => vpn_gateway_id,
                                                  'VpcId'        => vpc_id )
      request_info(link, QEc2AttachVpnGatewayParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Detach VPN gateway.
    #
    #  ec2.detach_vpn_gateway('vgw-dfa144b6','vpc-890ce2e0') #=> true
    #
    def detach_vpn_gateway(vpn_gateway_id, vpc_id)
      link = generate_request("DetachVpnGateway", 'VpnGatewayId' => vpn_gateway_id,
                                                  'VpcId'        => vpc_id )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Delete vpn gateway.
    #
    #  ec2.delete_vpn_gateway("vgw-dfa144b6") #=> true
    #
    def delete_vpn_gateway(vpn_gateway_id)
      link = generate_request("DeleteVpnGateway", 'VpnGatewayId' => vpn_gateway_id )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #-----------------
    # VPN Connections
    #-----------------

    # Describe VPN connections.
    #
    # Accepts a list of VPN gateways and/or a set of filters as the last parameter.
    #
    # Filters: customer-gateway-configuration, customer-gateway-id, state, tag-key, tag-value, tag:key,
    # type, vpn-connection-id, vpn-gateway-id
    #
    #  ec2.describe_vpn_connections #=>
    #    [{:type=>"ipsec.1",
    #      :vpn_connection_id=>"vpn-a9a643c0",
    #      :customer_gateway_configuration=>
    #       "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn_connection id=\"vpn-a9a643c0\">\n...</vpn_connection>\n",
    #      :state=>"available",
    #      :vpn_gateway_id=>"vgw-dfa144b6",
    #      :customer_gateway_id=>"cgw-81a643e8"}]
    #
    #  ec2.describe_vpn_gateways(:filters => {'tag:MyTag' => 'MyValue'})
    #
    # P.S. filters: http://docs.amazonwebservices.com/AmazonVPC/latest/APIReference/index.html?ApiReference-query-DescribeVpnConnections.html
    #
    def describe_vpn_connections(*list_and_options)
      describe_resources_with_list_and_options('DescribeVpnConnections', 'VpnConnectionId', QEc2DescribeVpnConnectionsParser, list_and_options)
    end

    # Create VPN connection.
    #
    #  ec2.create_vpn_connection('ipsec.1', 'cgw-81a643e8' ,'vgw-dfa144b6')
    #    {:customer_gateway_id=>"cgw-81a643e8",
    #     :vpn_connection_id=>"vpn-a9a643c0",
    #     :customer_gateway_configuration=>
    #      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn_connection id=\"vpn-a9a643c0\">\n...</vpn_connection>\n",
    #     :state=>"pending",
    #     :vpn_gateway_id=>"vgw-dfa144b6"}
    #
    def create_vpn_connection(type, customer_gateway_id, vpn_gateway_id)
      link = generate_request("CreateVpnConnection", 'Type'              => type,
                                                     'CustomerGatewayId' => customer_gateway_id,
                                                     'VpnGatewayId'      => vpn_gateway_id )
      request_info(link, QEc2DescribeVpnConnectionsParser.new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    # Delete VPN connection.
    #
    #  ec2.delete_vpn_connection("vpn-a9a643c0") #=> true
    #
    def delete_vpn_connection(vpn_connection_id)
      link = generate_request("DeleteVpnConnection", 'VpnConnectionId' => vpn_connection_id )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end


    #-----------------
    # Parsers
    #-----------------

    class QEc2DescribeVpcsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/(vpcSet/item|vpc)$} then @item    = { :tags => {} }
        when %r{/tagSet/item$}          then @aws_tag = {}
        end
      end
      def tagend(name)
        case name
        when 'vpcId'           then @item[:vpc_id]          = @text
        when 'state'           then @item[:state]           = @text
        when 'dhcpOptionsId'   then @item[:dhcp_options_id] = @text
        when 'cidrBlock'       then @item[:cidr_block]      = @text
        when 'instanceTenancy' then @item[:instance_tenancy] = @text
        when 'isDefault'       then @item[:is_default]      = @text == 'true'
        else
          case full_tag_name
          when %r{/tagSet/item/key$}   then @aws_tag[:key]               = @text
          when %r{/tagSet/item/value$} then @aws_tag[:value]             = @text
          when %r{/tagSet/item$}       then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
          when %r{(vpcSet/item|vpc)$}  then @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2DescribeSubnetsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/(subnetSet/item|subnet)$} then @item = { :tags => {} }
        when %r{/tagSet/item$}   then @aws_tag = {}
        end
      end
      def tagend(name)
        case name
        when 'subnetId'                then @item[:subnet_id]                  = @text
        when 'state'                   then @item[:state]                      = @text
        when 'vpcId'                   then @item[:vpc_id]                     = @text
        when 'cidrBlock'               then @item[:cidr_block]                 = @text
        when 'availabilityZone'        then @item[:availability_zone]          = @text
        when 'availableIpAddressCount' then @item[:available_ip_address_count] = @text
        when 'defaultForAz'            then @item[:default_for_az]             = @text == 'true'
        when 'mapPublicIpOnLaunch'     then @item[:map_public_ip_on_launch]    = @text == 'true'
        else
          case full_tag_name
          when %r{/tagSet/item/key$}   then @aws_tag[:key]               = @text
          when %r{/tagSet/item/value$} then @aws_tag[:value]             = @text
          when %r{/tagSet/item$}       then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
          when %r{/(subnetSet/item|subnet)$} then @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2DescribeDhcpOptionsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/(dhcpOptionsSet/item|dhcpOptions)$} then @item = { :tags => {}, :dhcp_configuration_set => {} }
        when %r{/tagSet/item$}                       then @aws_tag = {}
        end
      end
      def tagend(name)
        case full_tag_name
        when %r{/tagSet/item/key$}       then @aws_tag[:key]               = @text
        when %r{/tagSet/item/value$}     then @aws_tag[:value]             = @text
        when %r{/tagSet/item$}           then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
        when %r{/dhcpOptionsId$}         then @item[:dhcp_options_id]      = @text
        when %r{/dhcpConfigurationSet/item/key$}                 then @conf_item_key = @text
        when %r{/dhcpConfigurationSet/item/valueSet/item/value$} then (@item[:dhcp_configuration_set][@conf_item_key] ||= []) << @text
        when %r{/(dhcpOptionsSet/item|dhcpOptions)$}             then @result << @item
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2DescribeCustomerGatewaysParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/(customerGatewaySet/item|customerGateway)$} then @item = { :tags => {} }
        when %r{/tagSet/item$}                               then @aws_tag = {}
        end
      end
      def tagend(name)
        case name
        when 'customerGatewayId' then @item[:customer_gateway_id] = @text
        when 'state'             then @item[:state]               = @text
        when 'type'              then @item[:type]                = @text
        when 'ipAddress'         then @item[:ip_address]          = @text
        when 'bgpAsn'            then @item[:bgp_asn]             = @text
        else
          case full_tag_name
          when %r{/tagSet/item/key$}       then @aws_tag[:key]               = @text
          when %r{/tagSet/item/value$}     then @aws_tag[:value]             = @text
          when %r{/tagSet/item$}           then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
          when %r{/(customerGatewaySet/item|customerGateway)$} then @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2DescribeVpnGatewaysParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/(vpnGatewaySet/item|vpnGateway)$} then @item = { :tags => {}, :attachments => [] }
        when %r{/attachments/item$}                then @attachment = {}
        when %r{/tagSet/item$}                     then @aws_tag    = {}
        end
      end
      def tagend(name)
        case name
        when 'vpnGatewayId'     then @item[:vpn_gateway_id]    = @text
        when 'availabilityZone' then @item[:availability_zone] = @text
        when 'type'             then @item[:type]              = @text
        when 'vpcId'            then @attachment[:vpc_id]      = @text
        else
          case full_tag_name
          when %r{/vpnGatewaySet/item/state$} then @item[:state]       = @text
          when %r{/attachments/item/state$}   then @attachment[:state] = @text
          when %r{/attachments/item$}         then @item[:attachments] << @attachment unless @attachment.right_blank?
          when %r{/tagSet/item/key$}          then @aws_tag[:key]               = @text
          when %r{/tagSet/item/value$}        then @aws_tag[:value]             = @text
          when %r{/tagSet/item$}              then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
          when %r{/(vpnGatewaySet/item|vpnGateway)$} then @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2AttachVpnGatewayParser < RightAWSParser #:nodoc:
      def tagend(name)
        case name
        when 'vpcId' then @result[:vpc_id] = @text
        when 'state' then @result[:state]  = @text
        end
      end
      def reset
        @result = {}
      end
    end


    class QEc2DescribeVpnConnectionsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/(vpnConnectionSet/item|vpnConnection)$} then @item    = { :tags => {} }
        when %r{/tagSet/item$}                           then @aws_tag = {}
        end
      end
      def tagend(name)
        case name
        when 'vpnConnectionId'              then @item[:vpn_connection_id]              = @text
        when 'state'                        then @item[:state]                          = @text
        when 'type'                         then @item[:type]                           = @text
        when 'vpnGatewayId'                 then @item[:vpn_gateway_id]                 = @text
        when 'customerGatewayId'            then @item[:customer_gateway_id]            = @text
        when 'customerGatewayConfiguration' then @item[:customer_gateway_configuration] = @text
        else
          case full_tag_name
          when %r{/tagSet/item/key$}          then @aws_tag[:key]               = @text
          when %r{/tagSet/item/value$}        then @aws_tag[:value]             = @text
          when %r{/tagSet/item$}              then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
          when %r{/(vpnConnectionSet/item|vpnConnection)$} then @result         << @item
          end
        end
      end
      def reset
        @result = []
      end
    end


  end
end