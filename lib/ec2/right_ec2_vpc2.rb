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

  class Ec2

    # VPC v2: Limits
    #
    # http://docs.amazonwebservices.com/AmazonVPC/latest/UserGuide/index.html?VPC_Appendix_Limits.html
    
    #----------------------
    #   InternetGateways
    #----------------------

    # Create internet gateway
    #
    #  ec2.create_internet_gateway #=> 
    #    { :internet_gateway_id=>"igw-6585c10c", :tags=>{}}
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-CreateInternetGateway.html
    #
    def create_internet_gateway
      link = generate_request("CreateInternetGateway")
      request_info(link, QEc2DescribeInternetGatewaysParser.new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    # Describe internet gateways.
    #
    #  ec2.describe_internet_gateways #=>
    #    [{:state=>"available",
    #      :internet_gateway_id=>"igw-6585c10c",
    #      :vpc_id=>"vpc-df80a6b6",
    #      :tags=>{}},
    #     {:internet_gateway_id=>"igw-883503e1",
    #      :tags=>{}}]
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-CreateInternetGateway.html
    #
    def describe_internet_gateways(*list_and_options)
      describe_resources_with_list_and_options('DescribeInternetGateways', 'InternetGatewayId', QEc2DescribeInternetGatewaysParser, list_and_options)
    rescue Exception
      on_exception
    end

    # Delete internet gateway.
    #
    #  ec2.delete_internet_gateway("igw-6585c10c") #=> true
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DeleteInternetGateway.html
    #
    def delete_internet_gateway(internet_gateway_id)
      link = generate_request("DeleteInternetGateway", 'InternetGatewayId' => internet_gateway_id )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Attaches an Internet gateway to a VPC, enabling connectivity between the Internet and the VPC. 
    # 
    #  ec2.attach_internet_gateway("igw-6585c10c", "vpc-df80a6b6") #=> true
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-AttachInternetGateway.html
    #
    def attach_internet_gateway(internet_gateway_id, vpc_id)
      request_hash = { 'InternetGatewayId' => internet_gateway_id,
                       'VpcId'             => vpc_id }
      link = generate_request("AttachInternetGateway", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Detaches an Internet gateway from a VPC, disabling connectivity between the Internet and the VPC.
    # The VPC must not contain any running instances with Elastic IP addresses. 
    #
    #  ec2.detach_internet_gateway("igw-6585c10c", "vpc-df80a6b6") #=> true
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DetachInternetGateway.html
    #
    def detach_internet_gateway(internet_gateway_id, vpc_id)
      request_hash = { 'InternetGatewayId' => internet_gateway_id,
                       'VpcId'             => vpc_id }
      link = generate_request("DetachInternetGateway", request_hash)
      request_info(link, RightHttp2xxParser::new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #----------------------
    #   RouteTables
    #----------------------

    #  Describe route tables.
    #
    #  # List all tables
    #  ec2.describe_route_tables #=>
    #    [{:route_table_id=>"rtb-be3006d7",
    #      :route_set=>
    #       [{:state=>"active",
    #         :destination_cidr_block=>"10.0.3.0/24",
    #         :gateway_id=>"local"}],
    #      :vpc_id=>"vpc-df80a6b6",
    #      :association_set=>[],
    #      :tags=>{}},
    #     {:route_table_id=>"rtb-e36cf98a",
    #      :route_set=>
    #       [{:state=>"active",
    #         :destination_cidr_block=>"192.168.0.0/24",
    #         :gateway_id=>"local"}],
    #      :vpc_id=>"vpc-e16cf988",
    #      :association_set=>
    #       [{:route_table_id=>"rtb-e36cf98a",
    #         :main=>true,
    #         :route_table_association_id=>"rtbassoc-e26cf98b"}],
    #      :tags=>{}}, ... ]
    #
    #  # Filter tables by VpcId
    #  ec2.describe_route_tables(:filters => {'vpc-id' => "vpc-df80a6b6"})
    #
    #  # Custom route table
    #  ec2.describe_route_tables("rtb-be3006d7") #=> 
    #    [{:vpc_id=>"vpc-df80a6b6",
    #      :route_set=>
    #       [{:state=>"active",
    #         :destination_cidr_block=>"0.0.0.1/32",
    #         :gateway_id=>"igw-6585c10c"},
    #        {:state=>"active",
    #         :destination_cidr_block=>"10.0.3.0/24",
    #         :gateway_id=>"local"}],
    #      :route_table_id=>"rtb-be3006d7",
    #      :tags=>{},
    #      :association_set=>
    #       [{:route_table_association_id=>"rtbassoc-a02610c9",
    #         :subnet_id=>"subnet-b95f76d0",
    #         :route_table_id=>"rtb-be3006d7"}]}]
    #  
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-DescribeRouteTables.html
    # 
    def describe_route_tables(*list_and_options)
      describe_resources_with_list_and_options('DescribeRouteTables', 'RouteTableId', QEc2DescribeRouteTablesParser, list_and_options)
    rescue Exception
      on_exception
    end
    
    # Creates a new route table within a VPC. After you create a new route table, you can add routes and associate the table with a subne
    #
    #  ec2.create_route_table("vpc-df80a6b6") #=>
    #    {:route_table_id=>"rtb-4331072a",
    #     :route_set=>
    #      [{:state=>"active",
    #        :destination_cidr_block=>"10.0.3.0/24",
    #        :gateway_id=>"local"}],
    #     :vpc_id=>"vpc-df80a6b6",
    #     :association_set=>[],
    #     :tags=>{}}
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-CreateRouteTable.html
    #
    def create_route_table(vpc_id)
      link = generate_request("CreateRouteTable", 'VpcId' => vpc_id )
      request_info(link, QEc2DescribeRouteTablesParser::new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    # Deletes a route table from a VPC. 
    # The route table must not be associated with a subnet. You can't delete the main route table.
    #
    #  ec2.delete_route_table("rtb-4331072a") #=> true
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-DeleteRouteTable.html
    def delete_route_table(route_table_id)
      link = generate_request("DeleteRouteTable", 'RouteTableId' => route_table_id )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Associates a subnet with a route table. The subnet and route table must be in the same VPC. 
    # This association causes traffic originating from the subnet to be routed according to the routes in
    # the route table. The action returns an association ID, which you need if you want to disassociate 
    # the route table from the subnet later. A route table can be associated with multiple subnets.
    #
    #  ec2.associate_route_table("rtb-be3006d7", "subnet-b95f76d0") #=> true
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-AssociateRouteTable.html  
    #
    def associate_route_table(route_table_id, subnet_id)
      request_hash = { 'RouteTableId' => route_table_id,
                       'SubnetId'     => subnet_id }
      link = generate_request("AssociateRouteTable", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Disassociates a subnet from a route table.
    #
    #  ec2.disassociate_route_table(route_table_association_id) #=> true
    #  
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DisassociateRouteTable.html
    #
    def disassociate_route_table(route_table_association_id)
      link = generate_request("DisassociateRouteTable", 'AssociationId' => route_table_association_id )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Changes the route table associated with a given subnet in a VPC. After you execute this action, the subnet 
    # uses the routes in the new route table it's associated with. 
    # You can also use this action to change which table is the main route table in the VPC. You just specify 
    # the main route table's association ID and the route table that you want to be the new main route table.
    #
    #  ec2.replace_route_table_association("rtb-be3006d7", "rtbassoc-a02610c9") #=> true
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-ReplaceRouteTableAssociation.html
    #
    def replace_route_table_association(route_table_id, route_table_association_id)
      request_hash = { 'RouteTableId'  => route_table_id,
                       'AssociationId' => route_table_association_id }
      link = generate_request("ReplaceRouteTableAssociation", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end
    
    #---------------------
    # Routes
    #---------------------

    # Creates a new route in a route table within a VPC. The route's target can be either a gateway attached to 
    # the VPC or a NAT instance in the VPC.
    # Options: :gateway_id, :instance_id
    # 
    #  ec2.create_route("rtb-be3006d7",  "0.0.0.1/32", :gateway_id => 'igw-6585c10c') #=> true
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-CreateRoute.html
    #
    def create_route(route_table_id, destination_cidr_block, options = {})
      request_hash = { 'RouteTableId'         => route_table_id,
                       'DestinationCidrBlock' => destination_cidr_block }
      request_hash['GatewayId']  = options[:gateway_id]  unless options[:gateway_id].right_blank?
      request_hash['InstanceId'] = options[:instance_id] unless options[:instance_id].right_blank?      
      link = generate_request("CreateRoute", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Deletes a route from a route table in a VPC.
    #
    #  ec2.delete_route("rtb-be3006d7",  "0.0.0.1/32") #=> true
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DeleteRoute.html
    #
    def delete_route(route_table_id, destination_cidr_block)
      link = generate_request("DeleteRoute", 'RouteTableId'         => route_table_id,
                                             'DestinationCidrBlock' => destination_cidr_block )
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Replaces an existing route within a route table in a VPC
    # Options: :gateway_id, :instance_id
    # 
    #  ec2.replace_route("rtb-be3006d7",  "0.0.0.2/32", :gateway_id => 'igw-6585c10c') #=> true
    #
    # P.S. http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-ReplaceRoute.html
    #
    def replace_route(route_table_id, destination_cidr_block, options = {})
      request_hash = { 'RouteTableId'         => route_table_id,
                       'DestinationCidrBlock' => destination_cidr_block }
      request_hash['GatewayId']  = options[:gateway_id]  unless options[:gateway_id].right_blank?
      request_hash['InstanceId'] = options[:instance_id] unless options[:instance_id].right_blank?      
      link = generate_request("ReplaceRoute", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #---------------------
    # InternetGateways
    #---------------------

    class QEc2DescribeInternetGatewaysParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/(internetGatewaySet/item|internetGateway)$} then @item = { :tags => {} }
        when %r{/tagSet/item$} then @aws_tag = {}
        end
      end
      def tagend(name)
        case full_tag_name
        # item
        when %r{/(internetGatewaySet/item|internetGateway)$} then @result << @item
        when %r{/internetGatewayId$} then @item[:internet_gateway_id] = @text
        when %r{/vpcId$}             then @item[:vpc_id]              = @text
        when %r{/state$}             then @item[:state]               = @text
        # tags
        when %r{/tagSet/item/key$}   then @aws_tag[:key]               = @text
        when %r{/tagSet/item/value$} then @aws_tag[:value]             = @text
        when %r{/tagSet/item$}       then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
        end
      end
      def reset
        @result = []
      end
    end

    #---------------------
    # Routes
    #---------------------

    class QEc2DescribeRouteTablesParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/(routeTableSet/item|routeTable)$}
          @item = { :route_set       => [],
                    :association_set => [],
                    :tags            => {}}
        when %r{/routeSet/item$}       then @route_set       = {}
        when %r{/associationSet/item$} then @association_set = {}
        end
      end
      def tagend(name)
        case full_tag_name
        # item
        when %r{/(routeTableSet/item|routeTable)/routeTableId$} then @item[:route_table_id] = @text
        when %r{/(routeTableSet/item|routeTable)/vpcId$}        then @item[:vpc_id]         = @text
        when %r{/(routeTableSet/item|routeTable)$}              then @result               << @item
        # route set
        when %r{/routeSet/item/destinationCidrBlock$} then @route_set[:destination_cidr_block] = @text
        when %r{/routeSet/item/gatewayId$}            then @route_set[:gateway_id]             = @text
        when %r{/routeSet/item/instanceId$}           then @route_set[:instance_id]            = @text
        when %r{/routeSet/item/state$}                then @route_set[:state]                  = @text
        when %r{/routeSet/item$}                      then @item[:route_set]                  << @route_set
        # association set
        when %r{/associationSet/item/routeTableId$}            then @association_set[:route_table_id]             = @text
        when %r{/associationSet/item/routeTableAssociationId$} then @association_set[:route_table_association_id] = @text
        when %r{/associationSet/item/subnetId$}                then @association_set[:subnet_id]                  = @text
        when %r{/associationSet/item/main}                     then @association_set[:main]                       = @text == 'true'
        when %r{/associationSet/item$}                         then @item[:association_set]                      << @association_set
        # tags
        when %r{/tagSet/item/key$}   then @aws_tag[:key]               = @text
        when %r{/tagSet/item/value$} then @aws_tag[:value]             = @text
        when %r{/tagSet/item$}       then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
        end
      end
      def reset
        @result = []
      end
    end

end

end
