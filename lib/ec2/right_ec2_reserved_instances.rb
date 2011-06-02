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
  #      Reserved instances
  #-----------------------------------------------------------------

    # Retrieve reserved instances list.
    #
    # Accepts a list of reserved instances and/or a set of filters as the last parameter.
    #
    # Filters: availability-zone, duration, fixed-price, instance-type, product-description,
    # reserved-instances-id, start, state, tag-key, tag-value, tag:key, usage-price
    #
    # ec2.describe_reserved_instances #=>
    #  [{:currency_code=>"USD",
    #    :aws_fixed_price=>350.0,
    #    :aws_availability_zone=>"us-east-1c",
    #    :aws_instance_count=>1,
    #    :tags=>{},
    #    :aws_id=>"4357912c-ad94-4f57-8625-15ca71a8e66d",
    #    :aws_product_description=>"Linux/UNIX",
    #    :aws_state=>"active",
    #    :aws_start=>"2010-03-18T20:39:39.569Z",
    #    :aws_duration=>94608000,
    #    :aws_instance_type=>"m1.small",
    #    :instance_tenancy=>"default",
    #    :aws_usage_price=>0.03}]
    #
    #  ec2.describe_reserved_instances(:filters => {'availability-zone' => 'us-east-1a'})
    #
    # P.S. filters: http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-DescribeReservedInstances.html
    #
    def describe_reserved_instances(*list_and_options)
      describe_resources_with_list_and_options('DescribeReservedInstances', 'ReservedInstancesId', QEc2DescribeReservedInstancesParser, list_and_options)
    end

    # Retrieve reserved instances offerings.
    # 
    # Accepts a list of reserved instances offerings and/or a set of filters as the last parameter.
    #
    # Filters: availability-zone, duration, fixed-price, instance-type, product-description, reserved-instances-offering-id, usage-price
    #
    #  ec2.describe_reserved_instances_offerings #=>
    #    [{:currency_code=>"USD",
    #      :aws_fixed_price=>700.0,
    #      :aws_id=>"248e7b75-933c-451b-b126-be25865e02a5",
    #      :aws_product_description=>"Linux/UNIX",
    #      :aws_instance_type=>"c1.medium",
    #      :aws_duration=>94608000,
    #      :instance_tenancy=>"default",
    #      :aws_usage_price=>0.06,
    #      :aws_availability_zone=>"us-east-1a"},
    #     {:currency_code=>"USD",
    #      :aws_fixed_price=>700.0,
    #      :aws_id=>"c48ab04c-7e03-46b2-891a-2df1116e51a3",
    #      :aws_product_description=>"Linux/UNIX (Amazon VPC)",
    #      :aws_instance_type=>"c1.medium",
    #      :aws_duration=>94608000,
    #      :instance_tenancy=>"default",
    #      :aws_usage_price=>0.06,
    #      :aws_availability_zone=>"us-east-1a"}, ... ]
    #      
    #  ec2.describe_reserved_instances_offerings(:filters => {'availability-zone' => 'us-east-1c'})
    #
    # P.S. filters: http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-DescribeReservedInstancesOfferings.html
    #
    def describe_reserved_instances_offerings(*list_and_options)
      describe_resources_with_list_and_options('DescribeReservedInstancesOfferings', 'ReservedInstancesOfferingId', QEc2DescribeReservedInstancesOfferingsParser, list_and_options)
    end

    # Purchase a Reserved Instance.
    # Returns ReservedInstancesId value.
    #
    #  ec2.purchase_reserved_instances_offering('e5a2ff3b-f6eb-4b4e-83f8-b879d7060257', 3) # => '4b2293b4-5813-4cc8-9ce3-1957fc1dcfc8'
    #
    def purchase_reserved_instances_offering(reserved_instances_offering_id, instance_count=1)
      link = generate_request("PurchaseReservedInstancesOffering", { 'ReservedInstancesOfferingId' => reserved_instances_offering_id,
                                                                     'InstanceCount'               => instance_count  })
      request_info(link, QEc2PurchaseReservedInstancesOfferingParser.new)
    rescue Exception
      on_exception
    end

  #-----------------------------------------------------------------
  #      PARSERS: ReservedInstances
  #-----------------------------------------------------------------

    class QEc2DescribeReservedInstancesParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/reservedInstancesSet/item$} then @item    = { :tags => {} }
        when %r{/tagSet/item$}                        then @aws_tag = {}
        end
      end
      def tagend(name)
        case name
        when 'reservedInstancesId' then @item[:aws_id]                  = @text
        when 'instanceType'        then @item[:aws_instance_type]       = @text
        when 'availabilityZone'    then @item[:aws_availability_zone]   = @text
        when 'duration'            then @item[:aws_duration]            = @text.to_i
        when 'usagePrice'          then @item[:aws_usage_price]         = @text.to_f
        when 'fixedPrice'          then @item[:aws_fixed_price]         = @text.to_f
        when 'instanceCount'       then @item[:aws_instance_count]      = @text.to_i
        when 'productDescription'  then @item[:aws_product_description] = @text
        when 'state'               then @item[:aws_state]               = @text
        when 'start'               then @item[:aws_start]               = @text
        when 'instanceTenancy'     then @item[:instance_tenancy]        = @text
        when 'currencyCode'        then @item[:currency_code]           = @text
        else
          case full_tag_name
          when %r{/tagSet/item/key$}           then @aws_tag[:key]               = @text
          when %r{/tagSet/item/value$}         then @aws_tag[:value]             = @text
          when %r{/tagSet/item$}               then @item[:tags][@aws_tag[:key]] = @aws_tag[:value]
          when %r{/reservedInstancesSet/item$} then @result << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2DescribeReservedInstancesOfferingsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @item = {} if name == 'item'
        end
      def tagend(name)
        case name
        when 'reservedInstancesOfferingId' then @item[:aws_id]                  = @text
        when 'instanceType'                then @item[:aws_instance_type]       = @text
        when 'availabilityZone'            then @item[:aws_availability_zone]   = @text
        when 'duration'                    then @item[:aws_duration]            = @text.to_i
        when 'usagePrice'                  then @item[:aws_usage_price]         = @text.to_f
        when 'fixedPrice'                  then @item[:aws_fixed_price]         = @text.to_f
        when 'instanceTenancy'             then @item[:instance_tenancy]        = @text
        when 'currencyCode'                then @item[:currency_code]           = @text
        when 'productDescription'          then @item[:aws_product_description] = @text
        when 'item'                        then @result << @item
        end
        end
      def reset
        @result = []
      end
    end

    class QEc2PurchaseReservedInstancesOfferingParser < RightAWSParser #:nodoc:
      def tagend(name)
        if name == 'reservedInstancesId'
          @result = @text
        end
      end
      def reset
        @result = ''
      end
    end

  end

end