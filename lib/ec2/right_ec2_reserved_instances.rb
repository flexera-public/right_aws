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

    RESERVED_INSTANCE_API_VERSION = (API_VERSION > '2012-10-01') ? API_VERSION : '2012-10-01'

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
    #    [{:tags=>{},
    #      :aws_id=>"4357912c-0000-0000-0000-15ca71a8e66d",
    #      :aws_instance_type=>"m1.small",
    #      :aws_availability_zone=>"us-east-1c",
    #      :aws_start=>"2010-03-18T20:39:39.569Z",
    #      :aws_duration=>94608000,
    #      :aws_fixed_price=>350.0,
    #      :aws_usage_price=>0.03,
    #      :aws_instance_count=>1,
    #      :aws_product_description=>"Linux/UNIX",
    #      :aws_state=>"active",
    #      :instance_tenancy=>"default",
    #      :currency_code=>"USD",
    #      :offering_type=>"Medium Utilization"}]
    #
    #  ec2.describe_reserved_instances(:filters => {'availability-zone' => 'us-east-1a'})
    #
    # P.S. filters: http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-DescribeReservedInstances.html
    #
    def describe_reserved_instances(*list_and_options)
      list_and_options = merge_new_options_into_list_and_options(list_and_options, :options => {:api_version => RESERVED_INSTANCE_API_VERSION})
      describe_resources_with_list_and_options('DescribeReservedInstances', 'ReservedInstancesId', QEc2DescribeReservedInstancesParser, list_and_options)
    end

    # Retrieve reserved instances offerings.
    # 
    # Accepts a list of reserved instances offerings and/or a set of filters as the last parameter.
    #
    # Filters: availability-zone, duration, fixed-price, instance-type, product-description, reserved-instances-offering-id, usage-price
    #
    #  ec2.describe_reserved_instances_offerings #=>
    #    [{:recurring_charges=>[{:frequency=>"Hourly", :amount=>"0.095"}],
    #      :pricing_details_set=>[],
    #      :aws_id=>"438012d3-4031-43ff-9241-2964d1bf71d8",
    #      :aws_instance_type=>"c1.medium",
    #      :aws_availability_zone=>"us-east-1e",
    #      :aws_duration=>94608000,
    #      :aws_fixed_price=>775.0,
    #      :aws_usage_price=>0.0,
    #      :aws_product_description=>"Red Hat Enterprise Linux",
    #      :instance_tenancy=>"default",
    #      :currency_code=>"USD",
    #      :offering_type=>"Heavy Utilization",
    #      :marketplace=>false},
    #    { :recurring_charges=>[{:frequency=>"Hourly", :amount=>"0.095"}],
    #      :pricing_details_set=>[],
    #      :aws_id=>"649fd0c8-6cb4-47bf-83db-7a844016afa7",
    #      :aws_instance_type=>"c1.medium",
    #      :aws_availability_zone=>"us-east-1e",
    #      :aws_duration=>94608000,
    #      :aws_fixed_price=>775.0,
    #      :aws_usage_price=>0.0,
    #      :aws_product_description=>"Red Hat Enterprise Linux (Amazon VPC)",
    #      :instance_tenancy=>"default",
    #      :currency_code=>"USD",
    #      :offering_type=>"Heavy Utilization",
    #      :marketplace=>false}, ... ]
    #
    #  ec2.describe_reserved_instances_offerings(:filters => {'availability-zone' => 'us-east-1c'})
    #
    #  # Get all ReservedInstancesOfferings (list by 50 items)
    #  result = ec2.describe_reserved_instances_offerings(:max_results => 50) do |response|
    #    puts response[:items].count
    #    true
    #  end
    #
    #  # Get first 400 ReservedInstancesOfferings.
    #  # P.S. it stops making calls one the block below returns false.
    #  max_count_to_get = 400
    #  counter          = 0
    #  result = ec2.describe_reserved_instances_offerings do |response|
    #    counter += response[:items].count
    #    max_count_to_get <= counter
    #  end
    #
    # P.S. filters: http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-DescribeReservedInstancesOfferings.html
    #
    def describe_reserved_instances_offerings(*list_and_options, &block)
      result = []
      list_and_options = merge_new_options_into_list_and_options(list_and_options, :options => {:api_version => RESERVED_INSTANCE_API_VERSION})
      incrementally_list_items('DescribeReservedInstancesOfferings', 'ReservedInstancesOfferingId', QEc2DescribeReservedInstancesOfferingsParser, list_and_options) do |response|
        result += response[:items]
        block ? block.call(response) : true
      end
      result
    end

    # Purchase a Reserved Instance.
    # Returns ReservedInstancesId value.
    #
    #  ec2.purchase_reserved_instances_offering('e5a2ff3b-f6eb-4b4e-83f8-b879d7060257', 3) # => '4b2293b4-5813-4cc8-9ce3-1957fc1dcfc8'
    #
    def purchase_reserved_instances_offering(reserved_instances_offering_id, instance_count=1, options={})
      options[:options]               ||= {}
      options[:options][:api_version] ||= RESERVED_INSTANCE_API_VERSION

      api_params = { 'ReservedInstancesOfferingId' => reserved_instances_offering_id,
                     'InstanceCount'               => instance_count  }

      link = generate_request("PurchaseReservedInstancesOffering", api_params, options)
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
        when %r{/recurringCharges/item$}     then @recurring_charge = {}
        when %r{/tagSet/item$}               then @aws_tag = {}
        when %r{/reservedInstancesSet/item$} then @item    = { :tags=> {} }
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
        when 'offeringType'        then @item[:offering_type]           = @text
        else
          case full_tag_name
          when %r{/tagSet/item/key$}                 then @aws_tag[:key]                = @text
          when %r{/tagSet/item/value$}               then @aws_tag[:value]              = @text
          when %r{/tagSet/item$}                     then @item[:tags][@aws_tag[:key]]  = @aws_tag[:value]
          when %r{/recurringCharges/item/frequency$} then @recurring_charge[:frequency] = @text
          when %r{/recurringCharges/item/amount$}    then @recurring_charge[:amount]    = @text
          when %r{/recurringCharges/item$}           then (@item[:recurring_charges]  ||= []) << @recurring_charge
          when %r{/reservedInstancesSet/item$}       then @result                      << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

    class QEc2DescribeReservedInstancesOfferingsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/pricingDetailsSet/item$}             then @pricing_details  = {}
        when %r{/recurringCharges/item$}              then @recurring_charge = {}
        when %r{/reservedInstancesOfferingsSet/item$} then @item             = {}
        end
      end
      def tagend(name)
        case name
        when 'nextToken'                   then @result[:next_token]            = @text
        when 'reservedInstancesOfferingId' then @item[:aws_id]                  = @text
        when 'instanceType'                then @item[:aws_instance_type]       = @text
        when 'availabilityZone'            then @item[:aws_availability_zone]   = @text
        when 'duration'                    then @item[:aws_duration]            = @text.to_i
        when 'usagePrice'                  then @item[:aws_usage_price]         = @text.to_f
        when 'fixedPrice'                  then @item[:aws_fixed_price]         = @text.to_f
        when 'instanceTenancy'             then @item[:instance_tenancy]        = @text
        when 'currencyCode'                then @item[:currency_code]           = @text
        when 'productDescription'          then @item[:aws_product_description] = @text
        when 'offeringType'                then @item[:offering_type]           = @text
        when 'marketplace'                 then @item[:marketplace]             = (@text == 'true')
        else
          case full_tag_name
          when %r{/recurringCharges/item/frequency$}    then @recurring_charge[:frequency]  = @text
          when %r{/recurringCharges/item/amount$}       then @recurring_charge[:amount]     = @text
          when %r{/recurringCharges/item$}              then (@item[:recurring_charges]   ||= []) << @recurring_charge
          when %r{/pricingDetailsSet/item/price$}       then @pricing_details[:price]       = @text
          when %r{/pricingDetailsSet/item/count$}       then @pricing_details[:count]       = @text
          when %r{/pricingDetailsSet/item$}             then (@item[:pricing_details_set] ||= []) << @pricing_details
          when %r{/reservedInstancesOfferingsSet/item$} then @result[:items] << @item
          end
        end
      end
      def reset
        @result = { :items => [] }
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