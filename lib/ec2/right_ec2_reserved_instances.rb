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
    # Returns a list of Reserved Instances.
    #
    # ec2.describe_reserved_instances #=>
    #    [{:aws_id=>"1ba8e2e3-1c40-434c-a741-5ff16a4c542e",
    #      :aws_duration=>31536000,
    #      :aws_instance_type=>"m1.small",
    #      :aws_usage_price=>0.03,
    #      :aws_availability_zone=>"us-east-1b",
    #      :aws_state=>"payment-pending",
    #      :aws_product_description=>"Test",
    #      :aws_fixed_price=>325.0,
    #      :aws_start=>"2009-12-18T20:39:39.569Z"
    #      :aws_instance_count=>1}]
    #
    def describe_reserved_instances(*reserved_instances)
      reserved_instances = reserved_instances.flatten
      link = generate_request("DescribeReservedInstances", amazonize_list('ReservedInstancesId', reserved_instances))
      request_cache_or_info(:describe_reserved_instances, link,  QEc2DescribeReservedInstancesParser, @@bench, reserved_instances.blank?)
    rescue Exception
      on_exception
    end

    # Retrieve reserved instances offerings.
    # Returns a set of available offerings.
    #
    # Optional params:
    #  :aws_instance_type       => String
    #  :aws_availability_zone   => String
    #  :aws_product_description => String
    #
    #  ec2.describe_reserved_instances_offerings #=>
    #    [{:aws_instance_type=>"c1.medium",
    #      :aws_availability_zone=>"us-east-1c",
    #      :aws_duration=>94608000,
    #      :aws_product_description=>"Linux/UNIX",
    #      :aws_id=>"e5a2ff3b-f6eb-4b4e-83f8-b879d7060257",
    #      :aws_usage_price=>0.06,
    #      :aws_fixed_price=>1000.0},
    #      ...
    #     {:aws_instance_type=>"m1.xlarge",
    #      :aws_availability_zone=>"us-east-1a",
    #      :aws_duration=>31536000,
    #      :aws_product_description=>"Linux/UNIX",
    #      :aws_id=>"c48ab04c-63ab-4cd6-b8f5-978a29eb9bcc",
    #      :aws_usage_price=>0.24,
    #      :aws_fixed_price=>2600.0}]
    #
    def describe_reserved_instances_offerings(*list_and_params)
      list, params = AwsUtils::split_items_and_params(list_and_params)
      # backward compartibility with the old way
      list ||= Array(params[:aws_ids])
      rparams = {}
      rparams.update(amazonize_list('ReservedInstancesOfferingId', list)) unless list.blank?
      rparams['InstanceType']       = params[:aws_instance_type]       if params[:aws_instance_type]
      rparams['AvailabilityZone']   = params[:aws_availability_zone]   if params[:aws_availability_zone]
      rparams['ProductDescription'] = params[:aws_product_description] if params[:aws_product_description]
      link = generate_request("DescribeReservedInstancesOfferings", rparams)
      request_cache_or_info(:describe_reserved_instances_offerings, link,  QEc2DescribeReservedInstancesOfferingsParser, @@bench, list.blank?)
    rescue Exception
      on_exception
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
        @item = {} if name == 'item'
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
          when 'item'                then @result << @item
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