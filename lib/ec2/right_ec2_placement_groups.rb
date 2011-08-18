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
    #      Placement Groups
    #-----------------------------------------------------------------

    # Describe placement groups.
    #
    # Accepts a list of placement groups and/or a set of filters as the last parameter.
    #
    # Filters: group-name, state, strategy
    #
    # If you don’t specify a particular placement group, the response includes
    # information about all of them. The information includes the group name, the strategy,
    # and the group state (e.g., pending, available, etc.).
    #
    #  ec2.describe_placement_groups #=>
    #    [{:state=>"available", :strategy=>"cluster", :group_name=>"kd_first"},
    #     {:state=>"available", :strategy=>"cluster", :group_name=>"kd_second"}]
    #
    #  ec2.describe_placement_groups('kd_second') #=>
    #    [{:strategy=>"cluster", :group_name=>"kd_second", :state=>"available"}]
    #
    # P.S. filters: http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference_query_DescribePlacementGroups.html
    #
    def describe_placement_groups(*list_and_options)
      describe_resources_with_list_and_options('DescribePlacementGroups', 'GroupName', QEc2DescribePlacementGroupsParser, list_and_options)
    end

    # Create placement group creates a placement group (i.e. logical cluster group)
    # into which you can then launch instances. You must provide a name for the group
    # that is unique within the scope of your account. You must also provide a strategy
    # value. Currently the only value accepted is cluster.
    #
    #   ec2.create_placement_group('kd_second') #=> true
    #
    def create_placement_group(placement_group_name, strategy = 'cluster')
      link = generate_request('CreatePlacementGroup',
                              'GroupName' => placement_group_name.to_s,
                              'Strategy'  => strategy.to_s)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    # Delete placement group deletes a placement group that you own. The group must not
    # contain any instances.
    #
    #   ec2.delete_placement_group('kd_second') #=> true
    #
    def delete_placement_group(placement_group_name)
      link = generate_request('DeletePlacementGroup',
                              'GroupName' => placement_group_name.to_s)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    #-----------------------------------------------------------------
    #      PARSERS: Placement Groups
    #-----------------------------------------------------------------

    class QEc2DescribePlacementGroupsParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case name
        when 'item' then @item = {}
        end
      end
      def tagend(name)
        case name
        when 'groupName' then @item[:group_name] = @text
        when 'strategy'  then @item[:strategy]   = @text
        when 'state'     then @item[:state]      = @text
        when 'item'      then @result           << @item
        end
      end
      def reset
        @result = []
      end
    end

  end
end
