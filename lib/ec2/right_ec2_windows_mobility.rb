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

    def describe_licenses(*license_ids)
      link = generate_request("DescribeLicenses", amazonize_list('LicenseId', license_ids))
      request_info(link, QEc2DescribeLicensesParser.new(:logger => @logger))
    end

    def activate_license(license_id, capacity)
      link = generate_request("ActivateLicense", 'LicenseId' => license_id,
                                                 'Capacity'  => capacity)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    end

#    def get_license_capacity(license_id)
#      link = generate_request("GetLicenseCapacity", 'LicenseId' => license_id)
#      request_info(link, RightBoolResponseParser.new(:logger => @logger))
#    end

    def deactivate_license(license_id, capacity)
      link = generate_request("DeactivateLicense", 'LicenseId' => license_id,
                                                   'Capacity'  => capacity)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS: Images
    #-----------------------------------------------------------------

    class QEc2DescribeLicensesParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        case full_tag_name
        when %r{/licenseSet/item$}  then @item          = { :capacities => [] }
        when %r{/capacitySet/item$} then @capacity_item = {}
        end
      end
      def tagend(name)
        case name
        when 'licenseId'        then @item[:license_id] = @text
        when 'type'             then @item[:type]       = @text
        when 'pool'             then @item[:pool]       = @text
        when 'capacity'         then @capacity_item[:capacity]          = @text.to_i
        when 'instanceCapacity' then @capacity_item[:instance_capacity] = @text.to_i
        when 'state'            then @capacity_item[:state]             = @text
        when 'earliestAllowedDeactivationTime' then @capacity_item[:earliest_allowed_deactivation_time] = @text
        else
          case full_tag_name
          when %r{/capacitySet/item$} then @item[:capacities] << @capacity_item
          when %r{/licenseSet/item$}  then @result            << @item
          end
        end
      end
      def reset
        @result = []
      end
    end

  end
  
end
