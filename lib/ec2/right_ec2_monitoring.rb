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

    # Enables monitoring for a running instances. For more information, refer to the Amazon CloudWatch Developer Guide.
    # 
    #  ec2.monitor_instances('i-8437ddec') #=>
    #    {:instance_id=>"i-8437ddec", :monitoring_state=>"pending"}
    #
    def monitor_instances(*list)
      link = generate_request("MonitorInstances", amazonize_list('InstanceId', list.flatten) )
      request_info(link, QEc2MonitorInstancesParser.new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    # Disables monitoring for a running instances. For more information, refer to the Amazon CloudWatch Developer Guide.
    #
    #  ec2.unmonitor_instances('i-8437ddec') #=>
    #    {:instance_id=>"i-8437ddec", :monitoring_state=>"disabling"}
    #
    def unmonitor_instances(*list)
      link = generate_request("UnmonitorInstances", amazonize_list('InstanceId', list.flatten) )
      request_info(link, QEc2MonitorInstancesParser.new(:logger => @logger)).first
    rescue Exception
      on_exception
    end

    class QEc2MonitorInstancesParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @item = {} if name == 'item'
      end
      def tagend(name)
        case name
        when 'instanceId'   then @item[:instance_id] = @text
        when 'state'        then @item[:monitoring_state] = @text
        when 'item'         then @result << @item
        end
      end
      def reset
        @result = []
      end
    end

  end

end