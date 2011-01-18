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

  class AcfInterface

    # List Invalidations
    # 
    #  acf.list_invalidations('E3LTBMK4EAQS7D') #=>
    #    [{:status=>"InProgress", :aws_id=>"I3AW9PPQS0CBKV"},
    #     {:status=>"InProgress", :aws_id=>"I1HV23N5KD3XH9"}]
    #
    def list_invalidations(distribution_aws_id)
      result = []
      incrementally_list_invalidations(distribution_aws_id) do |response|
        result += response[:invalidations]
        true
      end
      result
    end

    # Incrementally list Invalidations.
    # Optional params: +:marker+ and +:max_items+.
    #
    def incrementally_list_invalidations(distribution_aws_id, params={}, &block)
      opts = {}
      opts['MaxItems'] = params[:max_items] if params[:max_items]
      opts['Marker']   = params[:marker]    if params[:marker]
      last_response = nil
      loop do
        link = generate_request('GET', "distribution/#{distribution_aws_id}/invalidation", opts)
        last_response = request_info(link,  AcfInvalidationsListParser.new(:logger => @logger))
        opts['Marker'] = last_response[:next_marker]
        break unless block && block.call(last_response) && !last_response[:next_marker].right_blank?
      end
      last_response
    end

    #-----------------------------------------------------------------
    #      Origin Access Identity
    #-----------------------------------------------------------------

    # Create a new Invalidation batch.
    #
    #  acf.create_invalidation('E3LTBMK4EAQS7D', :path => ['/boot.jpg', '/kd/boot.public.1.jpg']) #=>
    #    {:status=>"InProgress",
    #     :create_time=>"2010-12-08T14:03:38.449Z",
    #     :location=> "https://cloudfront.amazonaws.com/2010-11-01/distribution/E3LTBMK4EAQS7D/invalidation/I3AW9PPQS0CBKV",
    #     :aws_id=>"I3AW9PPQS0CBKV",
    #     :invalidation_batch=>
    #      {:caller_reference=>"201012081703372555972012",
    #       :path=>["/boot.jpg", "/kd/boot.public.1.jpg"]}}
    #
    def create_invalidation(distribution_aws_id, invalidation_batch)
      invalidation_batch[:caller_reference] ||= generate_call_reference
      link = generate_request('POST', "/distribution/#{distribution_aws_id}/invalidation", {}, invalidation_batch_to_xml(invalidation_batch))
      merge_headers(request_info(link, AcfInvalidationsListParser.new(:logger => @logger))[:invalidations].first)
    end

    # Get Invalidation
    #
    #  acf.get_invalidation('E3LTBMK4EAQS7D', 'I3AW9PPQS0CBKV') #=>
    #    {:create_time=>"2010-12-08T14:03:38.449Z",
    #     :status=>"InProgress",
    #     :aws_id=>"I3AW9PPQS0CBKV",
    #     :invalidation_batch=>
    #      {:caller_reference=>"201012081703372555972012",
    #       :path=>["/boot.jpg", "/kd/boot.public.1.jpg"]}}
    #
    def get_invalidation(distribution_aws_id, aws_id)
      link = generate_request('GET', "distribution/#{distribution_aws_id}/invalidation/#{aws_id}")
      merge_headers(request_info(link, AcfInvalidationsListParser.new(:logger => @logger))[:invalidations].first)
    end

    #-----------------------------------------------------------------
    #      Batch
    #-----------------------------------------------------------------

    def invalidation_batch_to_xml(invalidation_batch) # :nodoc:
      paths = ''
      Array(invalidation_batch[:path]).each do |path|
        paths << "  <Path>#{AwsUtils::xml_escape(path)}</Path>\n"
      end
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
      "<InvalidationBatch xmlns=\"http://#{@params[:server]}/doc/#{API_VERSION}/\">\n" +
      "  <CallerReference>#{invalidation_batch[:caller_reference]}</CallerReference>\n" +
      paths +
      "</InvalidationBatch>"
    end

    #-----------------------------------------------------------------
    #      PARSERS:
    #-----------------------------------------------------------------

    class AcfInvalidationsListParser < RightAWSParser # :nodoc:
      def reset
        @result = { :invalidations => [] }
      end
      def tagstart(name, attributes)
        case name
        when %r{(InvalidationSummary|Invalidation)$} then @item = {}
        when %r{InvalidationBatch}                   then @item[:invalidation_batch] = {}
        end
      end
      def tagend(name)
        case name
        when 'Marker'      then @result[:marker]       = @text
        when 'NextMarker'  then @result[:next_marker]  = @text
        when 'MaxItems'    then @result[:max_items]    = @text.to_i
        when 'IsTruncated' then @result[:is_truncated] = (@text == 'true')
        when 'Id'              then @item[:aws_id]                                = @text
        when 'Status'          then @item[:status]                                = @text
        when 'CreateTime'      then @item[:create_time]                           = @text
        when 'Path'            then (@item[:invalidation_batch][:path] ||= [])   << @text
        when 'CallerReference' then @item[:invalidation_batch][:caller_reference] = @text
        when %r{(InvalidationSummary|Invalidation)$}
          @item[:invalidation_batch][:path].sort! if @item[:invalidation_batch] && !@item[:invalidation_batch][:path].right_blank?
          @result[:invalidations] << @item
        end
      end
    end

  end
end