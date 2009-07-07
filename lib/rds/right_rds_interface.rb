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

  # = RightAws::AcfInterface -- RightScale Amazon's CloudFront interface
  # The AcfInterface class provides a complete interface to Amazon's
  # CloudFront service.
  #
  # For explanations of the semantics of each call, please refer to
  # Amazon's documentation at
  # http://developer.amazonwebservices.com/connect/kbcategory.jspa?categoryID=211
  #
  # Example:
  #
  #  acf = RightAws::AcfInterface.new('1E3GDYEOGFJPIT7XXXXXX','hgTHt68JY07JKUY08ftHYtERkjgtfERn57XXXXXX')
  #
  #  list = acf.list_distributions #=>
  #    [{:status             => "Deployed",
  #      :domain_name        => "d74zzrxmpmygb.6hops.net",
  #      :aws_id             => "E4U91HCJHGXVC",
  #      :origin             => "my-bucket.s3.amazonaws.com",
  #      :cnames             => ["x1.my-awesome-site.net", "x1.my-awesome-site.net"]
  #      :comment            => "My comments",
  #      :last_modified_time => Wed Sep 10 17:00:04 UTC 2008 }, ..., {...} ]
  #
  #  distibution = list.first
  #
  #  info = acf.get_distribution(distibution[:aws_id]) #=>
  #    {:enabled            => true,
  #     :caller_reference   => "200809102100536497863003",
  #     :e_tag              => "E39OHHU1ON65SI",
  #     :status             => "Deployed",
  #     :domain_name        => "d3dxv71tbbt6cd.6hops.net",
  #     :cnames             => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
  #     :aws_id             => "E2REJM3VUN5RSI",
  #     :comment            => "Woo-Hoo!",
  #     :origin             => "my-bucket.s3.amazonaws.com",
  #     :last_modified_time => Wed Sep 10 17:00:54 UTC 2008 }
  #
  #  config = acf.get_distribution_config(distibution[:aws_id]) #=>
  #    {:enabled          => true,
  #     :caller_reference => "200809102100536497863003",
  #     :e_tag            => "E39OHHU1ON65SI",
  #     :cnames           => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
  #     :comment          => "Woo-Hoo!",
  #     :origin           => "my-bucket.s3.amazonaws.com"}
  #
  #  config[:comment] = 'Olah-lah!'
  #  config[:enabled] = false
  #  config[:cnames] << "web3.my-awesome-site.net"
  #
  #  acf.set_distribution_config(distibution[:aws_id], config) #=> true
  #
  class RdsInterface < RightAwsBase
    
    include RightAwsBaseInterface

    API_VERSION      = "2009-06-17"
    DEFAULT_HOST     = 'rds.amazonaws.com'
    DEFAULT_PORT     = 443
    DEFAULT_PROTOCOL = 'https'
    DEFAULT_PATH     = '/'

    @@bench = AwsBenchmarkingBlock.new
    def self.bench_xml
      @@bench.xml
    end
    def self.bench_service
      @@bench.service
    end

    # Create a new handle to a CloudFront account. All handles share the same per process or per thread
    # HTTP connection to CloudFront. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol). Example: 'https://cloudfront.amazonaws.com'
    # * <tt>:server</tt>: CloudFront service host, default: DEFAULT_HOST
    # * <tt>:port</tt>: CloudFront service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:multi_thread</tt>: true=HTTP connection per thread, false=per process
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    #
    #  acf = RightAws::AcfInterface.new('1E3GDYEOGFJPIT7XXXXXX','hgTHt68JY07JKUY08ftHYtERkjgtfERn57XXXXXX',
    #    {:logger => Logger.new('/tmp/x.log')}) #=>  #<RightAws::AcfInterface::0xb7b3c30c>
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'RDS',
             :default_host        => ENV['RDS_URL'] ? URI.parse(ENV['RDS_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['RDS_URL'] ? URI.parse(ENV['RDS_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['RDS_URL'] ? URI.parse(ENV['RDS_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['RDS_URL'] ? URI.parse(ENV['RDS_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['RDS_API_VERSION'] || API_VERSION },
           aws_access_key_id     || ENV['AWS_ACCESS_KEY_ID'], 
           aws_secret_access_key || ENV['AWS_SECRET_ACCESS_KEY'], 
           params)
    end

    #-----------------------------------------------------------------
    #      Requests
    #-----------------------------------------------------------------

    # Generates request hash for REST API.
    def generate_request(action, params={}) #:nodoc:
      generate_request_impl(:get, action, params )
    end
      
      # Sends request to Amazon and parses the response.
      # Raises AwsError if any banana happened.
    def request_info(request, parser, &block) # :nodoc:
      request_info_impl(:rds_connection, @@bench, request, parser, &block)
    end

    # Incrementally lists something.
    def incrementally_list_items(action, parser_class, params={}, &block) # :nodoc:
      params = params.dup
      params['MaxRecords'] = params.delete(:max_records) if params[:max_records]
      params['Marker']     = params.delete(:marker)      if params[:marker]
      last_response = nil
      loop do
        link = generate_request(action, params)
        last_response = request_info( link,  parser_class.new(:logger => @logger))
        params['Marker'] = last_response[:marker]
        break unless block && block.call(last_response) && !last_response[:next_token].blank?
      end
      last_response
    end

    #-----------------------------------------------------------------
    #      API Calls:
    #-----------------------------------------------------------------

    # --------------------------------------------
    #  DB Instances
    # --------------------------------------------

    # List DB instances.
    #
    # Optional params: :aws_id, :max_records, :marker
    #
    def describe_db_instances(params={}, &block)
      params = params.dup
      params['DBInstanceIdentifier'] = params.delete(:aws_id) unless params[:aws_id].blank?
      result = []
      incrementally_list_items('DescribeDBInstances', DescribeDbInstancesParcer, params) do |response|
        result += response[:db_instances]
        block ? block.call(response) : true
      end
      result
    end

    # Create a new RDS instance of the type and size specified by you. The default storage engine for RDS Instances is InnoDB.
    #
    # Mandatory arguments: aws_id, master_username, master_user_password
    # Optional params: :allocated_storage (25 by def), :db_instance_class (:medium by def), :engine ('MySQL5.1' by def),
    #                  :endpoint_port, :db_name, :db_security_groups, :availability_zone, :preferred_maintenance_window
    #
    def create_db_instance(aws_id, master_username, master_user_password, params={})
      request_hash = {}
      # Mandatory
      request_hash['DBInstanceIdentifier'] = aws_id
      request_hash['MasterUsername']       = master_username
      request_hash['MasterUserPassword']   = master_user_password
      # Mandatory with default values
      request_hash['DBInstanceClass']  = params[:db_instance_class].blank? ? 'Medium'   : params[:db_instance_class].to_s.capitalize
      request_hash['AllocatedStorage'] = params[:db_instance_class].blank? ? 25         : params[:allocated_storage]
      request_hash['Engine']           = params[:engine].blank?            ? 'MySQL5.1' : params[:engine]
      # Optional
      request_hash['EndpointPort']               = params[:endpoint_port]                     unless params[:endpoint_port].blank?
      request_hash['DBName']                     = params[:db_name]                           unless params[:db_name].blank?
      request_hash['AuthorizedDBSecurityGroups'] = params[:db_security_groups].to_a.join(',') unless params[:db_security_groups].blank?
      request_hash['AvailabilityZone']           = params[:availability_zone]                 unless params[:availability_zone].blank?
      request_hash['PreferredMaintenanceWindow'] = params[:preferred_maintenance_window]      unless params[:preferred_maintenance_window].blank?
      link = generate_request('CreateDBInstance', request_hash)
      request_info(link, DescribeDbInstancesParcer.new(:logger => @logger))[:db_instances].first
    end

    # Modify a DB instance.
    # 
    # Mandatory arguments: aws_id
    # Optional params: :master_user_password, :db_instance_class, :db_security_groups, :preferred_maintenance_window
    #
    def modify_db_instance(aws_id, params={})
      request_hash = {}
      # Mandatory
      request_hash['DBInstanceIdentifier'] = aws_id
      # Optional
      request_hash['MasterUserPassword']         = params[:master_user_password]              unless params[:master_user_password].blank?
      request_hash['DBInstanceClass']            = params[:db_instance_class].to_s.capitalize unless params[:db_instance_class].blank?
      request_hash['DBSecurityGroups']           = params[:db_security_groups].to_a.join(',') unless params[:db_security_groups].blank?
      request_hash['PreferredMaintenanceWindow'] = params[:preferred_maintenance_window]      unless params[:preferred_maintenance_window].blank?
      request_hash['ApplyImmediately']           = params[:force].to_s                        unless params[:force].blank?
      link = generate_request('ModifyDBInstance', request_hash)
      request_info(link, DescribeDbInstancesParcer.new(:logger => @logger))[:db_instances].first
    end

    # Delete a DB instance
    #
    # Mandatory arguments: aws_id
    # Optional params: :force ('false' by def), :snapshot_aws_id ('{instance_aws_id}-final-snapshot-YYYYMMDDHHMMSS')
    #
    def delete_db_instance(aws_id, params={})
      request_hash = {}
      request_hash['DBInstanceIdentifier'] = aws_id
      request_hash['ForceDataDeletion']    = params.has_key?(:force) ? params[:force].to_s : 'false'
      if request_hash['ForceDataDeletion'] == 'false' && params[:snapshot_aws_id].blank?
        params = params.dup
        params[:snapshot_aws_id] = "#{aws_id}-final-snapshot-#{Time.now.utc.strftime('%Y%m%d%H%M%S')}"
      end
      request_hash['FinalDBSnapshotIdentifier'] = params[:snapshot_aws_id] unless params[:snapshot_aws_id].blank?
      link = generate_request('DeleteDBInstance', request_hash)
      request_info(link, DescribeDbInstancesParcer.new(:logger => @logger))[:db_instances].first
    end

    # --------------------------------------------
    #  DB SecurityGroups
    # --------------------------------------------

    def describe_db_security_groups(*aws_ids, &block)
      items, params = AwsUtils::split_items_and_params(aws_ids)
      params.merge!(amazonize_list('DBSecurityGroupName', items))
      result = []
      incrementally_list_items('DescribeDBSecurityGroups', DescribeDbSecurityGroupsParcer, params) do |response|
        result += response[:db_security_groups]
        block ? block.call(response) : true
      end
      result
    end

    # params:
    #  :snapshot =>
    #  :instance =>
    def describe_db_snapshots(params={}, &block)
      params = params.dup
      params['DBSnapshotIdentifier'] = params.delete(:snapshot) unless params[:snapshot].blank?
      params['DBInstanceIdentifier'] = params.delete(:instance) unless params[:instance].blank?
      result = []
      incrementally_list_items('DescribeDBSnapshots', DescribeDbSnapshotsParcer, params) do |response|
        result += response[:db_snapshots]
        block ? block.call(response) : true
      end
      result
    end

    # params:
    #  :duration =>
    def describe_events(params={}, &block)
      params = params.dup
      params['Duration'] = params.delete(:duration) unless params[:duration].blank?
      result = []
      incrementally_list_items('DescribeEvents', DescribeEventsParcer, params) do |response|
        result += response[:events]
        block ? block.call(response) : true
      end
      result
    end







    









=begin


    # Create a new distribution.
    # Returns the just created distribution or RightAws::AwsError exception.
    #
    #  acf.create_distribution('my-bucket.s3.amazonaws.com', 'Woo-Hoo!', true, ['web1.my-awesome-site.net'],
    #                          { :prefix=>"log/", :bucket=>"my-logs.s3.amazonaws.com" } ) #=>
    #    {:comment            => "Woo-Hoo!",
    #     :enabled            => true,
    #     :location           => "https://cloudfront.amazonaws.com/2008-06-30/distribution/E2REJM3VUN5RSI",
    #     :status             => "InProgress",
    #     :aws_id             => "E2REJM3VUN5RSI",
    #     :domain_name        => "d3dxv71tbbt6cd.6hops.net",
    #     :origin             => "my-bucket.s3.amazonaws.com",
    #     :cnames             => ["web1.my-awesome-site.net"],
    #     :logging            => { :prefix => "log/",
    #                              :bucket => "my-logs.s3.amazonaws.com"},
    #     :last_modified_time => Wed Sep 10 17:00:54 UTC 2008,
    #     :caller_reference   => "200809102100536497863003"}
    #
    def create_distribution(origin, comment='', enabled=true, cnames=[], caller_reference=nil, logging={})
      config = { :origin  => origin,
                 :comment => comment,
                 :enabled => enabled,
                 :cnames  => cnames.to_a,
                 :caller_reference => caller_reference }
      config[:logging] = logging unless logging.blank?
      create_distribution_by_config(config)
    end

    def create_distribution_by_config(config)
      config[:caller_reference] ||= generate_call_reference
      link = generate_request('POST', 'distribution', {}, config_to_xml(config))
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end

    # Get a distribution's information.
    # Returns a distribution's information or RightAws::AwsError exception.
    #
    #  acf.get_distribution('E2REJM3VUN5RSI') #=>
    #    {:enabled            => true,
    #     :caller_reference   => "200809102100536497863003",
    #     :e_tag              => "E39OHHU1ON65SI",
    #     :status             => "Deployed",
    #     :domain_name        => "d3dxv71tbbt6cd.6hops.net",
    #     :cnames             => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #     :aws_id             => "E2REJM3VUN5RSI",
    #     :comment            => "Woo-Hoo!",
    #     :origin             => "my-bucket.s3.amazonaws.com",
    #     :last_modified_time => Wed Sep 10 17:00:54 UTC 2008 }
    #
    def get_distribution(aws_id)
      link = generate_request('GET', "distribution/#{aws_id}")
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end

    # Get a distribution's configuration.
    # Returns a distribution's configuration or RightAws::AwsError exception.
    #
    #  acf.get_distribution_config('E2REJM3VUN5RSI') #=>
    #    {:enabled          => true,
    #     :caller_reference => "200809102100536497863003",
    #     :e_tag            => "E39OHHU1ON65SI",
    #     :cnames           => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #     :comment          => "Woo-Hoo!",
    #     :origin           => "my-bucket.s3.amazonaws.com"}
    #
    def get_distribution_config(aws_id)
      link = generate_request('GET', "distribution/#{aws_id}/config")
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end

    # Set a distribution's configuration 
    # (the :origin and the :caller_reference cannot be changed).
    # Returns +true+ on success or RightAws::AwsError exception.
    #
    #  config = acf.get_distribution_config('E2REJM3VUN5RSI') #=>
    #    {:enabled          => true,
    #     :caller_reference => "200809102100536497863003",
    #     :e_tag            => "E39OHHU1ON65SI",
    #     :cnames           => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #     :comment          => "Woo-Hoo!",
    #     :origin           => "my-bucket.s3.amazonaws.com"}
    #  config[:comment] = 'Olah-lah!'
    #  config[:enabled] = false
    #  acf.set_distribution_config('E2REJM3VUN5RSI', config) #=> true
    #
    def set_distribution_config(aws_id, config)
      link = generate_request('PUT', "distribution/#{aws_id}/config", {}, config_to_xml(config),
                                     'If-Match' => config[:e_tag])
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Delete a distribution. The enabled distribution cannot be deleted.
    # Returns +true+ on success or RightAws::AwsError exception.
    #
    #  acf.delete_distribution('E2REJM3VUN5RSI', 'E39OHHU1ON65SI') #=> true
    #
    def delete_distribution(aws_id, e_tag)
      link = generate_request('DELETE', "distribution/#{aws_id}", {}, nil,
                                        'If-Match' => e_tag)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS:
    #-----------------------------------------------------------------
=end

    # --------------------------------------------
    #  DB Instances
    # --------------------------------------------

    class DescribeDbInstancesParcer < RightAWSParser # :nodoc:
      def reset
        @result = { :db_instances => [] }
      end
      def tagstart(name, attributes)
        case name
          when 'DBInstance', 'CreateDBInstanceResult', 'DeleteDBInstanceResult', 'ModifyDBInstanceResult'
            @db_instance = { :db_security_groups => [], :pending_modified_values => {} }
          when 'DBSecurityGroup' then @db_security_group = {}
        end
      end
      def tagend(name)
        case name
        when 'Marker'                     then @result[:marker]       = @text
        when 'NextMarker'                 then @result[:next_marker]  = @text       # ?
        when 'MaxRecords'                 then @result[:max_records]  = @text.to_i  # ?
        when 'CreationDate'               then @db_instance[:creation_date]        = @text
        when 'Engine'                     then @db_instance[:engine]               = @text
        when 'DBInstanceStatus'           then @db_instance[:status]               = @text
        when 'AllocatedStorage'           then @db_instance[:allocated_storage]    = @text.to_i
        when 'DBInstanceIdentifier'       then @db_instance[:aws_id]               = @text
        when 'Port'                       then @db_instance[:endpoint_port]        = @text.to_i
        when 'Address'                    then @db_instance[:endpoint_address]     = @text
        when 'MasterUsername'             then @db_instance[:master_username]      = @text
        when 'AvailabilityZone'           then @db_instance[:availability_zone]    = @text
        when 'PreferredMaintenanceWindow' then @db_instance[:preferred_maintenance_window] = @text
        when 'DBInstanceClass'
          case @xmlpath
          when /DBInstance$/            then @db_instance[:db_instance_class] = @text
          when /PendingModifiedValues$/ then @db_instance[:pending_modified_values][:db_instance_class] = @text
          end
        when 'MasterUserPassword'         then @db_instance[:pending_modified_values][:master_user_password] = @text
        when 'DBSecurityGroupName'        then @db_security_group[:name]   = @text
        when 'Status'                     then @db_security_group[:status] = @text
        when 'DBSecurityGroup'            then @db_instance[:db_security_groups] << @db_security_group
        when 'DBInstance', 'CreateDBInstanceResult', 'DeleteDBInstanceResult', 'ModifyDBInstanceResult'
          @result[:db_instances] << @db_instance
        end
      end
    end

    # --------------------------------------------
    #  DB Security Groups
    # --------------------------------------------

    class DescribeDbSecurityGroupsParcer < RightAWSParser # :nodoc:
      def reset
        @p      = 'DescribeDBSecurityGroupsResponse/DescribeDBSecurityGroupsResult/DBSecurityGroupList/DBSecurityGroup'
        @result = { :db_security_groups => [] }
      end
      def tagstart(name, attributes)
        case name
          when 'DBSecurityGroup'  then @db_security_group  = { :ec2_security_groups => [], :ip_ranges => [] }
          when 'EC2SecurityGroup' then @ec2_security_group = {}
          when 'IPRange'          then @ip_range = {}
        end
      end
      def tagend(name)
        case name
        when 'Marker'                     then @result[:marker]       = @text
        when 'NextMarker'                 then @result[:next_marker]  = @text       # ?
        when 'MaxRecords'                 then @result[:max_records]  = @text.to_i  # ?
        when 'DBSecurityGroupDescription' then @db_security_group[:description] = @text
        when 'OwnerId'                    then @db_security_group[:owner_id]    = @text
        when 'DBSecurityGroupName'        then @db_security_group[:name]        = @text
        when 'Status'
          case @xmlpath
          when "@p/EC2SecurityGroups/EC2SecurityGroup" then @ec2_security_group[:status] = @text
          when "@p/IPRanges/IPRanges"                  then @ip_range[:status] = @text
          end
        when 'EC2GroupName'            then @ec2_security_group[:name]     = @text
        when 'EC2SecurityGroupOwnerId' then @ec2_security_group[:owner_id] = @text
        when 'CIDRIP'                  then @ip_range[:cidrip]             = @text
        when 'IPRange'                 then @ec2_security_group[:ip_ranges]          << @ip_range
        when 'EC2SecurityGroup'        then @db_security_group[:ec2_security_groups] << @ec2_security_group
        when 'DBSecurityGroup'         then @result[:db_security_groups]             << @db_security_group
        end
      end
    end

    # --------------------------------------------
    #  DB Snapshots
    # --------------------------------------------

    class DescribeDbSnapshotsParcer < RightAWSParser # :nodoc:
      def reset
        @result = { :db_snapshots => [] }
      end
      def tagstart(name, attributes)
        case name
          when 'DBSnapshot' then @db_snapshot = {}
        end
      end
      def tagend(name)
        case name
        when 'Marker'               then @result[:marker]            = @text
        when 'NextMarker'           then @result[:next_marker]       = @text       # ?
        when 'MaxRecords'           then @result[:max_records]       = @text.to_i  # ?
        when 'DBEngineName'         then @db_snapshot[:db_engine_name]         = @text
        when 'InstanceCreationDate' then @db_snapshot[:instance_creation_date] = @text
        when 'EndpointPort'         then @db_snapshot[:endpoint_port]          = @text.to_i
        when 'Status'               then @db_snapshot[:status]                 = @text
        when 'AvailabilityZone'     then @db_snapshot[:availability_zone]      = @text
        when 'DBMasterUsername'     then @db_snapshot[:db_master_username]     = @text
        when 'AllocatedStorage'     then @db_snapshot[:allocated_storage]      = @text.to_i
        when 'SnapshotTime'         then @db_snapshot[:snapshot_time]          = @text
        when 'DBInstanceIdentifier' then @db_snapshot[:instance_aws_id]        = @text
        when 'DBSnapshotIdentifier' then @db_snapshot[:aws_id]                 = @text
        when 'DBSnapshot'           then @result[:db_snapshots]               << @db_snapshot
        end
      end
    end

    # --------------------------------------------
    #  DB Events
    # --------------------------------------------

    class DescribeEventsParcer < RightAWSParser # :nodoc:
      def reset
        @result = { :events => [] }
      end
      def tagstart(name, attributes)
        case name
          when 'Event' then @event = {}
        end
      end
      def tagend(name)
        case name
        when 'Marker'           then @result[:marker]       = @text
        when 'NextMarker'       then @result[:next_marker]  = @text       # ?
        when 'MaxRecords'       then @result[:max_records]  = @text.to_i  # ?
        when 'Date'             then @event[:date]          = @text
        when 'SourceIdentifier' then @event[:source_aws_id] = @text
        when 'SourceType'       then @event[:source_type]   = @text
        when 'Message'          then @event[:message]       = @text
        when 'Event'            then @result[:events]      << @event
        end
      end
    end

  end
end
