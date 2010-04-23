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

    class RdsInterface < RightAwsBase
    
    include RightAwsBaseInterface

    API_VERSION      = "2009-10-16"
    DEFAULT_HOST     = 'rds.amazonaws.com'
    DEFAULT_PORT     = 443
    DEFAULT_PROTOCOL = 'https'
    DEFAULT_PATH     = '/'

    DEFAULT_INSTANCE_CLASS   =  'db.m1.small'
    INSTANCE_CLASSES         = ['db.m1.small', 'db.m1.large', 'db.m1.xlarge', 'db.m2.2xlarge', 'db.m2.4xlarge']

    @@bench = AwsBenchmarkingBlock.new
    def self.bench_xml
      @@bench.xml
    end
    def self.bench_service
      @@bench.service
    end

    # Create a new handle to a RDS account. All handles share the same per process or per thread
    # HTTP connection to RDS. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol). Example: 'https://rds.amazonaws.com'
    # * <tt>:server</tt>: RDS service host, default: DEFAULT_HOST
    # * <tt>:port</tt>: RDS service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:multi_thread</tt>: true=HTTP connection per thread, false=per process
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    #
    #  rds = RightAws::RdsInterface.new('xxxxxxxxxxxxxxxxxxxxx','xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    #    {:logger => Logger.new('/tmp/x.log')}) #=> #<RightAws::RdsInterface::0xb7b3c30c>
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
        break unless block && block.call(last_response) && !last_response[:marker].blank?
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
    # Optional params: +:aws_id+, +:max_records+, +:marker+
    #
    #  # Get a list of DB instances. The response is an +Array+ of instances.
    #  rds.describe_db_instances #=>
    #    [{:instance_class=>"Medium",
    #      :status=>"creating",
    #      :engine=>"MySQL5.1",
    #      :allocated_storage=>50,
    #      :pending_modified_values=>{},
    #      :db_parameter_group=>{:status=>"in-sync", :name=>"default.MySQL5.1"},
    #      :db_security_groups=>
    #       [{:status=>"active", :name=>"kd-2-test"},
    #        {:status=>"active", :name=>"default"},
    #        {:status=>"active", :name=>"kd-1-test"}],
    #      :availability_zone=>"us-east-1b",
    #      :master_username=>"username",
    #      :aws_id=>"kd-my-awesome-db-2",
    #      :preferred_maintenance_window=>"Sun:05:00-Sun:09:00"}]
    #
    #  # Retrieve a custom DB instance.
    #  # The response is an +Array+ with a single instance record.
    #  rds.describe_db_instances("kd-test-n3")
    #
    #  # Incrementally a list DB instances. Every response part is a +Hash+.
    #  rds.describe_db_instances(:max_records => 30) do |x|
    #    puts x.inspect #=>
    #      {:db_instances=>
    #        [{:instance_class=>"Medium",
    #          :status=>"creating",
    #          :engine=>"MySQL5.1",
    #          :allocated_storage=>50,
    #          :pending_modified_values=>{},
    #          :db_parameter_group=>{:status=>"in-sync", :name=>"default.MySQL5.1"},
    #          :db_security_groups=>
    #           [{:status=>"active", :name=>"kd-2-test"},
    #            {:status=>"active", :name=>"default"},
    #            {:status=>"active", :name=>"kd-1-test"}],
    #          :availability_zone=>"us-east-1b",
    #          :master_username=>"username",
    #          :aws_id=>"kd-my-awesome-db-2",
    #          :preferred_maintenance_window=>"Sun:05:00-Sun:09:00"}]}
    #    true
    #  end
    #
    def describe_db_instances(params={}, &block)
      item, params = AwsUtils::split_items_and_params(params)
      params = params.dup
      params['DBInstanceIdentifier'] = item if item
      result = []
      incrementally_list_items('DescribeDBInstances', DescribeDbInstancesParser, params) do |response|
        result += response[:db_instances]
        block ? block.call(response) : true
      end
      result
    end

    # Create a new RDS instance of the type and size specified by you. The default storage engine for RDS Instances is InnoDB.
    #
    # Mandatory arguments: +aws_id+, +master_username+, +master_user_password+
    # Optional params: +:allocated_storage+ (25 by def), +:instance_class+, +:engine+ ('MySQL5.1' by def),
    # +:endpoint_port+, +:db_name+, +:db_security_groups+, +:db_parameter_group+,  +:availability_zone+, +:preferred_maintenance_window+
    # +:backup_retention_period+, +:preferred_backup_window+
    #
    #  ds.create_db_instance('my-awesome-db', 'username', 'password') #=>
    #    {:instance_class=>"Medium",
    #     :status=>"creating",
    #     :engine=>"MySQL5.1",
    #     :allocated_storage=>50,
    #     :pending_modified_values=>{},
    #     :db_security_groups=>
    #      [{:status=>"active", :name=>"kd-2-test"},
    #       {:status=>"active", :name=>"default"},
    #       {:status=>"active", :name=>"kd-1-test"}],
    #     :availability_zone=>"us-east-1b",
    #     :master_username=>"username",
    #     :aws_id=>"kd-my-awesome-db-2",
    #     :preferred_maintenance_window=>"Sun:05:00-Sun:09:00"}
    #
    def create_db_instance(aws_id, master_username, master_user_password, params={})
      request_hash = {}
      # Mandatory
      request_hash['DBInstanceIdentifier'] = aws_id
      request_hash['MasterUsername']       = master_username
      request_hash['MasterUserPassword']   = master_user_password
      # Mandatory with default values
      request_hash['DBInstanceClass']  = params[:instance_class].blank?    ? DEFAULT_INSTANCE_CLASS : params[:instance_class].to_s
      request_hash['AllocatedStorage'] = params[:allocated_storage].blank? ? 25            : params[:allocated_storage]
      request_hash['Engine']           = params[:engine].blank?            ? 'MySQL5.1'    : params[:engine]
      # Optional
      request_hash['EndpointPort']               = params[:endpoint_port]                unless params[:endpoint_port].blank?
      request_hash['DBName']                     = params[:db_name]                      unless params[:db_name].blank?
      request_hash['AvailabilityZone']           = params[:availability_zone]            unless params[:availability_zone].blank?
      request_hash['PreferredMaintenanceWindow'] = params[:preferred_maintenance_window] unless params[:preferred_maintenance_window].blank?
      request_hash['BackupRetentionPeriod']      = params[:backup_retention_period]      unless params[:backup_retention_period].blank?
      request_hash['PreferredBackupWindow']      = params[:preferred_backup_window]      unless params[:preferred_backup_window].blank?
      request_hash.merge!(amazonize_list('DBSecurityGroups.member',  params[:db_security_groups]))
#      request_hash.merge!(amazonize_list('DBParameterGroups.member', params[:db_parameter_groups]))
      request_hash['DBParameterGroup']           = params[:db_parameter_group]           unless params[:db_parameter_group].blank?
      link = generate_request('CreateDBInstance', request_hash)
      request_info(link, DescribeDbInstancesParser.new(:logger => @logger))[:db_instances].first
    end

    # Modify a DB instance.
    # 
    # Mandatory arguments: +aws_id+. 
    # Optional params: +:master_user_password+, +:instance_class+, +:db_security_groups+,
    # +:db_parameter_group+, +:preferred_maintenance_window+, +:allocated_storage+, +:apply_immediately+,
    # +:backup_retention_period+, +:preferred_backup_window+
    #
    def modify_db_instance(aws_id, params={})
      request_hash = {}
      # Mandatory
      request_hash['DBInstanceIdentifier'] = aws_id
      # Optional
      request_hash['MasterUserPassword']         = params[:master_user_password]           unless params[:master_user_password].blank?
      request_hash['DBInstanceClass']            = params[:instance_class].to_s.capitalize unless params[:instance_class].blank?
      request_hash['PreferredMaintenanceWindow'] = params[:preferred_maintenance_window]   unless params[:preferred_maintenance_window].blank?
      request_hash['BackupRetentionPeriod']      = params[:backup_retention_period]        unless params[:backup_retention_period].blank?
      request_hash['PreferredBackupWindow']      = params[:preferred_backup_window]        unless params[:preferred_backup_window].blank?
      request_hash['AllocatedStorage']           = params[:allocated_storage]              unless params[:allocated_storage].blank?
      request_hash['ApplyImmediately']           = params[:apply_immediately].to_s         unless params[:apply_immediately].blank?
      request_hash.merge!(amazonize_list('DBSecurityGroups.member',  params[:db_security_groups]))
#      request_hash.merge!(amazonize_list('DBParameterGroups.member', params[:db_parameter_groups]))
      request_hash['DBParameterGroupName']       = params[:db_parameter_group]             unless params[:db_parameter_group].blank?
      link = generate_request('ModifyDBInstance', request_hash)
      request_info(link, DescribeDbInstancesParser.new(:logger => @logger))[:db_instances].first
    end

    # Reboot Db instance.
    #
    #  rds.reboot_db_instance('kd-my-awesome-db') #=>
    #    {:status=>"rebooting",
    #     :pending_modified_values=>{},
    #     :allocated_storage=>42,
    #     :master_username=>"kd",
    #     :db_security_groups=>[],
    #     :instance_class=>"Medium",
    #     :availability_zone=>"us-east-1a",
    #     :aws_id=>"kd-my-awesome-db",
    #     :create_time=>"2009-08-28T08:34:21.858Z",
    #     :engine=>"MySQL5.1",
    #     :preferred_maintenance_window=>"Sun:05:00-Sun:09:00"}
    #
    def reboot_db_instance(aws_id, params={})
      params = params.dup
      params['DBInstanceIdentifier'] = aws_id
      link = generate_request('RebootDBInstance', params)
      request_info(link, DescribeDbInstancesParser.new(:logger => @logger))[:db_instances].first
    end

    # Delete a DB instance
    #
    # Mandatory arguments: aws_id
    # Optional params: :skip_final_snapshot ('false' by def),
    #                  :snapshot_aws_id ('{instance_aws_id}-final-snapshot-YYYYMMDDHHMMSS')
    #
    #  rds.delete_db_instance('my-awesome-db-g2') #=> true
    #
    def delete_db_instance(aws_id, params={})
      request_hash = {}
      request_hash['DBInstanceIdentifier'] = aws_id
      request_hash['SkipFinalSnapshot']    = params.has_key?(:skip_final_snapshot) ? params[:skip_final_snapshot].to_s : 'false'
      if request_hash['SkipFinalSnapshot'] == 'false' && params[:snapshot_aws_id].blank?
        params = params.dup
        params[:snapshot_aws_id] = "#{aws_id}-final-snapshot-#{Time.now.utc.strftime('%Y%m%d%H%M%S')}"
      end
      request_hash['FinalDBSnapshotIdentifier'] = params[:snapshot_aws_id] unless params[:snapshot_aws_id].blank?
      link = generate_request('DeleteDBInstance', request_hash)
      request_info(link, DescribeDbInstancesParser.new(:logger => @logger))[:db_instances].first
    end

    # --------------------------------------------
    #  DB SecurityGroups
    # --------------------------------------------
    #
    #  rds.describe_db_security_groups #=>
    #    [{:owner_id=>"82...25",
    #      :description=>"Default",
    #      :ec2_security_groups=>[],
    #      :ip_ranges=>[],
    #      :name=>"Default"},
    #     {:owner_id=>"82...25",
    #      :description=>"kd",
    #      :ec2_security_groups=>[],
    #      :ip_ranges=>[],
    #      :name=>"kd2"},
    #     {:owner_id=>"82...25",
    #      :description=>"kd",
    #      :ec2_security_groups=>
    #       [{:status=>"Authorized", :owner_id=>"82...23", :name=>"default"},
    #        {:status=>"Authorized", :owner_id=>"82...24", :name=>"default1"},
    #        {:status=>"Authorized", :owner_id=>"82...25", :name=>"default"},
    #        {:status=>"Authorized", :owner_id=>"82...26", :name=>"default"},
    #        {:status=>"Authorized", :owner_id=>"82...26", :name=>"default1"},
    #        {:status=>"Authorized", :owner_id=>"82...29", :name=>"default22"}],
    #      :ip_ranges=>
    #       [{:status=>"Authorized", :cidrip=>"127.0.0.1/8"},
    #        {:status=>"Authorized", :cidrip=>"128.0.0.1/8"},
    #        {:status=>"Authorized", :cidrip=>"129.0.0.1/8"},
    #        {:status=>"Authorized", :cidrip=>"130.0.0.1/8"},
    #        {:status=>"Authorized", :cidrip=>"131.0.0.1/8"}],
    #      :name=>"kd3"}]
    #
    #  # get a custom group
    #  rds.describe_db_security_groups('kd3')
    #
    def describe_db_security_groups(*db_security_group_name, &block)
      items, params = AwsUtils::split_items_and_params(db_security_group_name)
      params['DBSecurityGroupName'] = items.first unless items.blank?
      result = []
      incrementally_list_items('DescribeDBSecurityGroups', DescribeDbSecurityGroupsParser, params) do |response|
        result += response[:db_security_groups]
        block ? block.call(response) : true
      end
      result
    end

    # Create a database security group so that ingress to an RDS Instance can be controlled.
    # A new security group cannot have the same name as an existing group.
    #
    #  ds.create_db_security_group('kd3', 'kd') #=>
    #    {:ec2_security_groups=>[],
    #     :description=>"kd",
    #     :ip_ranges=>[],
    #     :name=>"kd3",
    #     :owner_id=>"82...25"}
    #
    def create_db_security_group(db_security_group_name, db_security_group_description)
      link = generate_request('CreateDBSecurityGroup', 'DBSecurityGroupName'        => db_security_group_name,
                                                       'DBSecurityGroupDescription' => db_security_group_description)
      request_info(link, DescribeDbSecurityGroupsParser.new(:logger => @logger))[:db_security_groups].first
    end

    def modify_db_security_group_ingress(action, db_security_group_name, params={}) # :nodoc:
      request_hash = { 'DBSecurityGroupName' => db_security_group_name}
      request_hash['CIDRIP']                  = params[:cidrip]                   unless params[:cidrip].blank?
      request_hash['EC2SecurityGroupName']    = params[:ec2_security_group_name]  unless params[:ec2_security_group_name].blank?
      request_hash['EC2SecurityGroupOwnerId'] = params[:ec2_security_group_owner] unless params[:ec2_security_group_owner].blank?
      link = generate_request(action, request_hash)
      request_info(link, DescribeDbSecurityGroupsParser.new(:logger => @logger))[:db_security_groups].first
    end

    # Authorize an ingress. Params: +:cidrip+ or (+:ec2_security_group_name+ and +:ec2_security_group_owner+)
    #  
    #  rds.authorize_db_security_group_ingress('kd3', :cidrip => '131.0.0.1/8')
    #    {:owner_id=>"82...25",
    #     :ec2_security_groups=>[],
    #     :description=>"kd",
    #     :ip_ranges=>
    #      [{:status=>"Authorized", :cidrip=>"127.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"128.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"129.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"130.0.0.1/8"},
    #       {:status=>"Authorizing", :cidrip=>"131.0.0.1/8"}],
    #     :name=>"kd3"}
    #
    #  rds.authorize_db_security_group_ingress('kd3',:ec2_security_group_owner => '82...27',
    #                                                :ec2_security_group_name => 'default') #=>
    #    {:owner_id=>"82...25",
    #     :ec2_security_groups=>
    #      [{:status=>"Authorized", :owner_id=>"82...25", :name=>"g1"},
    #       {:status=>"Authorized", :owner_id=>"82...26", :name=>"g2"},
    #       {:status=>"Authorizing", :owner_id=>"82...27", :name=>"default"}],
    #     :ip_ranges=>
    #      [{:status=>"Authorized", :cidrip=>"127.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"128.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"129.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"130.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"131.0.0.1/8"}],
    #     :name=>"kd3"}
    #
    def authorize_db_security_group_ingress(db_security_group_name, params={})
      modify_db_security_group_ingress('AuthorizeDBSecurityGroupIngress', db_security_group_name, params)
    end

    # Revoke an ingress.
    # Optional params: +:cidrip+ or (+:ec2_security_group_name+ and +:ec2_security_group_owner+)
    #
    #  rds.revoke_db_security_group_ingress('kd3', :ec2_security_group_owner => '82...25',
    #                                              :ec2_security_group_name => 'default') #=>
    #    {:owner_id=>"82...25",
    #     :ec2_security_groups=>
    #      [{:status=>"Revoking", :owner_id=>"826693181925", :name=>"default"}],
    #     :name=>"kd3",
    #     :description=>"kd",
    #     :ip_ranges=>
    #      [{:status=>"Authorized", :cidrip=>"127.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"128.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"129.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"130.0.0.1/8"},
    #       {:status=>"Authorized", :cidrip=>"131.0.0.1/8"}]}
    #
    def revoke_db_security_group_ingress(db_security_group_name, params={})
      modify_db_security_group_ingress('RevokeDBSecurityGroupIngress', db_security_group_name, params)
    end

    # Delete a database security group. Database security group must not be associated with any
    # RDS Instances.
    #
    #  rds.delete_db_security_group('kd3') #=> true
    #
    def delete_db_security_group(db_security_group_name)
      link = generate_request('DeleteDBSecurityGroup', 'DBSecurityGroupName' => db_security_group_name)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # --------------------------------------------
    #  DB ParameterGroups
    # --------------------------------------------

    # Describe DBParameterGroups.
    #
    #  rds.describe_db_parameter_groups #=>
    #    [{:engine=>"MySQL5.1",
    #      :description=>"Default parameter group for MySQL5.1",
    #      :name=>"default.MySQL5.1"}]
    #
    #  # List parameter groups by 20
    #  rds.describe_db_parameter_groups(:max_records=>20) do |response|
    #    puts response.inspect
    #    true
    #  end
    #
    def describe_db_parameter_groups(*db_parameter_group_name, &block)
      items, params = AwsUtils::split_items_and_params(db_parameter_group_name)
      params['DBParameterGroupName'] = items.first unless items.blank?
      result = []
      incrementally_list_items('DescribeDBParameterGroups', DescribeDbParameterGroupsParser, params) do |response|
        result += response[:db_parameter_groups]
        block ? block.call(response) : true
      end
      result
    end

    # Creates a database parameter group so that configuration of an RDS Instance can be controlled.
    #
    #  rds.create_db_parameter_group('my-new-group-1','My new group') #=> {}
    #
    #  TODO: this call returns an empty hash, but should be a parameter group data - ask Amazon guys.
    #
    def create_db_parameter_group(db_parameter_group_name, db_parameter_group_description, engine='MySQL5.1', params={})
      params['DBParameterGroupName'] = db_parameter_group_name
      params['Description']          = db_parameter_group_description
      params['Engine']               = engine
      link = generate_request('CreateDBParameterGroup', params )
      request_info(link, DescribeDbParameterGroupsParser.new(:logger => @logger))[:db_parameter_groups].first
    end


    # Modify DBParameterGroup paramaters. Up to 20 params can be midified at once.
    #
    #  rds.modify_db_parameter_group('kd1', 'max_allowed_packet' => 2048) #=> true
    #  
    #  rds.modify_db_parameter_group('kd1', 'max_allowed_packet' => {:value => 2048, :method => 'immediate')  #=> true
    #
    def modify_db_parameter_group(db_parameter_group_name, params={}) # :nodoc:
      request_hash = { 'DBParameterGroupName' => db_parameter_group_name}
      parameters = []
      params.each do |key, value|
        method = 'pending-reboot'
        if value.is_a?(Hash)
          method = value[:method] unless value[:method].blank?
          value  = value[:value]
        end
        parameters << [key, value, method]
      end
      request_hash.merge!( amazonize_list(['Parameters.member.?.ParameterName',
                                           'Parameters.member.?.ParameterValue',
                                           'Parameters.member.?.ApplyMethod'],
                                           parameters ))
      link = generate_request('ModifyDBParameterGroup', request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Delete DBParameter Group.
    #
    # rds.delete_db_parameter_group('kd1') #=> true
    #
    def delete_db_parameter_group(db_parameter_group_name)
      link = generate_request('DeleteDBParameterGroup', 'DBParameterGroupName' => db_parameter_group_name)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Modify the parameters of a DBParameterGroup to the engine/system default value.
    # 
    #  # Reset all parameters
    #  rds.reset_db_parameter_group('kd2', :all ) #=> true
    #
    #  # Reset custom parameters
    #  rds.reset_db_parameter_group('kd2', 'max_allowed_packet', 'auto_increment_increment' ) #=> true
    #  rds.reset_db_parameter_group('kd2', 'max_allowed_packet', 'auto_increment_increment' => 'immediate' ) #=> true
    #
    def reset_db_parameter_group(db_parameter_group_name, *params)
      params = params.flatten
      request_hash = { 'DBParameterGroupName' => db_parameter_group_name }
      if params.first.to_s == 'all'
        request_hash['ResetAllParameters'] = true
      else
        tmp = []
        params.each{ |item| tmp |= item.to_a }
        params = []
        tmp.each do |key, method|
          method = 'pending-reboot' unless method
          params << [key, method]
        end
        request_hash.merge!( amazonize_list(['Parameters.member.?.ParameterName',
                                             'Parameters.member.?.ApplyMethod'],
                                             params ))
      end
      link = generate_request('ResetDBParameterGroup', request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Get the detailed parameters list for a particular DBParameterGroup.
    #
    #  rds.describe_db_parameters('kd1') #=>
    #    [{:is_modifiable=>true,
    #      :apply_type=>"static",
    #      :source=>"engine-default",
    #      :allowed_values=>"ON,OFF",
    #      :description=>"Controls whether user-defined functions that have only an xxx symbol for the main function can be loaded",
    #      :name=>"allow-suspicious-udfs",
    #      :data_type=>"boolean"},
    #     {:is_modifiable=>true,
    #      :apply_type=>"dynamic",
    #      :source=>"engine-default",
    #      :allowed_values=>"1-65535",
    #      :description=>"Intended for use with master-to-master replication, and can be used to control the operation of AUTO_INCREMENT columns",
    #      :name=>"auto_increment_increment",
    #      :data_type=>"integer"}, ... ]
    #
    #  # List parameters by 20
    #  rds.describe_db_parameters('kd1', :max_records=>20) do |response|
    #    puts response.inspect
    #    true
    #  end
    #
    def describe_db_parameters(*db_parameter_group_name, &block)
      item, params = AwsUtils::split_items_and_params(db_parameter_group_name)
      params['DBParameterGroupName'] = item
      result = []
      incrementally_list_items('DescribeDBParameters', DescribeDbParametersParser, params) do |response|
        result += response[:parameters]
        block ? block.call(response) : true
      end
      result
    end

    # Describe a default parameters for the engine.
    #
    #  rds.describe_engine_default_parameters('MySQL5.1') #=>
    #    [{:is_modifiable=>true,
    #      :apply_type=>"static",
    #      :source=>"engine-default",
    #      :allowed_values=>"ON,OFF",
    #      :description=>"Controls whether user-defined functions that have only an xxx symbol for the main function can be loaded",
    #      :name=>"allow-suspicious-udfs",
    #      :data_type=>"boolean"},
    #     {:is_modifiable=>true,
    #      :apply_type=>"dynamic",
    #      :source=>"engine-default",
    #      :allowed_values=>"1-65535",
    #      :description=>"Intended for use with master-to-master replication, and can be used to control the operation of AUTO_INCREMENT columns",
    #      :name=>"auto_increment_increment",
    #      :data_type=>"integer"}, ... ]
    #
    def describe_engine_default_parameters(*engine, &block)
      engine = ['MySQL5.1'] if engine.blank?
      item, params = AwsUtils::split_items_and_params(engine)
      params['Engine'] = item if item
      result = []
      incrementally_list_items('DescribeEngineDefaultParameters', DescribeDbParametersParser, params) do |response|
        result += response[:parameters]
        block ? block.call(response) : true
      end
      result
    end

    # --------------------------------------------
    #  DB Snapshots
    # --------------------------------------------

    # Get DBSecurityGroup details for a particular customer or for a particular DBSecurityGroup if a name is specified.
    # Optional params: +:instance_aws_id+
    #
    #  # all snapshots
    #  rds.describe_db_snapshots #=>
    #    [{:status=>"Available",
    #      :instance_aws_id=>"kd-test-n1",
    #      :allocated_storage=>25,
    #      :availability_zone=>"us-east-1b",
    #      :aws_id=>"kd-test-n1-final-snapshot-at-20090630131215",
    #      :engine=>"MySQL5.1",
    #      :endpoint_port=>3306,
    #      :instance_create_time=>"2009-06-30T12:48:15.590Z",
    #      :master_username=>"payless",
    #      :snapshot_time=>"2009-06-30T13:16:48.496Z"}, ...]
    #
    #  # all snapshots for a custom instance
    #  rds.describe_db_snapshots(:instance_aws_id => 'kd-test-n3') #=>
    #    [{:status=>"Available",
    #      :instance_aws_id=>"kd-test-n3",
    #      :allocated_storage=>25,
    #      :availability_zone=>"us-east-1a",
    #      :aws_id=>"kd-test-n3-final-snapshot-20090713074916",
    #      :engine=>"MySQL5.1",
    #      :endpoint_port=>3306,
    #      :instance_create_time=>"2009-06-30T12:51:32.540Z",
    #      :master_username=>"payless",
    #      :snapshot_time=>"2009-07-13T07:52:35.542Z"}]
    #
    #  # a snapshot by id
    #  rds.describe_db_snapshots('my-awesome-db-final-snapshot-20090713075554') #=>
    #    [{:status=>"Available",
    #      :allocated_storage=>25,
    #      :engine=>"MySQL5.1",
    #      :instance_aws_id=>"my-awesome-db",
    #      :availability_zone=>"us-east-1a",
    #      :instance_create_time=>"2009-07-13T07:53:08.912Z",
    #      :endpoint_port=>3306,
    #      :master_username=>"medium",
    #      :aws_id=>"my-awesome-db-final-snapshot-20090713075554",
    #      :snapshot_time=>"2009-07-13T07:59:17.537Z"}]
    #
    def describe_db_snapshots(params={}, &block)
      item, params = AwsUtils::split_items_and_params(params)
      params['DBSnapshotIdentifier'] = item if item
      params['DBInstanceIdentifier'] = params.delete(:instance_aws_id) unless params[:instance_aws_id].blank?
      result = []
      incrementally_list_items('DescribeDBSnapshots', DescribeDbSnapshotsParser, params) do |response|
        result += response[:db_snapshots]
        block ? block.call(response) : true
      end
      result
    end

    # Create a DBSnapshot. The source DBInstance must be in Available state
    #
    #  rds.create_db_snapshot('remove-me-tomorrow-2', 'my-awesome-db-g7' ) #=>
    #    {:status=>"PendingCreation",
    #     :allocated_storage=>50,
    #     :availability_zone=>"us-east-1b",
    #     :engine=>"MySQL5.1",
    #     :aws_id=>"remove-me-tomorrow-2",
    #     :instance_create_time=>"2009-07-13T09:35:39.243Z",
    #     :endpoint_port=>3306,
    #     :instance_aws_id=>"my-awesome-db-g7",
    #     :db_master_username=>"username"}
    #
    def create_db_snapshot(aws_id, instance_aws_id)
      link = generate_request('CreateDBSnapshot', 'DBSnapshotIdentifier' => aws_id,
                                                  'DBInstanceIdentifier' => instance_aws_id)
      request_info(link, DescribeDbSnapshotsParser.new(:logger => @logger))[:db_snapshots].first
    end

    # Create a new RDS instance from a DBSnapshot. The source DBSnapshot must be
    # in the "Available" state. The new RDS instance is created with the Default security group.
    #
    # Optional params: +:instance_class+, +:endpoint_port+, +:availability_zone+
    #
    #  rds.restore_db_instance_from_db_snapshot('ahahahaha-final-snapshot-20090828081159', 'q1') #=>
    #    {:status=>"creating",
    #     :pending_modified_values=>{},
    #     :allocated_storage=>42,
    #     :db_security_groups=>[],
    #     :master_username=>"kd",
    #     :availability_zone=>"us-east-1a",
    #     :aws_id=>"q1",
    #     :create_time=>"2009-08-29T18:07:01.510Z",
    #     :instance_class=>"Medium",
    #     :preferred_maintenance_window=>"Sun:05:00-Sun:09:00",
    #     :engine=>"MySQL5.1"}
    #
    def restore_db_instance_from_db_snapshot(snapshot_aws_id, instance_aws_id, params={})
      request_hash = { 'DBSnapshotIdentifier' => snapshot_aws_id,
                       'DBInstanceIdentifier' => instance_aws_id }
      request_hash['DBInstanceClass']  = params[:instance_class]    unless params[:instance_class].blank?
      request_hash['EndpointPort']     = params[:endpoint_port]     unless params[:endpoint_port].blank?
      request_hash['AvailabilityZone'] = params[:availability_zone] unless params[:availability_zone].blank?
      link = generate_request('RestoreDBInstanceFromDBSnapshot', request_hash)
      request_info(link, DescribeDbInstancesParser.new(:logger => @logger))[:db_instances].first
    end

    # Create a new RDS instance from a point-in-time system snapshot. The target
    # database is created from the source database restore point with the same configuration as
    # the original source database, except that the new RDS instance is created with the default
    # security group.
    def restore_db_instance_to_point_in_time(instance_aws_id, new_instance_aws_id, restore_time)
      request_hash = { 'SourceDBInstanceIdentifier' => instance_aws_id,
                       'TargetDBInstanceIdentifier' => new_instance_aws_id,
                       'RestoreTime' => restore_time}
      link = generate_request('RestoreDBInstanceToPointInTime', request_hash)
      request_info(link, DescribeDbInstancesParser.new(:logger => @logger))[:db_instances].first
    end

    # Delete a DBSnapshot. The DBSnapshot must be in the Available state to be deleted.
    #
    #  rds.delete_db_snapshot('remove-me-tomorrow-1') #=>
    #    {:status=>"Deleted",
    #     :allocated_storage=>50,
    #     :instance_create_time=>"2009-07-13T09:27:01.053Z",
    #     :availability_zone=>"us-east-1a",
    #     :db_master_username=>"username",
    #     :aws_id=>"remove-me-tomorrow-1",
    #     :snapshot_time=>"2009-07-13T10:59:30.227Z",
    #     :endpoint_port=>3306,
    #     :instance_aws_id=>"my-awesome-db-g5",
    #     :engine=>"MySQL5.1"}
    #
    def delete_db_snapshot(aws_id)
      link = generate_request('DeleteDBSnapshot', 'DBSnapshotIdentifier' => aws_id)
      request_info(link, DescribeDbSnapshotsParser.new(:logger => @logger))[:db_snapshots].first
    end

    # --------------------------------------------
    #  DB Events
    # --------------------------------------------

    # Get events related to RDS instances and DBSecurityGroups for the past 14 days.
    # Optional params: +:duration+, +:start_time+, +:end_time+, +:aws_id+, 
    #                  +:source_type+('db-instance', 'db-security-group', 'db-snapshot', 'db-parameter-group')
    #
    #  # get all enevts
    #  rds.describe_events #=>
    #    [{:aws_id=>"my-awesome-db-g4",
    #      :source_type=>"DBInstance",
    #      :message=>"Started user snapshot for database instance:my-awesome-db-g4",
    #      :date=>"2009-07-13T10:54:13.661Z"},
    #     {:aws_id=>"my-awesome-db-g5",
    #      :source_type=>"DBInstance",
    #      :message=>"Started user snapshot for database instance:my-awesome-db-g5",
    #      :date=>"2009-07-13T10:55:13.674Z"},
    #     {:aws_id=>"my-awesome-db-g7",
    #      :source_type=>"DBInstance",
    #      :message=>"Started user snapshot for database instance:my-awesome-db-g7",
    #      :date=>"2009-07-13T10:56:34.226Z"}]
    #
    #  # get all events since yesterday
    #  rds.describe_events(:start_date => 1.day.ago)
    #
    #  # get last 60 min events
    #  rds.describe_events(:duration => 60)
    #
    def describe_events(params={}, &block)
      params = params.dup
      params['SourceIdentifier'] = params.delete(:aws_id)                unless params[:aws_id].blank?
      params['SourceType']       = params.delete(:source_type)           unless params[:source_type].blank?
      params['Duration']         = params.delete(:duration)              unless params[:duration].blank?
      params['StartDate']        = fix_date(params.delete(:start_date))  unless params[:start_date].blank?
      params['EndDate']          = fix_date(params.delete(:end_date))    unless params[:end_date].blank?
      result = []
      incrementally_list_items('DescribeEvents', DescribeEventsParser, params) do |response|
        result += response[:events]
        block ? block.call(response) : true
      end
      result
    end

    def fix_date(date) # :nodoc:
      date = Time.at(date) if date.is_a?(Fixnum)
      date = date.utc.strftime('%Y-%m-%dT%H:%M:%SZ') if date.is_a?(Time)
      date
    end

    # --------------------------------------------
    #  Parsers
    # --------------------------------------------

    # --------------------------------------------
    #  DB Instances
    # --------------------------------------------

    class DescribeDbInstancesParser < RightAWSParser # :nodoc:
      def reset
        @m = [ 'DBInstance',
               'CreateDBInstanceResult',
               'DeleteDBInstanceResult',
               'ModifyDBInstanceResult',
               'RebootDBInstanceResult',
               'RestoreDBInstanceToPointInTimeResponse',
               'RestoreDBInstanceFromDBSnapshotResult' ]
        @result = { :db_instances => [] }
      end
      def tagstart(name, attributes)
        case name
          when *@m               then @db_instance = { :db_security_groups => [], 
                                                       :pending_modified_values => {} }
          when 'DBSecurityGroup' then @db_security_group = {}
          when 'DBParameterGroup', 'DBParameterGroupStatus' then @db_parameter_group = {}
        end
      end
      def tagend(name)
        case name
        when 'Marker'                     then @result[:marker]       = @text
        when 'MaxRecords'                 then @result[:max_records]  = @text.to_i
        when 'DBInstanceIdentifier'       then @db_instance[:aws_id]               = @text
        when 'DBName'                     then @db_instance[:name]                 = @text  # ? is this one used?
        when 'InstanceCreateTime'         then @db_instance[:create_time]          = @text
        when 'Engine'                     then @db_instance[:engine]               = @text
        when 'DBInstanceStatus'           then @db_instance[:status]               = @text
        when 'AllocatedStorage'           then @db_instance[:allocated_storage]    = @text.to_i
        when 'Port'                       then @db_instance[:endpoint_port]        = @text.to_i
        when 'Address'                    then @db_instance[:endpoint_address]     = @text
        when 'MasterUsername'             then @db_instance[:master_username]      = @text
        when 'AvailabilityZone'           then @db_instance[:availability_zone]    = @text
        when 'PreferredMaintenanceWindow' then @db_instance[:preferred_maintenance_window] = @text
        when 'BackupRetentionPeriod'      then @db_instance[:backup_retention_period] = @text
        when 'PreferredBackupWindow'      then @db_instance[:preferred_backup_window] = @text
        when 'DBInstanceClass'
          case @xmlpath
          when /PendingModifiedValues$/ then @db_instance[:pending_modified_values][:instance_class] = @text
          else                               @db_instance[:instance_class] = @text
          end
        when 'MasterUserPassword'         then @db_instance[:pending_modified_values][:master_user_password] = @text
        when 'DBSecurityGroupName'        then @db_security_group[:name]   = @text
        when 'Status'                     then @db_security_group[:status] = @text
        when 'DBParameterGroupName'       then @db_parameter_group[:name]   = @text
        when 'ParameterApplyStatus'       then @db_parameter_group[:status] = @text
        when 'DBSecurityGroup'            then @db_instance[:db_security_groups] << @db_security_group
        when 'DBParameterGroup','DBParameterGroupStatus'
          @db_instance[:db_parameter_group] = @db_parameter_group
        when *@m                          then @result[:db_instances]            << @db_instance
        end
      end
    end

    # --------------------------------------------
    #  DB Security Groups
    # --------------------------------------------

    class DescribeDbSecurityGroupsParser < RightAWSParser # :nodoc:
      def reset
        @m = [ 'DBSecurityGroup',
               'CreateDBSecurityGroupResult',
               'AuthorizeDBSecurityGroupIngressResult',
               'RevokeDBSecurityGroupIngressResult' ]
        @result = { :db_security_groups => [] }
      end
      def tagstart(name, attributes)
        case name
          when *@m                then @item     = { :ec2_security_groups => [], :ip_ranges => [] }
          when 'IPRange'          then @ip_range = {}
          when 'EC2SecurityGroup' then @ec2_security_group = {}
        end
      end
      def tagend(name)
        case name
        when 'Marker'                     then @result[:marker]       = @text
        when 'MaxRecords'                 then @result[:max_records]  = @text.to_i
        when 'DBSecurityGroupDescription' then @item[:description] = @text
        when 'OwnerId'                    then @item[:owner_id]    = @text
        when 'DBSecurityGroupName'        then @item[:name]        = @text
        when 'Status'
          case @xmlpath
          when /IPRange$/          then @ip_range[:status] = @text
          when /EC2SecurityGroup$/ then @ec2_security_group[:status] = @text
          end
        when 'EC2SecurityGroupName'    then @ec2_security_group[:name]     = @text
        when 'EC2SecurityGroupOwnerId' then @ec2_security_group[:owner_id] = @text
        when 'CIDRIP'                  then @ip_range[:cidrip]             = @text
        when 'IPRange'                 then @item[:ip_ranges]           << @ip_range
        when 'EC2SecurityGroup'        then @item[:ec2_security_groups] << @ec2_security_group
        when *@m
          # Sort the ip_ranges and ec2_security_groups
          @item[:ip_ranges].sort!{ |i1,i2| "#{i1[:cidrip]}" <=> "#{i2[:cidrip]}" }
          @item[:ec2_security_groups].sort!{ |i1,i2| "#{i1[:owner_id]}#{i1[:name]}" <=> "#{i2[:owner_id]}#{i2[:name]}" }
          @result[:db_security_groups] << @item
        end
      end
    end

    # --------------------------------------------
    #  DB Security Groups
    # --------------------------------------------

    class DescribeDbParameterGroupsParser < RightAWSParser # :nodoc:
      def reset
        @m = [ 'DBParameterGroup', 'CreateDBParameterGroupResult', 'ModifyDBParameterGroupResult' ]
        @result = { :db_parameter_groups => [] }
      end
      def tagstart(name, attributes)
        case name
          when *@m then @item = { }
        end
      end
      def tagend(name)
        case name
        when 'Marker'               then @result[:marker]       = @text
        when 'MaxRecords'           then @result[:max_records]  = @text.to_i
        when 'DBParameterGroupName' then @item[:name]        = @text
        when 'Description'          then @item[:description] = @text
        when 'Engine'               then @item[:engine]      = @text
        when *@m                    then @result[:db_parameter_groups] << @item
        end
      end
    end

    class DescribeDbParametersParser < RightAWSParser # :nodoc:
      def reset
        @result = { :parameters => [] }
      end
      def tagstart(name, attributes)
        case name
          when 'Parameter' then @item = {}
        end
      end
      def tagend(name)
        case name
        when 'Marker'               then @result[:marker]       = @text
        when 'MaxRecords'           then @result[:max_records]  = @text.to_i
        when 'DBParameterGroupName' then @result[:group_name]   = @text # DescribeDbParametersResponse
        when 'Engine'               then @result[:engine]       = @text # DescribeDBEngineDefaultParametersResponse
        when 'DataType'      then @item[:data_type]     = @text
        when 'Source'        then @item[:source]        = @text
        when 'Description'   then @item[:description]   = @text
        when 'IsModifiable'  then @item[:is_modifiable] = @text[/true/] ? true : false
        when 'ApplyType'     then @item[:apply_type]     = @text
        when 'AllowedValues' then @item[:allowed_values] = @text
        when 'ParameterName' then @item[:name]           = @text
        when 'ParameterValue' then @item[:value]         = @text
        when 'Parameter'     then @result[:parameters] << @item
        end
      end
    end

    # --------------------------------------------
    #  DB Snapshots
    # --------------------------------------------

    class DescribeDbSnapshotsParser < RightAWSParser # :nodoc:
      def reset
        @m = ['DBSnapshot', 'CreateDBSnapshotResult', 'DeleteDBSnapshotResult']
        @result = { :db_snapshots => [] }
      end
      def tagstart(name, attributes)
        case name
          when *@m
            @db_snapshot = {}
        end
      end
      def tagend(name)
        case name
        when 'Marker'               then @result[:marker]            = @text
        when 'MaxRecords'           then @result[:max_records]       = @text.to_i  # ?
        when 'Engine'               then @db_snapshot[:engine]               = @text
        when 'InstanceCreateTime'   then @db_snapshot[:instance_create_time] = @text
        when 'EndpointPort'         then @db_snapshot[:endpoint_port]        = @text.to_i
        when 'Status'               then @db_snapshot[:status]               = @text
        when 'AvailabilityZone'     then @db_snapshot[:availability_zone]    = @text
        when 'MasterUsername'       then @db_snapshot[:master_username]      = @text
        when 'AllocatedStorage'     then @db_snapshot[:allocated_storage]    = @text.to_i
        when 'SnapshotCreateTime'   then @db_snapshot[:create_time]          = @text
        when 'DBInstanceIdentifier' then @db_snapshot[:instance_aws_id]      = @text
        when 'DBSnapshotIdentifier' then @db_snapshot[:aws_id]               = @text
        when *@m                    then @result[:db_snapshots]               << @db_snapshot
        end
      end
    end

    # --------------------------------------------
    #  DB Events
    # --------------------------------------------

    class DescribeEventsParser < RightAWSParser # :nodoc:
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
        when 'MaxRecords'       then @result[:max_records]  = @text.to_i  # ?
        when 'Date'             then @event[:date]          = @text
        when 'SourceIdentifier' then @event[:aws_id]        = @text
        when 'SourceType'       then @event[:source_type]   = @text
        when 'Message'          then @event[:message]       = @text
        when 'Event'            then @result[:events]      << @event
        end
      end
    end

  end
end
