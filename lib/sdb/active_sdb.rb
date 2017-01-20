#
# Copyright (c) 2008 RightScale Inc
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

  # = RightAws::ActiveSdb -- RightScale SDB interface (alpha release)
  # The RightAws::ActiveSdb class provides a complete interface to Amazon's Simple
  # Database Service.
  # 
  # ActiveSdb is in alpha and does not load by default with the rest of RightAws.  You must use an additional require statement to load the ActiveSdb class.  For example:
  # 
  #   require 'right_aws'
  #   require 'sdb/active_sdb'
  #   
  # Simple ActiveSdb usage example:
  #
  #  class Client < RightAws::ActiveSdb::Base 
  #  end
  #  
  #  # connect to SDB
  #  RightAws::ActiveSdb.establish_connection
  #  
  #  # create domain
  #  Client.create_domain
  #  
  #  # create initial DB
  #  Client.create 'name' => 'Bush',     'country' => 'USA',    'gender' => 'male',   'expiration' => '2009', 'post' => 'president'
  #  Client.create 'name' => 'Putin',    'country' => 'Russia', 'gender' => 'male',   'expiration' => '2008', 'post' => 'president' 
  #  Client.create 'name' => 'Medvedev', 'country' => 'Russia', 'gender' => 'male',   'expiration' => '2012', 'post' => 'president'
  #  Client.create 'name' => 'Mary',     'country' => 'USA',    'gender' => 'female', 'hobby' => ['patchwork', 'bundle jumping']
  #  Client.create 'name' => 'Mary',     'country' => 'Russia', 'gender' => 'female', 'hobby' => ['flowers', 'cats', 'cooking']
  #  sandy_id = Client.create('name' => 'Sandy', 'country' => 'Russia', 'gender' => 'female', 'hobby' => ['flowers', 'cats', 'cooking']).id
  #  
  #  # find all Bushes in USA
  #  Client.find(:all, :conditions => ["['name'=?] intersection ['country'=?]",'Bush','USA']).each do |client|
  #    client.reload
  #    puts client.attributes.inspect
  #  end
  #  
  #  # find all Maries through the world
  #  Client.find_all_by_name_and_gender('Mary','female').each do |mary|
  #    mary.reload
  #    puts "#{mary[:name]}, gender: #{mary[:gender]}, hobbies: #{mary[:hobby].join(',')}"
  #  end
  #  
  #  # find new russian president
  #  medvedev = Client.find_by_post_and_country_and_expiration('president','Russia','2012')
  #  if medvedev
  #    medvedev.reload
  #    medvedev.save_attributes('age' => '42', 'hobby' => 'Gazprom')
  #  end
  #  
  #  # retire old president
  #  Client.find_by_name('Putin').delete
  #  
  #  # Sandy disappointed in 'cooking' and decided to hide her 'gender' and 'country' ()
  #  sandy = Client.find(sandy_id)
  #  sandy.reload
  #  sandy.delete_values('hobby' => ['cooking'] )
  #  sandy.delete_attributes('country', 'gender')
  #
  #  # remove domain
  #  Client.delete_domain
  #
  #  # Dynamic attribute accessors
  #
  #  class KdClient < RightAws::ActiveSdb::Base
  #  end
  #
  #  client = KdClient.select(:all, :order => 'expiration').first
  #    pp client.attributes #=>
  #      {"name"=>["Putin"],
  #       "post"=>["president"],
  #       "country"=>["Russia"],
  #       "expiration"=>["2008"],
  #       "id"=>"376d2e00-75b0-11dd-9557-001bfc466dd7",
  #       "gender"=>["male"]}
  #
  #    pp client.name    #=> ["Putin"]
  #    pp client.country #=> ["Russia"]
  #    pp client.post    #=> ["president"]
  #
  # # Columns and simple typecasting
  #
  #  class Person < RightAws::ActiveSdb::Base
  #    columns do
  #      name
  #      email
  #      score         :Integer
  #      is_active     :Boolean
  #      registered_at :DateTime
  #      created_at    :DateTime, :default => lambda{ Time.now }
  #    end
  #  end
  #  Person::create( :name => 'Yetta E. Andrews', :email => 'nulla.facilisis@metus.com', :score => 100, :is_active => true, :registered_at => Time.local(2000, 1, 1) )
  #
  #  person = Person.find_by_email 'nulla.facilisis@metus.com'
  #  person.reload
  #
  #  pp person.attributes #=>
  #    {"name"=>["Yetta E. Andrews"],
  #     "created_at"=>["2010-04-02T20:51:58+0400"],
  #     "id"=>"0ee24946-3e60-11df-9d4c-0025b37efad0",
  #     "registered_at"=>["2000-01-01T00:00:00+0300"],
  #     "is_active"=>["T"],
  #     "score"=>["100"],
  #     "email"=>["nulla.facilisis@metus.com"]}
  #  pp person.name                #=> "Yetta E. Andrews"
  #  pp person.name.class          #=> String
  #  pp person.registered_at.to_s  #=> "2000-01-01T00:00:00+03:00"
  #  pp person.registered_at.class #=> DateTime
  #  pp person.is_active           #=> true
  #  pp person.is_active.class     #=> TrueClass
  #  pp person.score               #=> 100
  #  pp person.score.class         #=> Fixnum
  #  pp person.created_at.to_s     #=> "2010-04-02T20:51:58+04:00"
  #
  class ActiveSdb
    
    module ActiveSdbConnect
      def connection
        @connection || raise(ActiveSdbError.new('Connection to SDB is not established'))
      end
      # Create a new handle to an Sdb account. All handles share the same per process or per thread
      # HTTP connection to Amazon Sdb. Each handle is for a specific account.
      # The +params+ are passed through as-is to RightAws::SdbInterface.new
      # Params:
      #    { :server       => 'sdb.amazonaws.com'  # Amazon service host: 'sdb.amazonaws.com'(default)
      #      :port         => 443                  # Amazon service port: 80 or 443(default)
      #      :protocol     => 'https'              # Amazon service protocol: 'http' or 'https'(default)
      #      :signature_version => '0'             # The signature version : '0' or '1'(default)
      #      :logger       => Logger Object        # Logger instance: logs to STDOUT if omitted 
      #      :nil_representation => 'mynil'}       # interpret Ruby nil as this string value; i.e. use this string in SDB to represent Ruby nils (default is the string 'nil')

      def establish_connection(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
        @connection = RightAws::SdbInterface.new(aws_access_key_id, aws_secret_access_key, params)
      end
    end
    
    class ActiveSdbError < RuntimeError ; end
    
    class << self
      include ActiveSdbConnect

      # Retreive a list of domains.
      #
      #  put RightAws::ActiveSdb.domains #=> ['co-workers','family','friends','clients']
      #
      def domains
        connection.list_domains[:domains]
      end

      # Create new domain. 
      # Raises no errors if the domain already exists.
      # 
      #  RightAws::ActiveSdb.create_domain('alpha')  #=> {:request_id=>"6fc652a0-0000-41d5-91f4-3ed390a3d3b2", :box_usage=>"0.0055590278"}
      #
      def create_domain(domain_name)
        connection.create_domain(domain_name)
      end

      # Remove domain from SDB. 
      # Raises no errors if the domain does not exist.
      # 
      #  RightAws::ActiveSdb.create_domain('alpha')  #=> {:request_id=>"6fc652a0-0000-41c6-91f4-3ed390a3d3b2", :box_usage=>"0.0055590001"}
      #
      def delete_domain(domain_name)
        connection.delete_domain(domain_name)
      end
    end
    
    class Base
      
      class << self
        include ActiveSdbConnect
        
        # next_token value returned by last find: is useful to continue finding
        attr_accessor :next_token
      
        # Returns a RightAws::SdbInterface object
        #
        #  class A < RightAws::ActiveSdb::Base
        #  end
        #  
        #  class B < RightAws::ActiveSdb::Base
        #  end
        #  
        #  class C < RightAws::ActiveSdb::Base
        #  end
        #
        #  RightAws::ActiveSdb.establish_connection 'key_id_1', 'secret_key_1'
        #  
        #  C.establish_connection 'key_id_2', 'secret_key_2'
        #
        #  # A and B uses the default connection, C - uses its own 
        #  puts A.connection  #=> #<RightAws::SdbInterface:0xb76d6d7c>
        #  puts B.connection  #=> #<RightAws::SdbInterface:0xb76d6d7c>
        #  puts C.connection  #=> #<RightAws::SdbInterface:0xb76d6ca0>
        #
        def connection
          @connection || ActiveSdb::connection
        end

        @domain = nil

        # Current domain name.
        #
        #  # if 'ActiveSupport' is not loaded then class name converted to downcase
        #  class Client < RightAws::ActiveSdb::Base
        #  end
        #  puts Client.domain  #=> 'client'
        #  
        #  # if 'ActiveSupport' is loaded then class name being tableized
        #  require 'activesupport'
        #  class Client < RightAws::ActiveSdb::Base
        #  end
        #  puts Client.domain  #=> 'clients'
        #
        #  # Explicit domain name definition
        #  class Client < RightAws::ActiveSdb::Base
        #    set_domain_name :foreign_clients
        #  end
        #  puts Client.domain  #=> 'foreign_clients'
        #
        def domain
          unless @domain
            if defined? ActiveSupport::CoreExtensions::String::Inflections
              @domain = name.tableize
            else
              @domain = name.downcase
            end
          end
          @domain
        end

        # Change the default domain name to user defined.
        # 
        #  class Client < RightAws::ActiveSdb::Base
        #    set_domain_name :foreign_clients
        #  end
        #
        def set_domain_name(domain)
          @domain = domain.to_s
        end

        # Create domain at SDB.
        # Raises no errors if the domain already exists.
        # 
        #  class Client < RightAws::ActiveSdb::Base
        #  end
        #  Client.create_domain  #=> {:request_id=>"6fc652a0-0000-41d5-91f4-3ed390a3d3b2", :box_usage=>"0.0055590278"}
        #
        def create_domain
          connection.create_domain(domain)
        end

        # Remove domain from SDB.
        # Raises no errors if the domain does not exist.
        # 
        #  class Client < RightAws::ActiveSdb::Base
        #  end
        #  Client.delete_domain  #=> {:request_id=>"e14d90d3-0000-4898-9995-0de28cdda270", :box_usage=>"0.0055590278"}
        #
        def delete_domain
          connection.delete_domain(domain)
        end

        def columns(&block)
          @columns ||= ColumnSet.new
          @columns.instance_eval(&block) if block
          @columns
        end

        def column?(col_name)
          columns.include?(col_name)
        end

        def type_of(col_name)
          columns.type_of(col_name)
        end

        def serialize(attribute, value)
          s = serialization_for_type(type_of(attribute))
          s ? s.serialize(value) : value.to_s
        end

        def deserialize(attribute, value)
          s = serialization_for_type(type_of(attribute))
          s ? s.deserialize(value) : value
        end

        # Perform a find request.
        #  
        # Single record: 
        # 
        #  Client.find(:first)
        #  Client.find(:first, :conditions=> [ "['name'=?] intersection ['wife'=?]", "Jon", "Sandy"])
        #  
        # Bunch of records: 
        # 
        #  Client.find(:all)
        #  Client.find(:all, :limit => 10)
        #  Client.find(:all, :conditions=> [ "['name'=?] intersection ['girlfriend'=?]", "Jon", "Judy"])
        #  Client.find(:all, :conditions=> [ "['name'=?]", "Sandy"], :limit => 3)
        #  
        # Records by ids:
        # 
        #  Client.find('1')
        #  Client.find('1234987b4583475347523948')
        #  Client.find('1','2','3','4', :conditions=> [ "['toys'=?]", "beer"])
        #
        # Find helpers: RightAws::ActiveSdb::Base.find_by_... and RightAws::ActiveSdb::Base.find_all_by_...
        # 
        #  Client.find_by_name('Matias Rust')
        #  Client.find_by_name_and_city('Putin','Moscow')
        #  Client.find_by_name_and_city_and_post('Medvedev','Moscow','president')
        #
        #  Client.find_all_by_author('G.Bush jr')
        #  Client.find_all_by_age_and_gender_and_ethnicity('34','male','russian')
        #  Client.find_all_by_gender_and_country('male', 'Russia', :auto_load => true, :order => 'name desc')
        #
        # Returned records have to be +reloaded+ to access their attributes.
        # 
        #  item = Client.find_by_name('Cat')  #=> #<Client:0xb77d0d40 @attributes={"id"=>"2937601a-e45d-11dc-a75f-001bfc466dd7"}, @new_record=false>
        #  item.reload                        #=> #<Client:0xb77d0d40 @attributes={"id"=>"2937601a-e45d-11dc-a75f-001bfc466dd7", "name"=>["Cat"], "toys"=>["Jons socks", "clew", "mice"]}, @new_record=false>
        #
        # Continue listing:
        #  # initial listing
        #  Client.find(:all, :limit => 10)
        #  # continue listing
        #  begin
        #    Client.find(:all, :limit => 10, :next_token => Client.next_token)
        #  end while Client.next_token
        #
        #  Sort oder:
        #    Client.find(:all, :order => 'gender')
        #    Client.find(:all, :order => 'name desc')
        #
        #  Attributes auto load (be carefull - this may take lot of time for a huge bunch of records):
        #    Client.find(:first)                      #=> #<Client:0xb77d0d40 @attributes={"id"=>"2937601a-e45d-11dc-a75f-001bfc466dd7"}, @new_record=false>
        #    Client.find(:first, :auto_load => true)  #=> #<Client:0xb77d0d40 @attributes={"id"=>"2937601a-e45d-11dc-a75f-001bfc466dd7", "name"=>["Cat"], "toys"=>["Jons socks", "clew", "mice"]}, @new_record=false>
        #
        # see http://docs.amazonwebservices.com/AmazonSimpleDB/2007-11-07/DeveloperGuide/index.html?UsingQuery.html
        #
        def find(*args)
          options = args.last.is_a?(Hash) ? args.pop : {}
          case args.first
            when :all   then find_every    options
            when :first then find_initial  options
            else             find_from_ids args, options
          end
        end

        # Perform a SQL-like select request.
        #
        # Single record:
        #
        #  Client.select(:first)
        #  Client.select(:first, :conditions=> [ "name=? AND wife=?", "Jon", "Sandy"])
        #  Client.select(:first, :conditions=> { :name=>"Jon", :wife=>"Sandy" }, :select => :girfriends)
        #
        # Bunch of records:
        #
        #  Client.select(:all)
        #  Client.select(:all, :limit => 10)
        #  Client.select(:all, :conditions=> [ "name=? AND 'girlfriend'=?", "Jon", "Judy"])
        #  Client.select(:all, :conditions=> { :name=>"Sandy" }, :limit => 3)
        #
        # Records by ids:
        #
        #  Client.select('1')
        #  Client.select('1234987b4583475347523948')
        #  Client.select('1','2','3','4', :conditions=> ["toys=?", "beer"])
        #
        # Find helpers: RightAws::ActiveSdb::Base.select_by_... and RightAws::ActiveSdb::Base.select_all_by_...
        #
        #  Client.select_by_name('Matias Rust')
        #  Client.select_by_name_and_city('Putin','Moscow')
        #  Client.select_by_name_and_city_and_post('Medvedev','Moscow','president')
        #
        #  Client.select_all_by_author('G.Bush jr')
        #  Client.select_all_by_age_and_gender_and_ethnicity('34','male','russian')
        #  Client.select_all_by_gender_and_country('male', 'Russia', :order => 'name')
        #
        # Continue listing:
        #
        #  # initial listing
        #  Client.select(:all, :limit => 10)
        #  # continue listing
        #  begin
        #    Client.select(:all, :limit => 10, :next_token => Client.next_token)
        #  end while Client.next_token
        #
        #  Sort oder:
        #  If :order=>'attribute' option is specified then result response (ordered by 'attribute') will contain only items where attribute is defined (is not null).
        #  
        #    Client.select(:all)                         # returns all records
        #    Client.select(:all, :order => 'gender')     # returns all records ordered by gender where gender attribute exists
        #    Client.select(:all, :order => 'name desc')  # returns all records ordered by name in desc order where name attribute exists
        #
        # see http://docs.amazonwebservices.com/AmazonSimpleDB/2007-11-07/DeveloperGuide/index.html?UsingSelect.html
        #
        def select(*args)
          Rails.logger.info("SELECT: args are #{args}");
          options = args.last.is_a?(Hash) ? args.pop : {}
          case args.first
            when :all   then sql_select(options)
            when :first then sql_select(options.merge(:limit => 1)).first
            else             select_from_ids args, options
          end
        end

        def generate_id # :nodoc:
          AwsUtils::generate_unique_token
        end

      protected

        # Select

        def select_from_ids(args, options) # :nodoc:
          cond = []
          # detect amount of records requested
          bunch_of_records_requested = args.size > 1 || args.first.is_a?(Array)
          # flatten ids
          args = Array(args).flatten
          args.each { |id| cond << "id=#{self.connection.escape(id)}" }
          ids_cond = "(#{cond.join(' OR ')})"
          # user defined :conditions to string (if it was defined)
          options[:conditions] = build_conditions(options[:conditions])
          # join ids condition and user defined conditions
          options[:conditions] = options[:conditions].right_blank? ? ids_cond : "(#{options[:conditions]}) AND #{ids_cond}"
          result = sql_select(options)
          # if one record was requested then return it
          unless bunch_of_records_requested
            record = result.first
            # railse if nothing was found
            raise ActiveSdbError.new("Couldn't find #{name} with ID #{args}") unless record
            record
          else
            # if a bunch of records was requested then return check that we found all of them
            # and return as an array
            unless args.size == result.size
              id_list = args.map{|i| "'#{i}'"}.join(',')
              raise ActiveSdbError.new("Couldn't find all #{name} with IDs (#{id_list}) (found #{result.size} results, but was looking for #{args.size})")
            else
              result
            end
          end
        end

        def sql_select(options) # :nodoc:
          @next_token = options[:next_token]
          select_expression = build_select(options)
          Rails.logger.info("SQL_SELECT: Select Expression #{select_expression}")
          # request items
          query_result = self.connection.select(select_expression, @next_token)
          Rails.logger.info("SQL_SELECT: query_result is #{query_result}")

          @next_token = query_result[:next_token]
          items = query_result[:items].map do |hash|
            id, attributes = hash.shift
            new_item = self.new( attributes.merge({ 'id' => id }))
            new_item.mark_as_old
            new_item
          end
          items
        end

        # select_by helpers
        def select_all_by_(format_str, args, options) # :nodoc:
          fields = format_str.to_s.sub(/^select_(all_)?by_/,'').split('_and_')
          conditions = fields.map { |field| "#{field}=?" }.join(' AND ')
          options[:conditions] = [conditions, *args]
          select(:all, options)
        end

        def select_by_(format_str, args, options) # :nodoc:
          options[:limit] = 1
          select_all_by_(format_str, args, options).first
        end

        # Query

        # Returns an array of query attributes.
        # Query_expression must be a well formated SDB query string:
        # query_attributes("['title' starts-with 'O\\'Reily'] intersection ['year' = '2007']") #=> ["title", "year"]
        def query_attributes(query_expression) # :nodoc:
          attrs = []
          array = query_expression.scan(/['"](.*?[^\\])['"]/).flatten
          until array.empty? do
            attrs << array.shift # skip it's value
            array.shift #
          end
          attrs
        end

        # Returns an array of [attribute_name, 'asc'|'desc']
        def sort_options(sort_string)
          sort_string[/['"]?(\w+)['"]? *(asc|desc)?/i]
          [$1, ($2 || 'asc')]
        end

        # Perform a query request.
        #
        # Options
        #  :query_expression     nil | string | array
        #  :max_number_of_items  nil | integer
        #  :next_token           nil | string
        #  :sort_option          nil | string    "name desc|asc"
        #
        def query(options) # :nodoc:
          @next_token = options[:next_token]
          query_expression = build_conditions(options[:query_expression])
          # add sort_options to the query_expression
          if options[:sort_option]
            sort_by, sort_order = sort_options(options[:sort_option])
            sort_query_expression = "['#{sort_by}' starts-with '']"
            sort_by_expression    = " sort '#{sort_by}' #{sort_order}"
            # make query_expression to be a string (it may be null)
            query_expression = query_expression.to_s
            # quote from Amazon:
            # The sort attribute must be present in at least one of the predicates of the query expression.
            if query_expression.right_blank?
              query_expression = sort_query_expression
            elsif !query_attributes(query_expression).include?(sort_by)
              query_expression += " intersection #{sort_query_expression}"
            end
            query_expression += sort_by_expression
          end
          # request items
          query_result = self.connection.query(domain, query_expression, options[:max_number_of_items], @next_token)
          @next_token = query_result[:next_token]
          items = query_result[:items].map do |name| 
            new_item = self.new('id' => name)
            new_item.mark_as_old
            reload_if_exists(record) if options[:auto_load]
            new_item
          end
          items
        end

        # reload a record unless it is nil
        def reload_if_exists(record) # :nodoc:
          record && record.reload
        end

        def reload_all_records(*list) # :nodoc:
          list.flatten.each { |record| reload_if_exists(record) }
        end

        def find_every(options) # :nodoc:
          records = query( :query_expression    => options[:conditions],
                           :max_number_of_items => options[:limit],
                           :next_token          => options[:next_token],
                           :sort_option         => options[:sort] || options[:order] )
          options[:auto_load] ? reload_all_records(records) : records
        end

        def find_initial(options) # :nodoc:
          options[:limit] = 1
          record = find_every(options).first
          options[:auto_load] ? reload_all_records(record).first : record
        end

        def find_from_ids(args, options) # :nodoc:
          cond = []
          # detect amount of records requested
          bunch_of_records_requested = args.size > 1 || args.first.is_a?(Array)
          # flatten ids
          args = Array(args).flatten
          args.each { |id| cond << "'id'=#{self.connection.escape(id)}" }
          ids_cond = "[#{cond.join(' OR ')}]"
          # user defined :conditions to string (if it was defined)
          options[:conditions] = build_conditions(options[:conditions])
          # join ids condition and user defined conditions
          options[:conditions] = options[:conditions].right_blank? ? ids_cond : "#{options[:conditions]} intersection #{ids_cond}"
          result = find_every(options)
          # if one record was requested then return it
          unless bunch_of_records_requested
            record = result.first
            # railse if nothing was found
            raise ActiveSdbError.new("Couldn't find #{name} with ID #{args}") unless record
            options[:auto_load] ? reload_all_records(record).first : record
          else
            # if a bunch of records was requested then return check that we found all of them
            # and return as an array
            unless args.size == result.size
              id_list = args.map{|i| "'#{i}'"}.join(',')
              raise ActiveSdbError.new("Couldn't find all #{name} with IDs (#{id_list}) (found #{result.size} results, but was looking for #{args.size})")
            else
              options[:auto_load] ? reload_all_records(result) : result
            end
          end
        end

        # find_by helpers 
        def find_all_by_(format_str, args, options) # :nodoc:
          fields = format_str.to_s.sub(/^find_(all_)?by_/,'').split('_and_')
          conditions = fields.map { |field| "['#{field}'=?]" }.join(' intersection ')
          options[:conditions] = [conditions, *args]
          find(:all, options)
        end

        def find_by_(format_str, args, options) # :nodoc:
          options[:limit] = 1
          find_all_by_(format_str, args, options).first
        end

        # Misc

        def method_missing(method, *args) # :nodoc:
          if method.to_s[/^(find_all_by_|find_by_|select_all_by_|select_by_)/]
            options = args.last.is_a?(Hash) ? args.pop : {}
            __send__($1, method, args, options)
          else
            super(method, *args)
          end
        end

        def build_select(options) # :nodoc:
          select     = options[:select]    || '*'
          from       = options[:from]      || domain
          conditions = options[:conditions] ? " WHERE #{build_conditions(options[:conditions])}" : ''
          order      = options[:order]      ? " ORDER BY #{options[:order]}"                     : ''
          limit      = options[:limit]      ? " LIMIT #{options[:limit]}"                        : ''
          # mix sort by argument (it must present in response)
          unless order.right_blank?
            sort_by, sort_order = sort_options(options[:order])
            conditions << (conditions.right_blank? ? " WHERE " : " AND ") << "(#{sort_by} IS NOT NULL)"
          end
          "SELECT #{select} FROM #{from}#{conditions}#{order}#{limit}"
        end

        def build_conditions(conditions) # :nodoc:
          case
          when conditions.is_a?(Array) then connection.query_expression_from_array(conditions)
          when conditions.is_a?(Hash)  then connection.query_expression_from_hash(conditions)
          else                              conditions
          end
        end

        def serialization_for_type(type)
          @serializations ||= {}
          unless @serializations.has_key? type
            @serializations[type] = ::RightAws::ActiveSdb.const_get("#{type}Serialization") rescue false
          end
          @serializations[type]
        end
      end
      
      public

      # instance attributes
      attr_accessor :attributes 
      
      # item name
      attr_accessor :id

      # Create new Item instance.
      # +attrs+ is a hash: { attribute1 => values1, ..., attributeN => valuesN }.
      #
      #  item = Client.new('name' => 'Jon', 'toys' => ['girls', 'beer', 'pub'])
      #  puts item.inspect   #=> #<Client:0xb77a2698 @new_record=true, @attributes={"name"=>["Jon"], "toys"=>["girls", "beer", "pub"]}>
      #  item.save           #=> {"name"=>["Jon"], "id"=>"c03edb7e-e45c-11dc-bede-001bfc466dd7", "toys"=>["girls", "beer", "pub"]}
      #  puts item.inspect   #=> #<Client:0xb77a2698 @new_record=false, @attributes={"name"=>["Jon"], "id"=>"c03edb7e-e45c-11dc-bede-001bfc466dd7", "toys"=>["girls", "beer", "pub"]}>
      #  
      def initialize(attrs={})
        @attributes = uniq_values(attrs)
        @new_record = true
      end

      # Create and save new Item instance.
      # +Attributes+ is a hash: { attribute1 => values1, ..., attributeN => valuesN }.
      #
      #  item = Client.create('name' => 'Cat', 'toys' => ['Jons socks', 'mice', 'clew']) 
      #  puts item.inspect   #=> #<Client:0xb77a0a78 @new_record=false, @attributes={"name"=>["Cat"], "id"=>"2937601a-e45d-11dc-a75f-001bfc466dd7", "toys"=>["Jons socks", "mice", "clew"]}>
      #  
      def self.create(attributes={})
        item = self.new(attributes)
        item.save
        item
      end
      
      # Returns an item id. Same as: item['id'] or item.attributes['id']
      def id
        @attributes['id']
      end
      
      # Sets an item id.
      def id=(id)
        @attributes['id'] = id.to_s
      end

      # Returns a hash of all the attributes.
      #
      #  puts item.attributes.inspect #=> {"name"=>["Cat"], "id"=>"2937601a-e45d-11dc-a75f-001bfc466dd7", "toys"=>["Jons socks", "clew", "mice"]}
      #
      def attributes
        @attributes.dup
      end
      
      # Allows one to set all the attributes at once by passing in a hash with keys matching the attribute names.
      # if '+id+' attribute is not set in new attributes has then it being derived from old attributes.
      #
      #  puts item.attributes.inspect   #=> {"name"=>["Cat"], "id"=>"2937601a-e45d-11dc-a75f-001bfc466dd7", "toys"=>["Jons socks", "clew", "mice"]}
      #  # set new attributes ('id' is missed)
      #  item.attributes = { 'name'=>'Dog', 'toys'=>['bones','cats'] }
      #  puts item.attributes.inspect   #=> {"name"=>["Dog"], "id"=>"2937601a-e45d-11dc-a75f-001bfc466dd7", "toys"=>["bones", "cats"]}
      #  # set new attributes ('id' is set)
      #  item.attributes = { 'id' => 'blah-blah', 'name'=>'Birds', 'toys'=>['seeds','dogs tail'] }
      #  puts item.attributes.inspect   #=> {"name"=>["Birds"], "id"=>"blah-blah", "toys"=>["seeds", "dogs tail"]}
      #
      def attributes=(attrs)
        old_id = @attributes['id']
        @attributes = uniq_values(attrs)
        @attributes['id'] = old_id if @attributes['id'].right_blank? && !old_id.right_blank?
        self.attributes
      end

      def columns
        self.class.columns
      end

      def connection
        self.class.connection
      end

      # Item domain name.
      def domain
        self.class.domain
      end
      
      # Returns the values of the attribute identified by +attribute+.
      # 
      #  puts item['Cat'].inspect  #=> ["Jons socks", "clew", "mice"]
      #
      def [](attribute)
        raw = @attributes[attribute.to_s]
        self.class.column?(attribute) && raw ? self.class.deserialize(attribute, raw.first) : raw
      end

      # Updates the attribute identified by +attribute+ with the specified +values+.
      # 
      #  puts item['Cat'].inspect  #=> ["Jons socks", "clew", "mice"]
      #  item['Cat'] = ["Whiskas", "chicken"]
      #  puts item['Cat'].inspect  #=> ["Whiskas", "chicken"]
      #
      def []=(attribute, values)
        attribute = attribute.to_s
        @attributes[attribute] = case
        when attribute == 'id'
          values.to_s
        when self.class.column?(attribute)
          self.class.serialize(attribute, values)
        else
          Array(values).uniq
        end
      end

      # Reload attributes from SDB. Replaces in-memory attributes.
      # 
      #  item = Client.find_by_name('Cat')  #=> #<Client:0xb77d0d40 @attributes={"id"=>"2937601a-e45d-11dc-a75f-001bfc466dd7"}, @new_record=false>
      #  item.reload                        #=> #<Client:0xb77d0d40 @attributes={"id"=>"2937601a-e45d-11dc-a75f-001bfc466dd7", "name"=>["Cat"], "toys"=>["Jons socks", "clew", "mice"]}, @new_record=false>
      #  
      def reload
        raise_on_id_absence
        old_id = id
        attrs = connection.get_attributes(domain, id)[:attributes]
        @attributes = {}
        unless attrs.right_blank?
          attrs.each { |attribute, values| @attributes[attribute] = values }
          @attributes['id'] = old_id
        end
        mark_as_old
        @attributes
      end

      # Reload a set of attributes from SDB. Adds the loaded list to in-memory data.
      # +attrs_list+ is an array or comma separated list of attributes names.
      # Returns a hash of loaded attributes.
      # 
      # This is not the best method to get a bunch of attributes because
      # a web service call is being performed for every attribute.
      # 
      #  item = Client.find_by_name('Cat')
      #  item.reload_attributes('toys', 'name')   #=> {"name"=>["Cat"], "toys"=>["Jons socks", "clew", "mice"]}
      #
      def reload_attributes(*attrs_list)
        raise_on_id_absence
        attrs_list = attrs_list.flatten.map{ |attribute| attribute.to_s }
        attrs_list.delete('id')
        result = {}
        attrs_list.flatten.uniq.each do |attribute|
          attribute = attribute.to_s
          values = connection.get_attributes(domain, id, attribute)[:attributes][attribute]
          unless values.right_blank?
            @attributes[attribute] = result[attribute] = values
          else
            @attributes.delete(attribute)
          end
        end
        mark_as_old
        result
      end

      # Stores in-memory attributes to SDB.
      # Adds the attributes values to already stored at SDB.
      # Returns a hash of stored attributes. 
      #
      #  sandy = Client.new(:name => 'Sandy') #=> #<Client:0xb775a7a8 @attributes={"name"=>["Sandy"]}, @new_record=true>
      #  sandy['toys'] = 'boys'
      #  sandy.put
      #  sandy['toys'] = 'patchwork'
      #  sandy.put
      #  sandy['toys'] = 'kids'
      #  sandy.put
      #  puts sandy.attributes.inspect        #=> {"name"=>["Sandy"], "id"=>"b2832ce2-e461-11dc-b13c-001bfc466dd7", "toys"=>["kids"]}
      #  sandy.reload                         #=> {"name"=>["Sandy"], "id"=>"b2832ce2-e461-11dc-b13c-001bfc466dd7", "toys"=>["boys", "kids", "patchwork"]}
      #
      # compare to +save+ method
      def put
        @attributes = uniq_values(@attributes)
        prepare_for_update
        attrs = @attributes.dup
        attrs.delete('id')
        connection.put_attributes(domain, id, attrs) unless attrs.right_blank?
        connection.put_attributes(domain, id, { 'id' => id }, :replace)
        mark_as_old
        @attributes
      end

      # Stores specified attributes.
      # +attrs+ is a hash: { attribute1 => values1, ..., attributeN => valuesN }.
      # Returns a hash of saved attributes.
      #
      # see to +put+ method
      def put_attributes(attrs)
        attrs = uniq_values(attrs)
        prepare_for_update
        # if 'id' is present in attrs hash:
        # replace internal 'id' attribute and remove it from the attributes to be sent
        @attributes['id'] = attrs['id'] unless attrs['id'].right_blank?
        attrs.delete('id')
        # add new values to all attributes from list
        connection.put_attributes(domain, id, attrs) unless attrs.right_blank?
        connection.put_attributes(domain, id, { 'id' => id }, :replace)
        attrs.each do |attribute, values|
          @attributes[attribute] ||= []
          @attributes[attribute] += values
          @attributes[attribute].uniq!
        end
        mark_as_old
        attributes
      end

      # Store in-memory attributes to SDB.
      # Replaces the attributes values already stored at SDB by in-memory data.
      # Returns a hash of stored attributes. 
      # 
      #  sandy = Client.new(:name => 'Sandy')  #=> #<Client:0xb775a7a8 @attributes={"name"=>["Sandy"]}, @new_record=true>
      #  sandy['toys'] = 'boys'
      #  sandy.put
      #  sandy['toys'] = 'patchwork'
      #  sandy.put
      #  sandy['toys'] = 'kids'
      #  sandy.put
      #  puts sandy.attributes.inspect         #=> {"name"=>["Sandy"], "id"=>"b2832ce2-e461-11dc-b13c-001bfc466dd7", "toys"=>["kids"]}
      #  sandy.reload                          #=> {"name"=>["Sandy"], "id"=>"b2832ce2-e461-11dc-b13c-001bfc466dd7", "toys"=>["kids"]}
      #
      # compare to +put+ method
      def save
        @attributes = uniq_values(@attributes)
        prepare_for_update
        connection.put_attributes(domain, id, @attributes, :replace)
        mark_as_old
        @attributes
      end

      # Replaces the attributes at SDB by the given values.
      # +Attrs+ is a hash: { attribute1 => values1, ..., attributeN => valuesN }.
      # The other in-memory attributes are not being saved.
      # Returns a hash of stored attributes.
      #
      # see +save+ method
      def save_attributes(attrs)
        prepare_for_update
        attrs = uniq_values(attrs)
        # if 'id' is present in attrs hash then replace internal 'id' attribute
        unless attrs['id'].right_blank?
          @attributes['id'] = attrs['id']
        else
          attrs['id'] = id
        end
        connection.put_attributes(domain, id, attrs, :replace) unless attrs.right_blank?
        attrs.each { |attribute, values| attrs[attribute] = values }
        mark_as_old
        attrs
      end

      # Remove specified values from corresponding attributes.
      # +attrs+ is a hash: { attribute1 => values1, ..., attributeN => valuesN }.
      #
      #  sandy = Client.find_by_name 'Sandy' 
      #  sandy.reload
      #  puts sandy.inspect                                #=> #<Client:0xb77b48fc @new_record=false, @attributes={"name"=>["Sandy"], "id"=>"b2832ce2-e461-11dc-b13c-001bfc466dd7", "toys"=>["boys", "kids", "patchwork"]}>
      #  puts sandy.delete_values('toys' => 'patchwork')   #=> { 'toys' => ['patchwork'] }
      #  puts sandy.inspect                                #=> #<Client:0xb77b48fc @new_record=false, @attributes={"name"=>["Sandy"], "id"=>"b2832ce2-e461-11dc-b13c-001bfc466dd7", "toys"=>["boys", "kids"]}>
      #
      def delete_values(attrs)
        raise_on_id_absence
        attrs = uniq_values(attrs)
        attrs.delete('id')
        unless attrs.right_blank?
          connection.delete_attributes(domain, id, attrs)
          attrs.each do |attribute, values|
            # remove the values from the attribute
            if @attributes[attribute]
              @attributes[attribute] -= values
            else
              # if the attribute is unknown remove it from a resulting list of fixed attributes
              attrs.delete(attribute)
            end
          end
        end
        attrs
      end

      # Removes specified attributes from the item.
      # +attrs_list+ is an array or comma separated list of attributes names.
      # Returns the list of deleted attributes.
      # 
      #  sandy = Client.find_by_name 'Sandy' 
      #  sandy.reload
      #  puts sandy.inspect                   #=> #<Client:0xb7761d28 @new_record=false, @attributes={"name"=>["Sandy"], "id"=>"b2832ce2-e461-11dc-b13c-001bfc466dd7", "toys"=>["boys", "kids", "patchwork"}>
      #  puts sandy.delete_attributes('toys') #=> ['toys']
      #  puts sandy.inspect                   #=> #<Client:0xb7761d28 @new_record=false, @attributes={"name"=>["Sandy"], "id"=>"b2832ce2-e461-11dc-b13c-001bfc466dd7"}>
      #
      def delete_attributes(*attrs_list)
        raise_on_id_absence
        attrs_list = attrs_list.flatten.map{ |attribute| attribute.to_s }
        attrs_list.delete('id')
        unless attrs_list.right_blank?
          connection.delete_attributes(domain, id, attrs_list)
          attrs_list.each { |attribute| @attributes.delete(attribute) }
        end
        attrs_list
      end

      # Delete the Item entirely from SDB.
      # 
      #  sandy = Client.find_by_name 'Sandy' 
      #  sandy.reload
      #  sandy.inspect       #=> #<Client:0xb7761d28 @new_record=false, @attributes={"name"=>["Sandy"], "id"=>"b2832ce2-e461-11dc-b13c-001bfc466dd7", "toys"=>["boys", "kids", "patchwork"}>
      #  puts sandy.delete
      #  sandy.reload      
      #  puts sandy.inspect  #=> #<Client:0xb7761d28 @attributes={}, @new_record=false>
      # 
      def delete
        raise_on_id_absence
        connection.delete_attributes(domain, id)
      end

      # Item ID
      def to_s
        @id
      end

      # Returns true if this object hasn‘t been saved yet.      
      def new_record?
        @new_record
      end

      def mark_as_old  # :nodoc:
        @new_record = false
      end

      # support accessing attribute values via method call
      def method_missing(method_sym, *args)
        method_name = method_sym.to_s
        setter = method_name[-1,1] == '='
        method_name.chop! if setter

        if @attributes.has_key?(method_name) || self.class.column?(method_name)
          setter ? self[method_name] = args.first : self[method_name]
        else
          super
        end
      end

    private

      def raise_on_id_absence
        raise ActiveSdbError.new('Unknown record id') unless id
      end
      
      def prepare_for_update
        @attributes['id'] = self.class.generate_id if @attributes['id'].right_blank?
        columns.all.each do |col_name|
          self[col_name] ||= columns.default(col_name)
        end
      end
      
      def uniq_values(attributes=nil) # :nodoc:
        attrs = {}
        attributes.each do |attribute, values|
          attribute = attribute.to_s
          attrs[attribute] = case
          when attribute == 'id'
            values.to_s
          when self.class.column?(attribute)
            values.is_a?(String) ? values : self.class.serialize(attribute, values)
          else
            Array(values).uniq
          end
          attrs.delete(attribute) if values.right_blank?
        end
        attrs
      end
    end

    class ColumnSet
      attr_accessor :columns
      def initialize
        @columns = {}
      end

      def all
        @columns.keys
      end

      def column(col_name)
        @columns[col_name.to_s]
      end
      alias_method :include?, :column

      def type_of(col_name)
        column(col_name) && column(col_name)[:type]
      end

      def default(col_name)
        return nil unless include?(col_name)
        default = column(col_name)[:default]
        default.respond_to?(:call) ? default.call : default
      end

      def method_missing(method_sym, *args)
        data_type = args.shift || :String
        options = args.shift || {}
        @columns[method_sym.to_s] = options.merge( :type => data_type )
      end
    end

    class DateTimeSerialization
      class << self
        def serialize(date)
          date.strftime('%Y-%m-%dT%H:%M:%S%z')
        end

        def deserialize(string)
          r = DateTime.parse(string) rescue nil
        end
      end
    end

    class BooleanSerialization
      class << self
        def serialize(boolean)
          boolean ? 'T' : 'F'
        end

        def deserialize(string)
          string == 'T'
        end
      end
    end

    class IntegerSerialization
      class << self
        def serialize(int)
          int.to_s
        end

        def deserialize(string)
          string.to_i
        end
      end
    end

  end
end
