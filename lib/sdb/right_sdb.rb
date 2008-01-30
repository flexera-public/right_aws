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
  
  
  class Sdb
    
    attr_reader :interface
    
    # Create a new handle to an Sdb account. All handles share the same per process or per thread
    # HTTP connection to Amazon Sdb. Each handle is for a specific account.
    # The +params+ are passed through as-is to RightAws::SdbInterface.new
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      @interface = SdbInterface.new(aws_access_key_id, aws_secret_access_key, params)
    end
    
    # Retrieve a list of domains.
    # Returns an array of +Domain+ instances.
    # 
    #  sdb = RightAws::Sdb.new
    #  puts sdb.domains #=> 'family \n friends'
    # 
    #  # list domains by 10
    #  sdb.domains(10) do |domains|
    #    puts domains #=> 'family \n friends'
    #    true         # block must return true (or any other not a 'nil/false' value) to continue listing !
    #  end
    #
    def domains(max_number_of_domains=nil, next_token=nil, &block)
      domains = []
      # request domains list
      begin
        query_result = @interface.list_domains(max_number_of_domains, next_token)
        new_domains  = query_result[:domains].map { |name| Domain.new(self, name, false)}
        domains     += new_domains
        next_token   = query_result[:next_token]
        break unless block && block.call(new_domains) && next_token
      end while true
      domains
    end

    
    class Domain
      attr_reader :sdb
      attr_reader :name
      
      # Create a new Domain instance.
      # 
      # Creates a domain at SDB if +create+ param is set.
      # 
      #  sdb = RightAws::Sdb.new
      #  puts sdb.domains                                         #=> 'family \n friends'
      #  domain1 = RightAws::Sdb::Domain.new(sdb, 'co-workers')   #=> #<RightAws::Sdb::Domain:0xb7795984 ...
      #  puts sdb.domains                                         #=> 'family \n friends \n co-workers'
      #  # skip domain creation at Amazon
      #  domain2 = RightAws::Sdb::Domain.new(sdb, 'girls', false) #=> #<RightAws::Sdb::Domain:0xb7900984 ...
      #  puts sdb.domains                                         #=> 'family \n friends \n co-workers'
      # 
      def initialize(sdb, name, create=true)
        @sdb  = sdb
        @name = name
        @sdb.interface.create_domain(@name) if create
      end

      def to_s
        @name
      end
      
      # Create new Item instance. 
      # 
      # Creates new item with a set of passed attributes or retrieves this attributes
      # from SDB if +attributes+ == :reload.
      # 
      # see Item#new for +attributes+ description and Item#reload warning.
      # 
      #  sdb = RightAws::Sdb.new
      #  # get domain 'family'
      #  domain = sdb.domains.find{|d| d.name == 'family' }
      #  
      #  # create new attribute in memory ...
      #  new_item1 = domain.item('food', {:dog => ['bones', 'meat'], :cat => ['mice', 'birds']})
      #  puts domain.query  #=> ''
      #  # ... and store them at SDB
      #  new_item1.put
      #  puts domain.query  #=> 'food'
      #  
      #  # create new attribute in memory and store them at SDB
      #  new_item2 = domain.item('house', {:dog => ['box'], :cat => ['basket']}, :replace)
      #  puts domain.query  #=> 'food \n house'
      #
      #  # create an instance of the Item already stored at SDB
      #  existent_item = domain.item('house', :reload)
      #  existent_item.attributes.each do |a|
      #    puts "#{a.name} = #{a.values.join(',')}"   # => 'cat = basket \n dog = box'
      #  end
      #
      def item(item_name, attributes=:reload, store=:skip_store)
        Item.new(self, item_name, attributes, store)
      end
      
      # Create new Attribute instance.
      #
      # Creates new attribute with a set of passed values or retrieves these values
      # from SDB if +values+ == :reload.
      #
      #  sdb = RightAws::Sdb.new
      #  # get domain 'family'
      #  domain = sdb.domains.find{|d| d.name == 'family' }
      #  
      #  # retrieve already exsistent attribute from SDB
      #  attr1 = domain.attribute('food', 'dog')
      #  puts attr1.values.join(',') #=> 'bones,meat'
      #  
      #  # create a new attribute  ...
      #  attr2 = domain.attribute('food', 'Jon', ['beef','ham'])
      #  # and store it at SDB
      #  attr2.put
      #  
      #  # get a list of attributes from SDB and print it
      #  domain.item('food').attributes.each do |a|
      #    puts "#{a.name} = #{a.values.join(',')}"   # => 'cat = basket \n dog = box \n Jon = beef,ham'
      #  end
      #
      def attribute(item, attribute_name, values=:reload)
        item = Item.new(self, item, []) unless item.is_a?(Item)
        Attribute.new(item, attribute_name, values)
      end
      
      
      # Perform a query on Domain instance.
      #
      # Returns a list of Item instances matched the query. 
      # To reduce the system load the items are initialized with empty attributes.
      # To get the correct list of attributes use item.reload or set +reload+ param to :reload.
      # 
      #  sdb = RightAws::Sdb.new
      #  # get domain 'family'
      #  domain = sdb.domains.find{|d| d.name == 'family' }
      #  # get a full list of items
      #  all_items = domain.query
      #  puts all_items.map(&:name)  #=> ['house, toys, food']
      #  
      #  # custom query (dont forget to escale single quotes and backslashes)
      #  query = "['dog'='Jon\\'s boot']"
      #  puts domain.query(query).first.name #=> ['family']
      #  
      #  # custom query with auto escaping
      #  query = [ "[?=?]", "dog", "Jon's boot" ]
      #  puts domain.query(query).first.name #=> 'family'
      #
      # read more about the queries: http://docs.amazonwebservices.com/AmazonSimpleDB/2007-11-07/DeveloperGuide/SDB_API_Query.html
      #
      def query(query_expression=nil, reload=:skip_reload,  max_number_of_items = nil, next_token = nil, &block)
        items = []
        # request items
        begin
          query_result  = @sdb.interface.query( @name, query_expression, max_number_of_items, next_token)
          new_items  = query_result[:items]
          new_items.map! do |i| 
            item = self.item(i, {})
            item.reload if reload && reload != :skip_reload
            item
          end
          items += new_items
          next_token = query_result[:next_token]
          break unless block && block.call(new_items) && next_token
        end while true
        items
      end
      
      # Delete domain.
      #
      def delete
        @sdb.interface.delete_domain(@name)
      end
      
    end

    
    class Item
      attr_reader :name
      attr_reader :domain
      attr_reader :attributes

      # Create a new Item instance.
      # 
      # Loads all attributes from SDB if +attributes+ param set to +:reload+.
      # Otherwise initialises the instance attributes list with passed +attributes+
      # param ( +attributes+ is a hash of :name => :values ).
      # To force the attributes upload their values from SDB pass +attributes+ as 
      # an array of attributes names.
      # 
      # see Item#reload warning.
      # 
      #  sdb = RightAws::Sdb.new
      #  domain = RightAws::Sdb::Domain.new(sdb, 'co-workers')   #=> #<RightAws::Sdb::Domain:0xb7795984 ...
      #  
      #  # create a new Item instance 'house' with  attributes (and store to SDB)
      #  attributes = {:dog => ['box', 'hole'], :cat => ['basket','rug']}
      #  item1 = RightAws::Sdb::Item.new(domain, 'house', attributes, :replace) #=> #<RightAws::Sdb::Item:0xb77c9068...
      #  
      #  # create an item but store it later
      #  item2 = RightAws::Sdb::Item.new(domain, 'house', attributes) #=> #<RightAws::Sdb::Item:0xb77c9111...
      #  # ... do something... 
      #  # store attributes from the in memory list. Use item2.replace to replace the SDB attributes 
      #  # by new values
      #  item2.put
      #  
      #  # load already existent item from SDB
      #  item3 = RightAws::Sdb::Item.new(domain, 'awesome')
      #
      def initialize(domain, name, attributes=:reload, store=:skip_store)
        @domain     = domain
        @name       = name
        @attributes = []
        if attributes == :reload 
          reload
        else 
          attributes.each do |name, values|
            create_attribute(name, values, store)
          end
        end
      end
      
      def to_s
        @name
      end
      
      # Reload data from SDB. 
      # 
      # Updates in memory list with the latest data from SDB.
      # Warning: this action retrieves all item's attributes from SDB. 
      # Make sure you have enough memory and time to process this!
      # Returns the new list of attributes.
      #
      #  sdb = RightAws::Sdb.new
      #  domain = RightAws::Sdb::Domain.new(sdb, 'co-workers')   #=> #<RightAws::Sdb::Domain:0xb7795984 ...
      #  
      #  # create a new Item instance with empty list
      #  item1 = RightAws::Sdb::Item.new(domain, 'house', {})
      #  # load attributes from SDB
      #  item1.reload
      #
      def reload
        @attributes = []
        @domain.sdb.interface.get_attributes(@domain.name, @name)[:attributes].each do |attribute, values|
          Attribute.new(self, attribute, values)
        end
        @attributes
      end
      
      # Find attribute by name.
      # Returns the Attribute instance from in memory list.
      def attribute(attribute_name)
        @attributes.find{ |a| a.name == attribute_name }
      end

      # Create new attribute.
      # 
      # Creates new attribute (replaces if the attribute with this name already exists), 
      # adds attribute to in memory list and store it to SDB (if +store+ param is set to :replace or :put).
      # If +values+ == :reload (or == nil) then the attribute will auto load it's values from SDB.
      #
      def create_attribute(name, values, store = :skip_store)
        # find or create attribute
        attr = attribute(name) || Attribute.new(self, name, [])
        # update it's  values
        if !values || values == :reload
          attr.reload
        else
          attr.values = values.to_a
          # store to SDB (if need)
          case store
          when nil, false, :skip_store : # do nothing
          when :put                    : attr.put
          else                           attr.replace
          end
        end
        attr
      end
      
      # Put in memory attributes values to SDB.
      # Returns the list of stored attributes.
      def put
        @attributes.each { |attribute| attribute.put }
        @attributes
      end
      
      # Replace  the attributes from in memory list by new values.
      # The other attributes at SDB (that are not in a memory list) are not affected.
      # I.e. for each attribute from the list the replace method is being performed.
      # Returns the list of replaced attributes.
      def replace
        @attributes.each { |attribute| attribute.replace }
        @attributes
      end
      
      # Delete all attributes from item.
      # Returns an empty list.
      #
      #  puts item.attributes.inspect #=> [#<RightAws::Sdb::Attribute:0xb7795984 ...>, ... ]
      #  item.clear                   #=> []
      #  # check
      #  item.reload                  #=> []
      #
      def delete
        @domain.sdb.interface.delete_attributes(@domain.name, @name)
        @attributes = []
      end
      
    end
    
    class Attribute
      attr_reader   :name
      attr_reader   :item
      attr_accessor :values
      
      # Create a new Attribute instance.
      # 
      # Loads all values from SDB if +values+ param set to +:reload+.
      # Otherwise initializes the values list with passed +values+
      # param ( +values+ is an array ). Stores the values to SDB if 
      # +store+ is to :replace or :put.
      #
      #  sdb    = RightAws::Sdb.new
      #  domain = RightAws::Sdb::Domain.new(sdb, 'co-workers')   #=> #<RightAws::Sdb::Domain:0xb7795984 ...
      #  item   = RightAws::Sdb::Item.new(domain, 'house', attributes, :replace) #=> #<RightAws::Sdb::Item:0xb77c9068...
      #
      #  attribute = RightAws::Sdb::Attribute.new(item, 'Jon', ['Willa', 'Palace', 'Kremlin'])
      #
      def initialize(item, name, values=:reload, store=:skip_store)
        @item = item
        @name = name
        # remove the attribute from parent item if it has the same name 
        @item.attributes.delete_if {|attr| attr.name == name }
        @item.attributes << self
        # set values
        if values == :reload 
          reload
        else 
          @values = values.to_a
          case store
          when nil, false, :skip_store : # do nothing
          when :put                    : put
          else                           replace
          end
        end
      end
      
      def to_s
        @name
      end
      
      # Reload attribute's values from SDB.
      # Replaces the in memory list with SDB values.
      #
      def reload
        @values = @item.domain.sdb.interface.get_attributes(@item.domain.name, @item.name, @name)[:attributes][@name].to_a
      end
      
      
      # Returns +true+ if the attribute includes all the values from the list.
      #
      #  attribute.has? 'beer'
      #  attribute.has? %w{beer car girls}
      #
      def has?(values)
        values.to_a.uniq.each do |value|
          return false unless @values.include?(value)
        end
        true
      end
      
      # Store in memory list of values or +values+ passed as param to SDB. 
      # Returns a list of stored values.
      # 
      #  # show initial values
      #  puts attribute.values.inspect       # => ['beer','pub']
      #  attribute.put('girls')              # => ['girls']
      #  # check (reload from sdb)
      #  attribute.reload                    # => ['beer','pub','girls']
      #
      def put(values=nil)
        if values
          stored = values.to_a.uniq
          @item.domain.sdb.interface.put_attributes(@item.domain.name, @item.name, @name => stored)
          (@values += stored).uniq!
          stored
        else
          @values.uniq!
          @item.domain.sdb.interface.put_attributes(@item.domain.name, @item.name, @name => @values)
          @values
        end
      end
      
      # Store in memory list of values or +values+ passed as param to sdb. 
      # Returns a list of new values.
      #
      #  # show initial values
      #  puts attribute.values.inspect       # => ['beer','pub']
      #  attribute.replace('girls')          # => ['girls']
      #  # check (reload from sdb)
      #  attribute.reload                    # => ['girls']
      #
      def replace(values=nil)
        @values = values.to_a if values
        @values.uniq!
        @item.domain.sdb.interface.put_attributes(@item.domain.name, @item.name, {@name => @values}, :replace)
        @values
      end
      
      # Delete a set of values (or all by deault) from attribute. 
      # Returns the list of removed values.
      #  
      #  # show initial values
      #  puts attribute.values.inspect       # => ['beer','pub','girls','car','vodka']
      #  # delete two elements
      #  attribute.delete(['beer', 'vodka']) # => ['beer', 'vodka']
      #  # check the deletion
      #  puts attribute.values.inspect       # => ['pub','girls','car']
      #  attribute.reload                    # => ['pub','girls','car']
      #  # delete one element
      #  attribute.delete('car')             # => ['car']
      #  # check the deletion
      #  attribute.reload                    # => ['pub','girls']
      #
      def delete(values=nil)
        # values to delete (all by default)
        if values
          # delete the values partialy
          removed = values.to_a
          @item.domain.sdb.interface.delete_attributes(@item.domain.name, @item.name, { @name => removed })
          @values -= removed
        else
          # quick way to delete all the values
          @item.domain.sdb.interface.delete_attributes(@item.domain.name, @item.name, [ @name ])
          removed, @values = @values, []
          # there are no values left -> remove from item attributes list 
          @item.attributes.delete(self)
        end
        removed
      end
      
    end
  end  
end