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
    
    attr_reader   :interface
    attr_accessor :next_token
    
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
    #  puts sdb.domains #=> "family\nfriends"
    # 
    #  # list domains by 2
    #  sdb.domains(2) do |domains|
    #    puts domains         #=> "family\nfriends"
    #    puts sdb.next_token  #=> "ZmFtaWx5"
    #    # set sdb.next_token to +nil+ to break the block execution
    #    # sdb.next_token = nil
    #  end
    #
    def domains(max_number_of_domains=nil, next_token=nil, &block)
      @next_token = next_token
      domains = []
      # request domains list
      begin
        query_result = @interface.list_domains(max_number_of_domains, @next_token)
        new_domains  = query_result[:domains].map { |name| Domain.new(self, name)}
        domains     += new_domains
        @next_token  = query_result[:next_token]
        if block 
          block.call new_domains
          break unless @next_token
        else
          break
        end
      end while true
      domains
    end
  
    
    class Domain
      attr_reader   :sdb
      attr_reader   :name
      attr_accessor :next_token

      # Create new domain instance.
      #  
      #  sdb    = RightAws::Sdb.new
      #  domain = RightAws::Sdb::Domain.new(sdb, "family")
      #  domain.query( ["[?=?]", "Jon", "beer"] )
      #
      def initialize(sdb, name)
        @sdb  = sdb
        @name = name
      end

      # Create an Item instance.
      #  
      #  item = domain.item("toys")
      #  puts item.attributes #=> {}
      #  item.load
      #  puts item.attributes #=> { "cat"    => ["Jons_socks", "clew", "mouse"], 
      #                             "Silvia" => ["beetle", "kids", "rolling_pin"] }
      #
      def item(name, attributes={})
        Item.new(self, name, attributes)
      end

      # Perform a query on SDB.
      #
      #  item = domain.query(["[?=?]","cat","clew"]).first
      #  puts item.inspect             #=> #<RightAws::Sdb::Item:0xb76fddf0 ... >
      #  puts item.attributes.inspect  #=> {}
      #  item.load
      #  puts item.attributes.inspect  #=> { "cat"    => ["Jons_socks", "clew", "mouse"], 
      #                                      "Silvia" => ["beetle", "kids", "rolling_pin"], 
      #                                      "Jon"    => ["hammer", "spade", "vacuum_cleaner"] }
      #  
      #  # a block usage for huge query output:
      #  domain.query(["[?=?]","cat","clew"], 10) do |items|
      #    puts items.inspect  # 10 items per iteration
      #    puts domain.next_token  #=> "rO0AB...uLn="
      #    # set domain.next_token to +nil+ to break the block execution
      #    # domain.next_token = nil
      #  end
      #
      def query(query_expression=nil, max_number_of_items = nil, next_token = nil, &block)
        @next_token = next_token
        items = []
        # request items
        begin
          query_result  = @sdb.interface.query( @name, query_expression, max_number_of_items, @next_token)
          new_items  = query_result[:items]
          new_items.map! { |name| self.item(name) }
          items += new_items
          @next_token = query_result[:next_token]
          if block 
            block.call new_items
            break unless @next_token
          else
            break
          end
        end while true
        items
      end
      
      def to_s
        @name
      end
    end

    
    class Item
      attr_accessor :name
      attr_accessor :attributes 

      # Create new Item instance.
      # +Attributes+ is a hash: { attribute1 => values1, ..., attributeN => valuesN }.
      #
      #  sdb    = RightAws::Sdb.new
      #  domain = RightAws::Sdb::Domain.new(sdb, "family")
      #  item   = RightAws::Sdb::Item.new(domain, "toys")
      #  puts item.attributes.inspect #=> {}
      #  item.load
      #  puts item.attributes.inspect #=> { "cat"    => ["Jons_socks", "clew", "mouse"], 
      #                                     "Silvia" => ["beetle", "kids", "rolling_pin"], 
      #                                     "Jon"    => ["hammer", "spade", "vacuum_cleaner"] }
      #                                     
      #  # create a new (not existent at SDB) item
      #  item2 = RightAws::Sdb::Item.new(domain, "toys", "booble" => ["buble","boble"])
      #  puts item2.attributes.inspect #=> {"booble" => ["buble","boble"]}
      #  item2.save
      #  # check SDB was updated
      #  item2.load  #=> { "booble" => ["buble","boble"] }
      #
      def initialize(domain, name, attributes={})
        @domain = domain
        @name   = name
        @attributes = attributes
      end

      # Get in-memory attribute.
      #
      #  puts item.attributes.inspect #=> { "cat"    => ["Jons_socks", "clew", "mouse"], 
      #                                     "Silvia" => ["beetle", "kids", "rolling_pin"], 
      #                                     "Jon"    => ["hammer", "spade", "vacuum_cleaner"] }
      #  puts item["cat"].inspect     #=> ["Jons_socks", "clew", "mouse"]
      #  puts item["dog"].inspect     #=> nil
      #
      def [](attribute)
        @attributes[attribute]
      end

      # Set in-memory attribute.
      # 
      #  puts item["cat"].inspect  #=> ["Jons_socks", "clew", "mouse"]
      #  puts item["dog"].inspect  #=> nil
      #  item["cat"] = ["Whiskas", "chicken"]
      #  item["dog"] = "Pedigree"
      #  puts item["cat"].inspect  #=> ["Whiskas", "chicken"]
      #  puts item["dog"].inspect  #=> ["Pedigree"]
      #
      def []=(attribute, values)
        @attributes[attribute] = values.to_a
      end

      # Load attributes from SDB. Replaces in-memory attributes.
      # 
      #  item = RightAws::Sdb::Item.new(domain, "toys", { "winki" => ["pinki"], "booble" => ["buble","boble"] } )
      #  puts item.attributes.inspect #=> { "winki"  => ["pinki"], 
      #                                     "booble" => ["buble","boble"] }
      #  item.load                    #=> { "cat"    => ["Jons_socks", "clew", "mouse"], 
      #                                     "Silvia" => ["beetle", "kids", "rolling_pin"], 
      #                                     "Jon"    => ["hammer", "spade", "vacuum_cleaner"] }
      def load
        @attributes = {}
        @domain.sdb.interface.get_attributes(@domain.name, @name)[:attributes].each do |attribute, values|
          @attributes[attribute]= values
        end
        @attributes
      end
      
      # Load a set of attributes from SDB. Adds the loaded list to in-memory data.
      # +Attributes+ is an array or comma separated list of attributes names.
      # Returns a hash of loaded attributes.
      # 
      # This is not the best method to get a bunch of attributes because
      # a web service call is being performed for every attribute.
      # 
      #  item = RightAws::Sdb::Item.new(domain, "toys", { "winki"  => ["pinki"], 
      #                                                   "booble" => ["buble","boble"],
      #                                                   "Jon"    => ["beer", "girls"] } )
      #  item.load_attributes("cat", "Jon")  #=> { "cat"    => ["Jons_socks", "clew", "mouse"], 
      #                                            "Jon"    => ["hammer", "spade", "vacuum_cleaner"] }
      #  # "winki" and "booble" are in-memory attributes that are not saved yet
      #  puts item.attributes.inspect        #=> { "winki"  => ["pinki"], 
      #                                            "booble" => ["buble","boble"],
      #                                            "cat"    => ["Jons_socks", "clew", "mouse"], 
      #                                            "Jon"    => ["hammer", "spade", "vacuum_cleaner"] }
      #
      def load_attributes(*attributes)
        result = {}
        attributes.flatten!
        attributes.uniq.each do |attribute|
          values = @domain.sdb.interface.get_attributes(@domain.name, @name, attribute)[:attributes][attribute]
          if values
            @attributes[attribute] = result[attribute] = values
          else
            @attributes.delete(attribute)
          end
        end
        result
      end
      
      # Store in-memory attributes to SDB.
      # Adds the attributes values to already stored at SDB.
      #
      #  item.save #=> a hash of saved attributes
      #
      def save
        @attributes = uniq_values(@attributes)
        @domain.sdb.interface.put_attributes(@domain.name, @name, @attributes)
        @attributes
      end
       
      # Save specified attributes.
      # +Attributes+ is a hash: { attribute1 => values1, ..., attributeN => valuesN }.
      # Returns a hash of saved attributes.
      #
      #  item = RightAws::Sdb::Item.new(domain, "toys", { "winki"  => ["pinki"], 
      #                                                   "booble" => ["buble","boble"],
      #                                                   "Jon"    => ["beer", "girls"] } )
      #  item.save_attributes("Jon" => ["friends", "car"] ) #=> "Jon" => ["friends", "car"]
      #  # "beer" and "girls" are in memory only, but "friends" and "car" are stored on SDB.
      #  puts item["Jon"].inspect                           #=> ["beer", "girls", "friends", "car"]
      #
      def save_attributes(attributes)
        attributes = uniq_values(attributes)
        @domain.sdb.interface.put_attributes(@domain.name, @name, attributes)
        attributes.each do |attribute, values|
          @attributes[attribute] ||= []
          @attributes[attribute] += values
          @attributes[attribute].uniq!
        end
        attributes
      end

      # Store in-memory attributes to SDB.
      # Replaces the attributes values already stored at SDB by in-memory data.
      # Returns a hash of stored attributes. 
      # 
      #  item = RightAws::Sdb::Item.new(domain, "toys" )
      #  item.load     #=> { "winki"  => ["pinki"], 
      #                      "booble" => ["buble","boble"] }
      #  item.attributes = { "winki" => ["botinki"], "cat" => ["mice"] }
      #  item.replace  #=> { "winki"  => ["botinki"], 
      #                      "cat"    => ["mice"]}
      #  # "cat" was added, "winki"  - replaced, "booble" - not affected
      #  item.load     #=> { "booble" => ["buble","boble"], 
      #                      "cat"    => ["mice"],
      #                      "winki"  => ["botinki"] }
      #
      def replace
        @attributes = uniq_values(@attributes)
        @domain.sdb.interface.put_attributes(@domain.name, @name, @attributes, :replace)
        @attributes
      end

      # Replace the attributes.
      # +Attributes+ is a hash: { attribute1 => values1, ..., attributeN => valuesN }.
      # Replaces the attributes at SDB by the given values.
      # The other in-memory attributes are not being saved.
      # Returns a hash of stored attributes.
      #
      #  item = RightAws::Sdb::Item.new(domain, "toys" )
      #  item.load    #=> { "winki"  => ["pinki"], 
      #                     "booble" => ["buble","boble"] }
      #  item.replace_attributes("booble"=>["oops"]) #=> {"booble" => ["oops"]}
      #  # check SDB updated
      #  item.load    #=> { "winki"  => ["pinki"], 
      #                     "booble" => ["oops"] }
      #
      def replace_attributes(attributes)
        attributes = uniq_values(attributes)
        @domain.sdb.interface.put_attributes(@domain.name, @name, attributes, :replace)
        attributes.each { |attribute, values| attributes[attribute] = values }
        attributes
      end
      
      # Remove specified values from corresponding attributes.
      # +Attributes+ is a hash: { attribute1 => values1, ..., attributeN => valuesN }.
      #
      #  item = RightAws::Sdb::Item.new(domain, "toys" )
      #  item.load    #=> { "winki"  => ["pinki"], 
      #                     "booble" => ["buble","boble"] }
      #  item.delete_values("booble" => ["boble"])  # => {"booble" => ["boble"]}
      #  # check SDB was updated
      #  item.load    #=> { "winki"  => ["pinki"], 
      #                     "booble" => ["boble"] }
      #
      def delete_values(attributes)
        attributes = uniq_values(attributes)
        unless attributes.blank?
          @domain.sdb.interface.delete_attributes(@domain.name, @name, attributes)
          attributes.each { |attribute, values| @attributes[attribute] -= values }
        end
        attributes
      end

      # Removes specified attributes from the item.
      # +Attributes+ is an array or comma separated list of attributes names.
      # Returns the list of deleted attributes.
      # 
      #  item = RightAws::Sdb::Item.new(domain, "toys" )
      #  item.load    #=> { "winki"  => ["pinki"], 
      #                     "booble" => ["buble","boble"],
      #                     "Jon"    => ["beer","girls"]  }
      #  item.delete_attributes("booble", "Jon") #=> ["booble", "Jon"]
      #  # check SDB was updated and "booble" and "Jon" was deleted
      #  item.load    #=> { "winki" => ["pinki"] }
      def delete_attributes(*attributes)
        attributes = attributes.flatten!
        unless attributes.blank?
          @domain.sdb.interface.delete_attributes(@domain.name, @name, attributes)
          attributes.each { |attribute| @attributes.delete(attribute) }
        end
        attributes
      end
      
      # Delete the Item entirely from SDB.
      # 
      #  item = RightAws::Sdb::Item.new(domain, "toys" )
      #  item.load   #=> { "winki"  => ["pinki"], 
      #                    "booble" => ["buble","boble"],
      #                    "Jon"    => ["beer","girls"]  }
      #  item.delete
      #  item.load   #=> {}
      #
      def delete
        @domain.sdb.interface.delete_attributes(@domain.name, @name)
        @attributes = {}
      end
      
      def to_s
        @name
      end
      
    private    

      def uniq_values(attributes=nil) # :nodoc:
        attributes = attributes.dup
        attributes.each do |attribute, values|
          attributes[attribute] = values.to_a.uniq
          attributes.delete(attribute) if values.blank?
        end
        attributes
      end

    end
  end
end
