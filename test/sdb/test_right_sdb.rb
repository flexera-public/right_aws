require File.dirname(__FILE__) + '/test_helper.rb'

class TestSdb < Test::Unit::TestCase

  def setup
    STDOUT.sync  = true
    @domain = 'right_sdb_awesome_test_domain'
    @item   = 'toys'
    @attr   = { 'Jon' => %w{beer car} }
    # Interface instance
    @sdb    = Rightscale::SdbInterface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
    # Sdb instance
    @s      = Rightscale::Sdb.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
  end

  SDB_DELAY = 3
  
  def wait(delay, msg='')
    print "waiting #{delay} seconds #{msg}"
    while delay>0 do
      delay -= 1
      print '.'
      sleep 1
    end
    puts
  end

  #---------------------------
  # Rightscale::SdbInterface
  #---------------------------

  def test_00_delete_domain
    # delete the domain to reset all the things
    assert @sdb.delete_domain(@domain), 'delete_domain fail'
    wait SDB_DELAY, 'after domain deletion'
  end
  
  def test_01_create_domain
    # check that domain does not exist
    assert !@sdb.list_domains[:domains].include?(@domain)
    # create domain
    assert @sdb.create_domain(@domain), 'create_domain fail'
    wait SDB_DELAY, 'after domain creation'
    # check that we have received new domain from Amazin
    assert @sdb.list_domains[:domains].include?(@domain)
  end

  def test_02_put_attributes
    # put attributes
    assert @sdb.put_attributes(@domain, @item, @attr)
    wait SDB_DELAY, 'after putting attributes'
  end
  
  def test_03_get_attributes
    # get attributes
    values = @sdb.get_attributes(@domain, @item)[:attributes]['Jon'].to_a.sort
    # compare to original list
    assert_equal values, @attr['Jon'].sort
  end

  def test_04_add_attributes
    # add new attribute
    new_value = 'girls'
    @sdb.put_attributes @domain, @item, {'Jon' => new_value}
    wait SDB_DELAY, 'after putting attributes'
    # get attributes ('girls' must be added to already existent attributes)
    values = @sdb.get_attributes(@domain, @item)[:attributes]['Jon'].to_a.sort
    assert_equal values, (@attr['Jon'] << new_value).sort
  end
  
  def test_05_replace_attributes
    # replace attributes
    @sdb.put_attributes @domain, @item, {'Jon' => 'pub'}, :replace
    wait SDB_DELAY, 'after replacing attributes'
    # get attributes (all must be removed except of 'pub')
    values = @sdb.get_attributes(@domain, @item)[:attributes]['Jon']
    assert_equal values, ['pub']
  end
  
  def test_06_delete_attribute
    # add value 'girls' and 'vodka' to 'Jon'
    @sdb.put_attributes @domain, @item, {'Jon' => ['girls','vodka']}
    wait SDB_DELAY, 'after adding attributes'
    # get attributes ('girls' and 'vodka' must be added 'pub')
    values = @sdb.get_attributes(@domain, @item)[:attributes]['Jon'].to_a.sort
    assert_equal values, ['girls', 'pub', 'vodka']
    # delete a single value 'girls' from attribute 'Jon'
    @sdb.delete_attributes @domain, @item, 'Jon' => ['girls']
    wait SDB_DELAY, 'after the deletion of attribute'
    # get attributes ('girls' must be removed)
    values = @sdb.get_attributes(@domain, @item)[:attributes]['Jon']
    assert_equal values, ['pub', 'vodka']
    # delete all values from attribute 'Jon'
    @sdb.delete_attributes @domain, @item, ['Jon']
    wait SDB_DELAY, 'after the deletion of attributes'
    # get attributes (values must be empty)
    values = @sdb.get_attributes(@domain, @item)[:attributes]['Jon']
    assert_equal values, nil
  end

  def test_07_delete_item
    @sdb.put_attributes @domain, @item, {'Jon' => ['girls','vodka']}
    wait SDB_DELAY, 'after adding attributes'
    # get attributes ('girls' and 'vodka' must be there)
    values = @sdb.get_attributes(@domain, @item)[:attributes]['Jon'].to_a.sort
    assert_equal values, ['girls', 'vodka']
    # delete an item
    @sdb.delete_attributes @domain, @item
    # get attributes (values must be empty)
    values = @sdb.get_attributes(@domain, @item)[:attributes]['Jon']
    assert_equal values, nil
  end  
  
  def test_08_query
    # add some values for query
    @sdb.put_attributes @domain, @item, {'Jon' => ['girls','vodka']}
    wait SDB_DELAY, 'after adding attributes'
    items = @sdb.query(@domain, ['[?=?]', 'Jon','vodka'])[:items]
    assert_equal items.size, 1
    assert_equal items.first, @item
  end
  
  def test_09_delete_domain
    assert @sdb.delete_domain(@domain), 'delete_domain fail'
    wait SDB_DELAY, 'after domain deletion'
    # check that domain does not exist
    assert !@sdb.list_domains[:domains].include?(@domain)
  end

  #---------------------------
  # Rightscale::Sdb
  #---------------------------
  def test_10_domains
    domains = @s.domains
    assert domains.is_a?(Array)
    # check that we have no our test domail in the list
    assert !domains.map{|d| d.name}.find{|d| d == @domain}
    # create domain via SdbInterface
    assert @sdb.create_domain(@domain), 'create_domain fail'
    wait SDB_DELAY, 'after domain creation'
    # domain must be in the list now
    assert @s.domains.map{|d| d.name}.find{|d| d == @domain}
    # kill it
    assert @sdb.delete_domain(@domain), 'delete_domain fail'
    wait SDB_DELAY, 'after domain deletion'
  end

  #---------------------------
  # Rightscale::Sdb::Domain
  #---------------------------

  def test_20_in_memory_domain
    # create the domain instance but do not create it at SDB
    domain = RightAws::Sdb::Domain.new(@s, @domain, false)
    wait SDB_DELAY, 'after dummy domain creation'
    # check that domain does not exist at SDB
    assert !@sdb.list_domains[:domains].include?(@domain)
    # try to request any data for domain
    # must get: RightAws::AwsError: NoSuchDomain: The specified domain does not exist
    assert_raise RightAws::AwsError do
      domain.query
    end
  end

  def test_21_domain_creation
    # create the domain at SDB
    domain = RightAws::Sdb::Domain.new(@s, @domain, true)
    wait SDB_DELAY, 'after in memory creation'
    # check that domain exists at SDB
    assert @sdb.list_domains[:domains].include?(@domain)
  end

  #---------------------------
  # Rightscale::Sdb::Item
  #---------------------------

  def test_30_in_memory_item
    domain = RightAws::Sdb::Domain.new(@s, @domain, false)
    # create the Item instance (in memory only)
    item = domain.item @item, @attr
    wait SDB_DELAY, 'after in memory item creation'
    # check the new Item has correct attributes
    assert_equal item.attributes[0].values, @attr['Jon']
    # Get attributes for this item from SDB (via SdbInterface) and make sure they are empty
    sdb_attr = @sdb.get_attributes(@domain, @item)[:attributes]
    assert sdb_attr.blank?
    # Reload item from SDB (must clear the in memory attributes)
    item.reload
    assert item.attributes.blank?
  end

  def test_31_in_memory_item_put
    domain = RightAws::Sdb::Domain.new(@s, @domain, false)
    # create the Item instance (in memory only)
    item = domain.item @item, @attr
    # store all attributes to SDB
    item.put
    wait SDB_DELAY, 'after in memory item put method'
    # create new item instance and load it's attributes from SDB
    item2 = domain.item @item
    assert_equal item.attributes.size, item2.attributes.size
    # compare in memory attributes (item) and just readed from SDB (item2)
    assert_equal item.attribute('Jon').values.sort, item2.attribute('Jon').values.sort
  end

  def test_32_item_reload_replace
    domain = RightAws::Sdb::Domain.new(@s, @domain, false)
    # create the Item instance and read its attributes from SDB
    item = domain.item @item, :reload
    item.attribute('Jon').values = ['pub']
    item.replace
    wait SDB_DELAY, 'after replacing the attributes'
    # create new item instance and load it's attributes from SDB
    item2 = domain.item @item, :reload
    # compare just readed attribute values and saved
    assert_equal item2.attribute('Jon').values, ['pub']
  end

  def test_33_item_deletion
    domain = RightAws::Sdb::Domain.new(@s, @domain, false)
    # create the Item instance and read its attributes from SDB
    item = domain.item @item, :reload
    # it must have at least one attribute (stored at previous steps)
    assert !item.attributes.blank?
    # clear all attributes, this should return an empty list of attributes
    assert item.delete.blank?
    wait SDB_DELAY, 'after clearing the attributes'
    # create new item instance and load it's attributes from SDB
    item2 = domain.item @item
    # both of the attributes lists should be empty
    assert_equal item.attributes, item2.attributes
  end

  #---------------------------
  # Rightscale::Sdb::Attribute
  #---------------------------

  def test_40_attribute_create_put
    domain = RightAws::Sdb::Domain.new(@s, @domain, false)
    item   = domain.item @item, []
    # create in memory attribute 
    attr  = RightAws::Sdb::Attribute.new(item, 'Jon', %w{beer car})
    # check that it has not been created at SDB
    attr2 = RightAws::Sdb::Attribute.new(item, 'Jon')
    assert_equal attr2.values, []
    # store attribute values to SDB.
    # make sure it returns a list of stored values.
    assert_equal attr.put.sort, attr.values.sort
    wait SDB_DELAY, 'after putting the values'
    # reload the test attribute and make sure it was updated
    assert_equal attr2.reload.sort, attr.values.sort
    assert_equal attr2.values.sort, attr.values.sort
  end

  def test_41_query
    domain = RightAws::Sdb::Domain.new(@s, @domain, false)
    # simple request
    items = domain.query ["[?=?]", 'Jon', 'beer'], :reload
    # this item should be returned
    item  = items.find{ |i| i.name == @item }
    assert item
    # must have attribute 'Jon'
    attr = item.attribute('Jon')
    assert attr
    # which must have values 'beer', 'cat'
    assert attr.has?(%w{beer car})
  end
  
  def test_42_attribute_replace
    domain = RightAws::Sdb::Domain.new(@s, @domain, false)
    item   = domain.item @item, []
    # create attribute and load its values from SDB
    attr = RightAws::Sdb::Attribute.new(item, 'Jon')
    assert_equal attr.values.sort, %w{beer car}
    # replace values
    new_values = %w{girls vodka chicken bigmac friends}
    assert_equal attr.replace(new_values), new_values
    # create test attribute and liak its values from SDB
    attr2 = RightAws::Sdb::Attribute.new(item, 'Jon')
    assert_equal attr2.values.sort, attr.values.sort
  end

  def test_43_attribute_values_deletion
    domain = RightAws::Sdb::Domain.new(@s, @domain, false)
    item   = domain.item @item, []
    # load both attributes from SDB
    attr  = RightAws::Sdb::Attribute.new(item, 'Jon')
    attr2 = RightAws::Sdb::Attribute.new(item, 'Jon')
    # delete one value
    assert_equal attr.delete('friends'), ['friends']
    wait SDB_DELAY, 'after value deletion'
    # update from SDB and check
    attr2.reload
    assert_equal attr.values.sort, attr2.values.sort
    # now delete all the rest values
    old_list = attr.values
    assert_equal attr.delete, old_list
    wait SDB_DELAY, 'after value deletion'
    # update from SDB and check
    attr2.reload
    assert_equal attr.values, attr2.values
  end

  def test_99_delete_domain
    # delete the domain to reset all the things
    assert @sdb.delete_domain(@domain), 'delete_domain fail'
  end
  
end