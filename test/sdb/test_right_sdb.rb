require File.dirname(__FILE__) + '/test_helper.rb'

class TestSdb < Test::Unit::TestCase

  def setup
    STDOUT.sync  = true
    @domain = 'right_sdb_awesome_test_domain'
    @item   = 'toys'
    @attr   = { 'Jon' => %w{beer car} }
    # Interface instance
    @sdb    = Rightscale::SdbInterface.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
  end

  SDB_DELAY = 2
  
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

end