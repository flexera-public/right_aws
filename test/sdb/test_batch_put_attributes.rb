# -*- coding: utf-8 -*-
require File.dirname(__FILE__) + '/test_helper.rb'

class TestSdb < Test::Unit::TestCase

  def setup
    STDOUT.sync  = true
    @domain = 'right_sdb_awesome_test_domain'
    @attributes = {
      'a' => { 'foo' => '123' },
      'b' => { 'bar' => '456' }
    }
    # Interface instance
    @sdb = Rightscale::SdbInterface.new
    @sdb.delete_domain(@domain)
    wait(SDB_DELAY, "after removing domain")
    @sdb.create_domain(@domain)
    wait(SDB_DELAY, "after recreating domain")
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

  def test_batch_put_attributes
    @sdb.batch_put_attributes(@domain, @attributes)
    wait(SDB_DELAY, "after putting attributes")
    a = @sdb.get_attributes(@domain, 'a')[:attributes]
    b = @sdb.get_attributes(@domain, 'b')[:attributes]
    assert_equal( {'foo' => ['123']}, a)
    assert_equal( {'bar' => ['456']}, b)
    
    # Replace = false
    @sdb.batch_put_attributes(@domain, { 'a' => {'foo' => ['789']}})
    wait(SDB_DELAY, "after putting attributes") 
    a = @sdb.get_attributes(@domain, 'a')[:attributes]
    assert_equal ['123', '789'], a['foo'].sort

    # Replace = true
    @sdb.batch_put_attributes(@domain, {'b' => {'bar' => ['789']}}, true)
    wait(SDB_DELAY, "after putting attributes") 
    b = @sdb.get_attributes(@domain, 'b')[:attributes]
    assert_equal ['789'], b['bar'].sort

  end
end
