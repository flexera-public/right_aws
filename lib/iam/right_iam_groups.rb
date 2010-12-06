module RightAws

  class IamInterface < RightAwsBase

    #-----------------------------------------------------------------
    #      Groups
    #-----------------------------------------------------------------

    # Lists the groups that have the specified path prefix.
    #
    # Options: :path_prefix, :max_items, :marker
    #
    #  iam.list_groups #=>
    #    [{:group_id=>"AGP000000000000000UTY",
    #      :arn=>"arn:aws:iam::640000000037:group/kd_test",
    #      :path=>"/",
    #      :group_name=>"kd_test"}]
    #
    def list_groups(options={}, &block)
      incrementally_list_iam_resources('ListGroups', options, &block)
    end

    # Creates a new group.
    #
    #  iam.create_group('kd_group') #=>
    #    {:group_id=>"AGP000000000000000UTY",
    #     :arn=>"arn:aws:iam::640000000037:group/kd_test",
    #     :path=>"/",
    #     :group_name=>"kd_test"}
    #
    #  iam.create_group('kd_test_3', '/kd/') #=>
    #    {:group_id=>"AGP000000000000000G6Q",
    #     :arn=>"arn:aws:iam::640000000037:group/kd/kd_test_3",
    #     :path=>"/kd/",
    #     :group_name=>"kd_test_3"}
    #
    def create_group(group_name, path=nil)
      request_hash = { 'GroupName' => group_name }
      request_hash['Path'] = path unless path.right_blank?
      link = generate_request("CreateGroup", request_hash)
      request_info(link, CreateGroupParser.new(:logger => @logger))
    end

    # Updates the name and/or the path of the specified group
    #
    # Options: :new_group_name, :new_path
    #
    #  iam.update_group('kd_test', :new_group_name => 'kd_test_1', :new_path => '/kd1/') #=> true
    #
    def update_group(group_name, options={})
      request_hash = { 'GroupName' => group_name}
      request_hash['NewGroupName'] = options[:new_group_name] unless options[:new_group_name].right_blank?
      request_hash['NewPath']      = options[:new_path]       unless options[:new_path].right_blank?
      link = generate_request("UpdateGroup", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Returns a list of Users that are in the specified group.
    #
    # Options: :max_items, :marker
    #
    #  iam.get_group('kd_test') #=>
    #    {:arn=>"arn:aws:iam::640000000037:group/kd1/kd_test_1",
    #      :users=>
    #        [{:arn=>"arn:aws:iam::640000000037:user/kd",
    #          :path=>"/",
    #          :user_name=>"kd",
    #          :user_id=>"AID000000000000000WZ2"}],
    #      :group_name=>"kd_test_1",
    #      :group_id=>"AGP000000000000000UTY",
    #      :path=>"/kd1/"}
    #
    def get_group(group_name, options={}, &block)
      options[:group_name] = group_name
      incrementally_list_iam_resources('GetGroup', options, :items => :users, :except => [:marker, :is_truncated], &block)
    end

    # Deletes the specified group. The group must not contain any Users or have any attached policies.
    #
    #  iam.delete_group('kd_test_3') #=> true
    #
    def delete_group(group_name)
      request_hash = { 'GroupName' => group_name }
      link = generate_request("DeleteGroup", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Group Policies
    #-----------------------------------------------------------------

    # Lists the names of the policies associated with the specified group.
    #
    # Options: :max_items, :marker
    #
    #  iam.list_group_policies('kd_test') #=> ["kd_policy_1"]
    #
    def list_group_policies(group_name, options={}, &block)
      options[:group_name] = group_name
      incrementally_list_iam_resources('ListGroupPolicies', options, :parser => BasicIamListParser, &block)
    end

    # Adds (or updates) a policy document associated with the specified group.
    #
    #  iam.put_group_policy('kd_test', 'kd_policy_1', %Q({"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]})) #=> true
    #
    def put_group_policy(group_name, policy_name, policy_document)
      request_hash = { 'GroupName'      => group_name,
                       'PolicyDocument' => policy_document,
                       'PolicyName'     => policy_name }
      link = generate_request_impl(:post, "PutGroupPolicy", request_hash)
      result = request_info(link, RightHttp2xxParser.new(:logger => @logger))
      result[:policy_document] = URI::decode(result[:policy_document])
      result
    end

    # Retrieves the specified policy document for the specified group.
    #
    #  iam.get_group_policy('kd_test', 'kd_policy_1') #=>
    #    {:policy_name=>"kd_policy_1",
    #     :policy_document=>"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
    #     :group_name=>"kd_test"}
    #
    def get_group_policy(group_name, policy_name)
      request_hash = { 'GroupName'  => group_name,
                       'PolicyName' => policy_name }
      link = generate_request("GetGroupPolicy", request_hash)
      request_info(link, GetGroupPolicyParser.new(:logger => @logger))
    end

    # Deletes the specified policy that is associated with the specified group
    #
    #  iam.delete_group_policy('kd_test', 'kd_policy_1') #=> true
    #
    def delete_group_policy(group_name, policy_name)
      request_hash = { 'GroupName'  => group_name,
                       'PolicyName' => policy_name }
      link = generate_request("DeleteGroupPolicy", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS:
    #-----------------------------------------------------------------

    class ListGroupsParser < BasicIamListParser #:nodoc:
      def reset
        @expected_tags = %w{ Arn GroupId GroupName Path }
      end
    end

    class CreateGroupParser < BasicIamParser #:nodoc:
      def reset
        @expected_tags = %w{ Arn GroupId GroupName Path }
      end
    end

    class GetGroupParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @item = {} if name == 'member'
      end
      def tagend(name)
        case name
        when 'Marker'      then @result[:marker]       = @text
        when 'IsTruncated' then @result[:is_truncated] = @text == 'true'

        when 'GroupName' then @result[:group_name] = @text
        when 'GroupId'   then @result[:group_id]   = @text
        when 'UserName'  then @item[:user_name]    = @text
        when 'UserId'    then @item[:user_id]      = @text
        when 'member'    then @result[:users]     << @item
        else
          case full_tag_name
          when %r{/Group/Path$}  then @result[:path] = @text
          when %r{/Group/Arn$}   then @result[:arn]  = @text
          when %r{/member/Path$} then @item[:path]   = @text
          when %r{/member/Arn$}  then @item[:arn]    = @text
          end
        end
      end
      def reset
        @result = { :users => [] }
      end
    end

    class GetGroupPolicyParser < BasicIamParser #:nodoc:
      def reset
        @expected_tags = %w{ GroupName PolicyDocument PolicyName }
      end
    end

  end
  
end

