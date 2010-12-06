module RightAws

  class IamInterface < RightAwsBase

    #-----------------------------------------------------------------
    #      Users
    #-----------------------------------------------------------------

    # Lists the Users that have the specified path prefix.
    #
    # Options: :path_prefix, :max_items, :marker
    #
    #  iam.list_users #=>
    #    [{:user_name=>"kd",
    #      :user_id=>"AI000000000000000006A",
    #      :arn=>"arn:aws:iam::640000000037:user/kd",
    #      :path=>"/"}]
    #
    def list_users(options={}, &block)
      incrementally_list_iam_resources('ListUsers', options, &block)
    end

    # Creates a new User for your AWS Account.
    #
    # Options: :path
    #
    #  iam.create_user('kd') #=>
    #    {:user_name=>"kd",
    #     :user_id=>"AI000000000000000006A",
    #     :arn=>"arn:aws:iam::640000000037:user/kd",
    #     :path=>"/"}
    #
    def create_user(user_name, options={})
      request_hash = { 'UserName' => user_name }
      request_hash['Path'] = options[:path] unless options[:path]
      link = generate_request("CreateUser", request_hash)
      request_info(link, GetUserParser.new(:logger => @logger))
    end

    # Updates the name and/or the path of the specified User.
    #
    #  iam.update_user('kd1', :new_user_name => 'kd1', :new_path => '/kd1/') #=> true
    #
    def update_user(user_name, options={})
      request_hash = { 'UserName' => user_name}
      request_hash['NewUserName'] = options[:new_user_name] unless options[:new_user_name].right_blank?
      request_hash['NewPath']     = options[:new_path]       unless options[:new_path].right_blank?
      link = generate_request("UpdateUser", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Retrieves information about the specified User, including the User's path, GUID, and ARN.
    #
    #  iam.get_user('kd') #=>
    #    {:user_name=>"kd",
    #     :user_id=>"AI000000000000000006A",
    #     :arn=>"arn:aws:iam::640000000037:user/kd",
    #     :path=>"/"}
    #
    def get_user(user_name)
      request_hash = { 'UserName' => user_name }
      link = generate_request("GetUser", request_hash)
      request_info(link, GetUserParser.new(:logger => @logger))
    end

    # Deletes the specified User. The User must not belong to any groups, have any keys or signing certificates, or have any attached policies.
    #
    #  iam.delete_user('kd') #=> true
    #
    def delete_user(user_name)
      request_hash = { 'UserName' => user_name }
      link = generate_request("DeleteUser", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      User Policies
    #-----------------------------------------------------------------

    # Lists the names of the policies associated with the specified User.
    #
    # Options: :max_items, :marker
    #
    #  iam.list_user_policies('kd') #=> ["kd_user_policy_1"]
    #
    def list_user_policies(user_name, options={}, &block)
      options[:user_name] = user_name
      incrementally_list_iam_resources('ListUserPolicies', options, :parser => BasicIamListParser, &block)
    end

    # Adds (or updates) a policy document associated with the specified User
    #
    #  iam.put_user_policy('kd', 'kd_user_policy_1', %Q({"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]})) #=> true
    #
    def put_user_policy(user_name, policy_name, policy_document)
      request_hash = { 'UserName'       => user_name,
                       'PolicyDocument' => policy_document,
                       'PolicyName'     => policy_name }
      link = generate_request_impl(:post, "PutUserPolicy", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Retrieves the specified policy document for the specified User.
    #
    #  iam.get_user_policy('kd','kd_user_policy_1') #=>
    #    {:user_name=>"kd",
    #     :policy_name=>"kd_user_policy_1",
    #     :policy_document=>"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}
    #
    def get_user_policy(user_name, policy_name)
      request_hash = { 'UserName'   => user_name,
                       'PolicyName' => policy_name }
      link = generate_request("GetUserPolicy", request_hash)
      result = request_info(link, GetUserPolicyParser.new(:logger => @logger))
      result[:policy_document] = URI::decode(result[:policy_document])
      result
    end

    # Deletes the specified policy associated with the specified User.
    #
    #  iam.delete_user_policy('kd','kd_user_policy_1') #=> true
    #
    def delete_user_policy(user_name, policy_name)
      request_hash = { 'UserName'   => user_name,
                       'PolicyName' => policy_name }
      link = generate_request("DeleteUserPolicy", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      User Groups
    #-----------------------------------------------------------------

    # Lists the names of the policies associated with the specified group. If there are none,
    # the action returns an empty list.
    #
    # Options: :max_items, :marker
    #
    #  iam.list_groups_for_user('kd') #=>
    #    [{:group_name=>"kd_test_1",
    #      :group_id=>"AGP000000000000000UTY",
    #      :arn=>"arn:aws:iam::640000000037:group/kd1/kd_test_1",
    #      :path=>"/kd1/"}]
    #
    def list_groups_for_user(user_name, options={}, &block)
      options[:user_name] = user_name
      incrementally_list_iam_resources('ListGroupsForUser', options, :parser => ListGroupsParser, &block)
    end

    # Adds the specified User to the specified group.
    #
    #  iam.add_user_to_group('kd', 'kd_test_1') #=> true
    #
    def add_user_to_group(user_name, group_name)
      request_hash = { 'UserName'  => user_name,
                       'GroupName' => group_name }
      link = generate_request("AddUserToGroup", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Removes the specified User from the specified group.
    #
    #  iam.remove_user_from_group('kd', 'kd_test_1') #=> true
    #
    def remove_user_from_group(user_name, group_name)
      request_hash = { 'UserName'  => user_name,
                       'GroupName' => group_name }
      link = generate_request("RemoveUserFromGroup", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      User Login Profiles
    #-----------------------------------------------------------------

    # Creates a login profile for the specified User, giving the User the ability to access
    # AWS services such as the AWS Management Console.
    #
    #  iam.create_login_profile('kd','q1w2e3r4t5') #=> { :user_name => 'kd' }
    #
    def create_login_profile(user_name, password)
      request_hash = { 'UserName' => user_name,
                       'Password' => password}
      link = generate_request("CreateLoginProfile", request_hash)
      request_info(link, GetLoginProfileParser.new(:logger => @logger))
    end

    # Updates the login profile for the specified User. Use this API to change the User's password.
    #
    #  update_login_profile('kd', '00000000') #=> true
    #
    def update_login_profile(user_name, options={})
      request_hash = { 'UserName' => user_name}
      request_hash['Password'] = options[:password] unless options[:passwrod].right_blank?
      link = generate_request("UpdateLoginProfile", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Retrieves the login profile for the specified User
    #
    #  iam.create_login_profile('kd','q1w2e3r4t5') #=> { :user_name => 'kd' }
    #
    def get_login_profile(user_name)
      request_hash = { 'UserName' => user_name }
      link = generate_request("GetLoginProfile", request_hash)
      request_info(link, GetLoginProfileParser.new(:logger => @logger))
    end

    # Deletes the login profile for the specified User, which terminates the User's ability to access
    # AWS services through the IAM login page.
    #
    #  iam.delete_login_profile('kd') #=> true
    #
    def delete_login_profile(user_name)
      request_hash = { 'UserName' => user_name }
      link = generate_request("DeleteLoginProfile", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS
    #-----------------------------------------------------------------

    class ListUsersParser < BasicIamListParser #:nodoc:
      def reset
        @expected_tags = %w{ Arn Path UserId UserName }
      end
    end

    class GetUserParser < BasicIamParser #:nodoc:
      def reset
        @expected_tags = %w{ Arn Path UserId UserName }
      end
    end

    class GetUserPolicyParser < BasicIamParser #:nodoc:
      def reset
        @expected_tags = %w{ PolicyDocument PolicyName UserName }
      end
    end

    class GetLoginProfileParser < BasicIamParser #:nodoc:
      def reset
        @expected_tags = %w{ UserName }
      end
    end

  end

end

