module RightAws

  class IamInterface < RightAwsBase

    #-----------------------------------------------------------------
    #      Access Keys
    #-----------------------------------------------------------------

    # Returns information about the Access Key IDs associated with the specified User.
    #
    # Options: :user_name, :max_items, :marker
    #
    #  iam.list_access_keys #=>
    #    [{:create_date=>"2007-01-09T06:16:30Z",
    #      :status=>"Active",
    #      :access_key_id=>"00000000000000000000"}]
    #
    def list_access_keys(options={}, &block)
      incrementally_list_iam_resources('ListAccessKeys', options, &block)
    end

    # Creates a new AWS Secret Access Key and corresponding AWS Access Key ID for the specified User.
    #
    # Options: :user_name
    #
    #  iam.create_access_key(:user_name => 'kd1') #=>
    #    {:access_key_id=>"AK0000000000000000ZQ",
    #     :status=>"Active",
    #     :secret_access_key=>"QXN0000000000000000000000000000000000Ioj",
    #     :create_date=>"2010-10-29T07:16:32.210Z",
    #     :user_name=>"kd1"}
    #
    def create_access_key(options={})
      request_hash = {}
      request_hash['UserName'] = options[:user_name] unless options[:user_name].right_blank?
      link = generate_request("CreateAccessKey", request_hash)
      request_info(link, CreateAccessKeyParser.new(:logger => @logger))
    end

    # Deletes the access key associated with the specified User.
    #
    # Options: :user_name
    #
    #  iam.delete_access_key('AK00000000000000006A', :user_name => 'kd1') #=> true
    #
    def delete_access_key(access_key_id, options={})
      request_hash = { 'AccessKeyId' => access_key_id }
      request_hash['UserName'] = options[:user_name] unless options[:user_name].right_blank?
      link = generate_request("DeleteAccessKey", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS
    #-----------------------------------------------------------------

    class ListAccessKeysParser < BasicIamListParser #:nodoc:
      def reset
        @expected_tags = %w{ AccessKeyId CreateDate Status UserName }
      end
    end

    class CreateAccessKeyParser < BasicIamParser #:nodoc:
      def reset
        @expected_tags = %w{ AccessKeyId CreateDate SecretAccessKey Status UserName }
      end
    end

  end

end