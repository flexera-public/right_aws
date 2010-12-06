module RightAws

  class IamInterface < RightAwsBase

    #-----------------------------------------------------------------
    #      MFADevices
    #-----------------------------------------------------------------

    # Lists the MFA devices associated with the specified User name.
    #
    # Options: :user_name, :max_items, :marker
    #
    def list_mfa_devices(options={}, &block)
      incrementally_list_iam_resources('ListMFADevices', options, &block)
    end

    # Enables the specified MFA device and associates it with the specified User name.
    # Once enabled, the MFA device is required for every subsequent login by the User name associated with the device.
    #
    #  iam.enable_mfa_device('kd1', 'x12345', '12345', '67890') #=> true
    #
    def enable_mfa_device(user_name, serial_number, auth_code1, auth_code2)
      request_hash = { 'UserName'            => user_name,
                       'SerialNumber'        => serial_number,
                       'AuthenticationCode1' => auth_code1,
                       'AuthenticationCode2' => auth_code2 }
      link = generate_request("EnableMFADevice", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Synchronizes the specified MFA device with AWS servers.
    #
    #  iam.resync_mfa_device('kd1', 'x12345', '12345', '67890') #=> true
    #
    def resync_mfa_device(user_name, serial_number, auth_code1, auth_code2)
      request_hash = { 'UserName'            => user_name,
                       'SerialNumber'        => serial_number,
                       'AuthenticationCode1' => auth_code1,
                       'AuthenticationCode2' => auth_code2 }
      link = generate_request("ResyncMFADevice", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Deactivates the specified MFA device and removes it from association with the User name for which it was originally enabled.
    #
    #  deactivate_mfa_device('kd1', 'dev1234567890') #=> true
    #
    def deactivate_mfa_device(user_name, serial_number)
      request_hash = { 'UserName'     => user_name,
                       'SerialNumber' => serial_number }
      link = generate_request("DeactivateMFADevice", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS
    #-----------------------------------------------------------------

    class ListMFADevicesParser < BasicIamListParser #:nodoc:
      def reset
        @expected_tags = %w{ SerialNumber UserName }
      end
    end

  end

end