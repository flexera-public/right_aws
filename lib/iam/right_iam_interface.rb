#
# Copyright (c) 2007-2010 RightScale Inc
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

  # = RightAWS::Iam -- RightScale AWS Identity and Access Management (IAM) interface
  #
  # The RightAws::Iam class provides a complete interface to Amazon's Identity and
  # Access Management service.
  #
  # For explanations of the semantics of each call, please refer to Amazon's documentation at
  # http://aws.amazon.com/documentation/iam/
  #
  # Examples:
  #
  # Create an EC2 interface handle:
  #
  #   iam = RightAws::IamInterface.new(aws_access_key_id, aws_secret_access_key)
  #   iam.list_access_keys
  #   iam.list_users
  #   iam.list_groups
  #
  class IamInterface < RightAwsBase
    include RightAwsBaseInterface

    API_VERSION       = "2010-05-08"
    DEFAULT_HOST      = "iam.amazonaws.com"
    DEFAULT_PATH      = '/'
    DEFAULT_PROTOCOL  = 'https'
    DEFAULT_PORT      = 443

    @@bench = AwsBenchmarkingBlock.new
    def self.bench_xml
      @@bench.xml
    end
    def self.bench_service
      @@bench.service
    end

    # Create a new handle to an IAM account. All handles share the same per process or per thread
    # HTTP connection to Amazon IAM. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol). 
    # * <tt>:server</tt>: IAM service host, default: DEFAULT_HOST
    # * <tt>:port</tt>: IAM service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    # * <tt>:signature_version</tt>:  The signature version : '0','1' or '2'(default)
    # * <tt>:cache</tt>: true/false(default): caching works for: describe_load_balancers
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'IAM',
             :default_host        => ENV['IAM_URL'] ? URI.parse(ENV['IAM_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['IAM_URL'] ? URI.parse(ENV['IAM_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['IAM_URL'] ? URI.parse(ENV['IAM_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['IAM_URL'] ? URI.parse(ENV['IAM_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['IAM_API_VERSION'] || API_VERSION },
           aws_access_key_id    || ENV['AWS_ACCESS_KEY_ID'] ,
           aws_secret_access_key|| ENV['AWS_SECRET_ACCESS_KEY'],
           params)
    end

    def generate_request(action, params={}) #:nodoc:
      generate_request_impl(:get, action, params )
    end

    # Sends request to Amazon and parses the response
    # Raises AwsError if any banana happened
    def request_info(request, parser)  #:nodoc:
      request_info_impl(:iam_connection, @@bench, request, parser)
    end

    # Options: :parser, :except, :items
    #
    def incrementally_list_iam_resources(api_function, params={}, options={},  &block) #:nodoc:
      items        = options[:items] || :items
      result       = { items => [] }
      parser       = options[:parser] || "RightAws::IamInterface::#{api_function}Parser".right_constantize
      request_hash = {}
      params.each { |key,value| request_hash[key.to_s.right_camelize] = value unless value.right_blank? }
      incrementally_list_items(api_function, parser, request_hash) do |response|
        if result[items].right_blank?
          result = response
        else
          result[items] += response[items]
        end
        block ? block.call(response) : true
      end
      if options[:except]
        Array(options[:except]).each{ |key| result.delete(key)}
        result
      else
        result[items]
      end
    end
    
    #-----------------------------------------------------------------
    #      Server Certificates
    #-----------------------------------------------------------------

    # Lists the server certificates that have the specified path prefix. If none exist, the action returns an empty list.
    #
    # Options: :path_prefix, :max_items, :marker
    #
    #  iam.list_server_certificates #=>
    #    {:server_certificate_id=>"ASCDJN5K5HRGS1N2UJWWU",
    #     :server_certificate_name=>"KdCert1",
    #     :upload_date=>"2010-12-09T13:21:07.226Z",
    #     :path=>"/kdcert/",
    #     :arn=>"arn:aws:iam::600000000007:server-certificate/kdcert/KdCert1"}
    #
    def list_server_certificates(options={}, &block)
      incrementally_list_iam_resources('ListServerCertificates', options, &block)
    end

    # Uploads a server certificate entity for the AWS Account. The server certificate
    # entity includes a public key certificate, a private key, and an optional certificate
    # chain, which should all be PEM-encoded.
    #
    # Options: :certificate_chain, :path
    #
    #  certificate_body =<<-EOB
    #  -----BEGIN CERTIFICATE-----
    #  MIICdzCCAeCgAwIBAgIGANc+Ha2wMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNVBAYT
    #  AlVTMRMwEQYDVQQKEwpBbWF6b24uY29tMQwwCgYDVQQLEwNBV1MxITAfBgNVBAMT
    #  GEFXUyBMaW1pdGVkLUFzc3VyYW5jZSBDQTAeFw0wOTAyMDQxNzE5MjdaFw0xMDAy
    #  AEaHzTpmEXAMPLE=
    #  EOB
    #
    #  private_key =<<EOK
    #  -----BEGIN DSA PRIVATE KEY-----
    #  MIIBugIBTTKBgQD33xToSXPJ6hr37L3+KNi3/7DgywlBcvlFPPSHIw3ORuO/22mT
    #  8Cy5fT89WwNvZ3BPKWU6OZ38TQv3eWjNc/3U3+oqVNG2poX5nCPOtO1b96HYX2mR
    #  62TITdw53KWJEXAMPLE=
    #  EOK
    #
    #  iam.upload_server_certificate('KdCert1', certificate_body, private_key, :path=>'/kdcert/') #=>
    #    {:server_certificate_id=>"ASCDJN5K5HRGS1N2UJWWU",
    #     :server_certificate_name=>"KdCert1",
    #     :upload_date=>"2010-12-09T13:21:07.226Z",
    #     :path=>"/kdcert/",
    #     :arn=>"arn:aws:iam::600000000007:server-certificate/kdcert/KdCert1"}
    #
    def upload_server_certificate(server_certificate_name, certificate_body, private_key, options={})
      request_hash = { 'CertificateBody'       => certificate_body,
                       'PrivateKey'            => private_key,
                       'ServerCertificateName' => server_certificate_name }
      request_hash['CertificateChain'] = options[:certificate_chain] unless options[:certificate_chain].right_blank?
      request_hash['Path']             = options[:path]              unless options[:path].right_blank?
      link = generate_request_impl(:post, "UploadServerCertificate", request_hash)
      request_info(link, GetServerCertificateParser.new(:logger => @logger))
    end
    
    # Updates the name and/or the path of the specified server certificate.
    #
    # Options: :new_server_certificate_name, :new_path
    #
    #  iam.update_server_certificate('ProdServerCert', :new_server_certificate_name => 'OldServerCert') #=> true
    #
    def update_server_certificate(server_certificate_name, options={})
      request_hash = { 'ServerCertificateName' => server_certificate_name}
      request_hash['NewServerCertificateName'] = options[:new_server_certificate_name] unless options[:new_server_certificate_name].right_blank?
      request_hash['NewPath']                  = options[:new_path]                    unless options[:new_path].right_blank?
      link = generate_request("UpdateServerCertificate", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Retrieves information about the specified server certificate.
    #
    #  iam.get_server_certificate('KdCert1')
    #    {:certificate_body=>
    #      "-----BEGIN CERTIFICATE-----\nMIICATC...TiU5TibMpD1g==\n-----END CERTIFICATE-----",
    #     :server_certificate_id=>"ASCDJN5K5HRGS1N2UJWWU",
    #     :server_certificate_name=>"KdCert1",
    #     :upload_date=>"2010-12-09T13:21:07Z",
    #     :path=>"/kdcert/",
    #     :certificate_chain=>"",
    #     :arn=>"arn:aws:iam::600000000007:server-certificate/kdcert/KdCert1"}
    #
    def get_server_certificate(server_certificate_name)
      request_hash = { 'ServerCertificateName' => server_certificate_name}
      link = generate_request("GetServerCertificate", request_hash)
      request_info(link, GetServerCertificateParser.new(:logger => @logger))
    end

    # Deletes the specified server certificate
    #
    #  iam.delete_server_certificate('ProdServerCert') #=> true
    #
    def delete_server_certificate(server_certificate_name)
      request_hash = { 'ServerCertificateName' => server_certificate_name }
      link = generate_request("DeleteServerCertificate", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      Signing Certificates
    #-----------------------------------------------------------------

    # Returns information about the signing certificates associated with the specified User.
    # 
    # Options: :user_name, :max_items, :marker
    #
    # iam.list_signing_certificates #=>
    #    [{:upload_date      => "2007-08-11T06:48:35Z",
    #      :status           => "Active",
    #      :certificate_id   => "00000000000000000000000000000000",
    #      :certificate_body => "-----BEGIN CERTIFICATE-----\nMIICd...PPHQ=\n-----END CERTIFICATE-----\n"}]
    #
    def list_signing_certificates(options={}, &block)
      incrementally_list_iam_resources('ListSigningCertificates', options, &block)
    end

    # Uploads an X.509 signing certificate and associates it with the specified User.
    #
    # Options: :user_name
    #
    #  certificate_body =<<-EOB
    #  -----BEGIN CERTIFICATE-----
    #  MIICdzCCAeCgAwIBAgIGANc+Ha2wMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNVBAYT
    #  AlVTMRMwEQYDVQQKEwpBbWF6b24uY29tMQwwCgYDVQQLEwNBV1MxITAfBgNVBAMT
    #  GEFXUyBMaW1pdGVkLUFzc3VyYW5jZSBDQTAeFw0wOTAyMDQxNzE5MjdaFw0xMDAy
    #  AEaHzTpmEXAMPLE=
    #  EOB
    #
    #  iam.upload_signing_certificate(certificate_body, :user_name => 'kd1') #=>
    #    {:user_name        => "kd1",
    #     :certificate_id   => "OBG00000000000000000000000000DHY",
    #     :status           => "Active",
    #     :certificate_body => "-----BEGIN CERTIFICATE-----\nMII...5GS\n-----END CERTIFICATE-----\n",
    #     :upload_date      => "2010-10-29T10:02:05.929Z"}
    #
    def upload_signing_certificate(certificate_body, options={})
      request_hash = { 'CertificateBody' => certificate_body }
      request_hash['UserName'] = options[:user_name] unless options[:user_name].right_blank?
      link = generate_request_impl(:post, "UploadSigningCertificate", request_hash)
      request_info(link, GetSigningCertificateParser.new(:logger => @logger))
    end

    # Deletes the specified signing certificate associated with the specified User.
    #
    # Options: :user_name
    #
    #  pp iam.delete_signing_certificate('OB0000000000000000000000000000HY', :user_name => 'kd1')
    #
    def delete_signing_certificate(certificate_id, options={})
      request_hash = { 'CertificateId' => certificate_id }
      request_hash['UserName'] = options[:user_name] unless options[:user_name].right_blank?
      link = generate_request("DeleteSigningCertificate", request_hash)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS:
    #-----------------------------------------------------------------

    class BasicIamParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @result ||= {}
      end
      def tagend(name)
        if Array(@expected_tags).include?(name)
          @result[name.right_underscore.to_sym] = @text
        end
      end
    end

    class BasicIamListParser < RightAWSParser #:nodoc:
      def tagstart(name, attributes)
        @result ||= { :items => [] }
        @item     = {} if name == (@items_splitter || 'member')
      end
      def tagend(name)
        case name
        when 'Marker'      then @result[:marker]       = @text
        when 'IsTruncated' then @result[:is_truncated] = @text == 'true'
        when (@items_splitter || 'member')
          @result[:items] << (@item.right_blank? ? @text : @item)
        else
          if Array(@expected_tags).include?(name)
            @item[name.right_underscore.to_sym] = @text
          end
        end
      end
    end

    #-----------------------------------------------------------------
    #      Server Certificates
    #-----------------------------------------------------------------

    class GetServerCertificateParser < BasicIamParser #:nodoc:
      def reset
        @expected_tags = %w{ Arn Path ServerCertificateId ServerCertificateName UploadDate CertificateBody CertificateChain }
      end
    end

    class ListServerCertificatesParser < BasicIamListParser #:nodoc:
      def reset
        @expected_tags = %w{ Arn Path ServerCertificateId ServerCertificateName UploadDate }
      end
    end

    #-----------------------------------------------------------------
    #      Signing Certificates
    #-----------------------------------------------------------------

    class ListSigningCertificatesParser < BasicIamListParser #:nodoc:
      def reset
        @expected_tags = %w{ CertificateBody CertificateId Status UploadDate UserName }
      end
    end

    class GetSigningCertificateParser < BasicIamParser #:nodoc:
      def reset
        @expected_tags = %w{ CertificateBody CertificateId Status UploadDate UserName }
      end
    end

  end

end
