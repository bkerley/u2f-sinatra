require 'openssl'
require 'base64'
require 'json'

require 'java'
java_import java.security.cert.CertificateFactory
java_import java.security.cert.X509Certificate
java_import java.io.DataInputStream
java_import java.io.ByteArrayInputStream

module U2F
  class RegistrationResponse
    attr_reader :hash
    def initialize(registration_response_hash, options={  })
      @hash = registration_response_hash
      @options = options
      @registration_data = Base64.decode64 hash['registrationData']
      @challenge = options[:challenge]
      @version = hash['version']
      @app_id = options[:origin]
      @client_data = JSON.parse Base64.decode64 hash['clientData']
    end

    def matching_challenge?
      @challenge == hash['challenge']
    end

    def matching_appid_and_origin?
      @app_id == hash['appId']
    end

    def user_public_key
      decoded_registration_data[:user_public_key]
    end

    def key_handle_length
      decoded_registration_data[:key_handle_length]
    end

    def key_handle
      decoded_registration_data[:key_handle]
    end

    def attestation_certificate
      @attestation_certificate ||= 
        OpenSSL::X509::Certificate.new decoded_registration_data[:cert]
    end

    def decoded_registration_data
      return @decoded_registration_data if defined? @decoded_registration_data

      io = DataInputStream.new ByteArrayInputStream.new @registration_data.to_java_bytes

      h = {  }

      reserved = io.read_byte
      raise 'malformed' unless reserved == 5

      h[:user_public_key] = upk = ("\0"*65).to_java_bytes
      io.read_fully upk
      h[:key_handle_length] = key_handle_length = io.read_unsigned_byte
      h[:key_handle] = kh = ("\0"*key_handle_length).to_java_bytes
      io.read_fully kh

      puts io.available()

      x509_factory = CertificateFactory.get_instance 'X.509'

      cert = x509_factory.generate_certificate(io)

      h[:cert] = cert
      h[:signature] = sig = ("\0"*io.available()).to_java_bytes

      io.read_fully sig

      @decoded_registration_data = h
    end
  end
end
