require 'openssl'
require 'base64'
require 'json'
require 'pp'

require 'java'
java_import java.security.cert.CertificateFactory
java_import java.security.cert.X509Certificate
java_import java.io.DataInputStream
java_import java.io.ByteArrayInputStream

java_import java.security.Signature
java_import java.security.KeyFactory

java_import org.bouncycastle.asn1.sec.SECNamedCurves
java_import org.bouncycastle.asn1.x9.X9ECParameters
java_import org.bouncycastle.jce.provider.BouncyCastleProvider
java_import org.bouncycastle.jce.spec.ECParameterSpec
java_import org.bouncycastle.jce.spec.ECPublicKeySpec
java_import org.bouncycastle.math.ec.ECPoint

# {"keyHandle":"2bX_4q55pUlkI4Q-70JePQqMwTYX6_-sZBFOBgpkwtzfEld8enbzVsnUCUS-UtV5WjAjRkPuV0ZmFxReZEjVKA",
# "clientData":"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoia1ItQVB0bXRHM0hZdUExZVhla3EwSlNIZkYxZS1nNm5tOFNxNHlWN3NTZyIsIm9yaWdpbiI6Imh0dHA6Ly91MmYtc2luYXRyYS4xMjcuMC4wLjEueGlwLmlvOjkyOTIiLCJjaWRfcHVia2V5IjoiIn0",
# "signatureData":"AQAAACgwRAIgReSy7TCJEBQVyGT77KRdL-1MIq4AUnLxzgCiamuGZwkCIBKjdXyfbKQR6Gs-HLSncnJnUY1Z5EW386EQ7_aTxGBt"}

# {"typ"=>"navigator.id.getAssertion",
# "challenge"=>"kR-APtmtG3HYuA1eXekq0JSHfF1e-g6nm8Sq4yV7sSg",
#    "origin"=>"http://u2f-sinatra.127.0.0.1.xip.io:9292",
#    "cid_pubkey"=>""}

module U2F
  class AuthenticationResponse
    attr_reader :hash, :client_data

    def initialize(authentication_response_hash, options={  })
      @hash = authentication_response_hash
      @options = options
      @challenge = options[:challenge]
      @app_id = options[:origin]
      @pk_bytes = options[:public_key]
      @key_handle = options[:key_handle]
      attempt_client_data_decode
      attempt_signature_data_decode
    end

    def matching_challenge?
      @challenge == client_data['challenge']
    end

    def matching_appid_and_origin?
      @app_id == client_data['appId']
    end

    def matching_key_handle?
      hash['keyHandle'] == key_handle
    end

    def valid_signature?
      sig = Signature.getInstance("SHA256withECDSA")
      sig.init_verify public_key
      sig.update signed_bytes
      sig.verify hash['signatureData']
    end

    private

    def public_key
      return @public_key if defined? @public_key
      curve = SECNamedCurves.getByName("secp256r1")
      point = curve.get_curve.decode_point @pk_bytes.to_java_bytes

      parameters = ECParameterSpec.new(curve.get_curve,
                                       curve.get_g,
                                       curve.get_n,
                                       curve.get_h)
      key_spec = ECPublicKeySpec.new point, parameters

      @public_key = KeyFactory.
          get_instance('ECDSA').
          generate_public(key_spec)
    end

    def signed_bytes
      [sha256(@app_id),
       @user_present,
       @counter,
       sha256(hash['clientData'])].join
    end

    def attempt_client_data_decode
      begin
        @raw_client_data = Base64.urlsafe_decode64 hash['clientData']
        return @client_data = JSON.parse(@raw_client_data)
      rescue JSON::ParserError
      end

      begin
        @raw_client_data = Base64.urlsafe_decode64(hash['clientData'] + '=')
        return @client_data = JSON.parse(@raw_client_data)
      rescue JSON::ParserError
      end

      @raw_client_data = Base64.urlsafe_decode64(hash['clientData'] + '==')
      return @client_data = JSON.parse(@raw_client_data)
    end

    def attempt_signature_data_decode
      bytes = Base64.decode64 hash['signatureData']
      @user_present = bytes[0].ord
      @counter = bytes[1..4].unpack 'l>'
      @sig = bytes[5..-1]
    end

    def sha256(bytes)
      Digest::SHA256.digest bytes
    end
  end
end
