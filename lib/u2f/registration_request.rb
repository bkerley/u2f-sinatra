require 'openssl'
require 'securerandom'

module U2F
  class RegistrationRequest
    attr_reader :origin

    def initialize(origin)
      @origin = origin
    end

    def challenge
      @challenge ||= SecureRandom.urlsafe_base64(32)
    end

    def as_json
      { 
        challenge: challenge,
        appId: origin,
        version: 'U2F_V2'
      }
    end
  end
end

