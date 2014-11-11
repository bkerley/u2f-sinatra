module U2F
  class AuthenticationRequest
    attr_reader :key_handle, :origin
    
    def initialize(key_handle, origin)
      @key_handle = key_handle
      @origin = origin
    end

    def challenge
      @challenge ||= SecureRandom.urlsafe_base64(32)
    end

    def as_json
      { 
        keyHandle: key_handle,
        challenge: challenge,
        appId: origin,
        version: 'U2F_V2'
      }
    end
  end
end
