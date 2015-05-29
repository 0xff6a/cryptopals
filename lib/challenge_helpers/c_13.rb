require_relative '../oracles/aes'
require 'cgi'

module ChallengeHelpers
  module_function

  ELEMENT_DELIM = '&'
  VALUE_DELIM   = '='
  EMAIL_REGEXP  = /\A[^@]+@([^@\.]+\.)+[^@\.]+\z/

  def kv_parse(url_s)
    elements = url_s.split(ELEMENT_DELIM)

    Hash[elements.map { |el| 
      k,v = el.split(VALUE_DELIM)
      [ k.to_sym, v ]
    }]
  end

  def profile_for(email)
    raise ArgumentError, 'Invalid email' unless email =~ EMAIL_REGEXP

    "email=#{email.split('&').first}&" +
    "uid=10&" +
    "role=user"
  end

  def encrypted_profile_for(email, key)
    profile_s = profile_for(email)

    Encryption::AES::ECB.encode(profile_s, key)
  end

  def decrypt_profile(ciphertext, key)
    url_s = Encryption::AES::ECB.decode(ciphertext, key)

    kv_parse(url_s)
  end
end
