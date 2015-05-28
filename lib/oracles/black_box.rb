require 'base64'
require_relative '../encryption/aes_ecb.rb'
require_relative 'aes'

module Oracle
  module AES

    class BlackBox
      include Oracle::AES

      def initialize(b64_s)
        @unknown_s = Base64.decode64(b64_s)
        @key       = random_block
      end

      def encode(ascii_s)
        plaintext = ascii_s + @unknown_s
        
        Encryption::AES::ECB.encode(plaintext, @key)
      end
    end
  end
end
