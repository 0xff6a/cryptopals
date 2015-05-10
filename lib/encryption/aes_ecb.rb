require 'openssl'

module Encryption
  module AES
    module ECB
      module_function

      def is_used_for?(hex_s)
        # return true if the ciphertext is encrypted in ECB, false otherwise
        # guess keysize
        # count number of cipher blocks repeated
        # if > 1 return true
      end

      def decode(hex_s, hex_key)
        plaintext, key  = Hex.to_ascii(hex_s), Hex.to_ascii(hex_key)
        decrypter       = build_cipher(:decrypt, key)

        decrypter.update(plaintext) + decrypter.final
      end

      private_class_method

      def build_cipher(type, key)
        cipher         =  OpenSSL::Cipher::AES128.new(:ECB)
        cipher.public_send(type)
        cipher.key     = key
        cipher.padding = 0
        cipher
      end
    end
  end
end