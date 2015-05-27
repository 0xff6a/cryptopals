require 'openssl'

module Encryption
  module AES
    module ECB
      module_function

      BLOCK_SIZE_BYTES = 16

      def encode(ascii_s, ascii_key)
        encrypter = build_cipher(:encrypt, ascii_key)

        encrypter.update(ascii_s) + encrypter.final
      end

      def decode(hex_s, hex_key)
        ciphertext, key = Hex.to_ascii(hex_s), Hex.to_ascii(hex_key)
        decrypter       = build_cipher(:decrypt, key)

        decrypter.update(ciphertext) + decrypter.final
      end

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