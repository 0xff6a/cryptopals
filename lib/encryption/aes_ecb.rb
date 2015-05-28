require 'openssl'

require_relative 'aes'
require_relative '../utils/pkcs7'

module Encryption
  module AES
    module ECB
      module_function

      extend AES

      def encode(ascii_s, ascii_key)
        ascii_s   = PKCS7.pad_aes(ascii_s)
        encrypter = build_cipher(:encrypt, ascii_key)

        Ascii.to_hex(encrypter.update(ascii_s) + encrypter.final)
      end

      def decode(hex_s, hex_key)
        ciphertext = Hex.to_ascii(PKCS7.trim_aes(hex_s))
        key        = Hex.to_ascii(hex_key)
        decrypter  = build_cipher(:decrypt, key)

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