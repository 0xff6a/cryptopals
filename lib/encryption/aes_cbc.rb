require 'openssl'

require_relative 'aes'
require_relative 'aes_ecb'
require_relative  '../utils/ascii'
require_relative  '../utils/hex'
require_relative  '../utils/pkcs7'

module Encryption
  module AES
    module CBC
      module_function
      
      extend AES::ECB
      extend AES

      def encode(ascii_s, ascii_key, ascii_iv)
        # Encrypt block by block
        # -> c[0] = E(k, m[0] ⨁ IV)
        # -> c[1] = E(k, m[1] ⨁ c[0])
        # -> .....
        ascii_s   = PKCS7.pad_aes(ascii_s)
        blocks    = Ascii.chunk(ascii_s, BLOCK_SIZE_BYTES)
        encrypter = build_cipher(:encrypt, ascii_key)
        
        encrypted_blocks = blocks.map do |b|
          b        = Ascii.bitwise_xor(b, ascii_iv)
          c        = encrypter.update(b) + encrypter.final
          ascii_iv = c
        end

        Ascii.to_hex(encrypted_blocks.join(''))
      end

      def decode(hex_s, hex_key, hex_iv)
        # Decrypt block by block
        # -> m[0] = D(k, c[0]) ⨁ IV 
        # -> m[1] = D(k, c[1]) ⨁ c[0]
        # -> .....
        ct        = Hex.to_ascii(PKCS7.trim_aes(hex_s))
        k         = Hex.to_ascii(hex_key)
        iv        = Hex.to_ascii(hex_iv) 

        blocks    = Ascii.chunk(ct, BLOCK_SIZE_BYTES)
        decrypter = build_cipher(:decrypt, k)
  
        decrypted_blocks = blocks.map do |b|
         m  = decrypter.update(b) + decrypter.final
         m  = Ascii.bitwise_xor(m, iv)
         iv = b
         m
        end

        decrypted_blocks.join('')
      end
      
    end
  end
end