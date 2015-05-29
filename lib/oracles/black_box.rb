# encoding: BINARY

require 'securerandom'
require 'base64'

require_relative '../encryption/aes_ecb.rb'
require_relative 'aes'

module Oracle
  module AES
    class BlackBox
      include Oracle::AES

      def initialize(b64_s)
        @unknown_s = b64_s
        @key       = random_block
      end

      def encode(ascii_s)
        plaintext = ascii_s + target_s

        Encryption::AES::ECB.encode(plaintext, @key)
      end

      def encode_with_prefix(ascii_s)
        prefix = SecureRandom.random_bytes(100)

        encode(prefix + ascii_s)
      end

      def bytes_len
        ciphertext.size / 2
      end

      def ciphertext
        encode('')
      end

      private

      def target_s
        @target_s ||= Base64.decode64(@unknown_s)
      end
    end
  end
end
