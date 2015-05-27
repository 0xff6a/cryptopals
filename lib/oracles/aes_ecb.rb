require_relative '../encryption/repeat_key_xor'
require_relative '../encryption/aes_ecb'
require_relative '../utils/hex'

module Oracle
  module AES
    module ECB
      module_function

      BLOCK_SIZE_BYTES = Encryption::AES::ECB::BLOCK_SIZE_BYTES

      def detected?(hex_s)
        key_size_match?(hex_s) && repeated_blocks?(hex_s)
      end

      private_class_method

      def key_size_match?(hex_s)
        buffer   = Hex.to_bytes(hex_s)
        key_size = Encryption::RepeatKeyXOR.advanced_guess_keysize(buffer)

        key_size.between?(BLOCK_SIZE_BYTES - 1, BLOCK_SIZE_BYTES + 1)
      end

      def repeated_blocks?(hex_s)
        blocks = hex_s.scan(/../).each_slice(BLOCK_SIZE_BYTES).to_a
        
        blocks.uniq.size != blocks.size
      end

    end
  end
end 