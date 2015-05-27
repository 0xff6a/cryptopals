module Oracle
  module AES
    module ECB
      module_function

      KEY_SIZE_BYTES = 16

      def detected?(hex_s)
        key_size_match?(hex_s) && repeated_blocks?(hex_s)
      end

      private_class_method

      def key_size_match?(hex_s)
        buffer   = Hex.to_bytes(hex_s)
        key_size = Encryption::RepeatKeyXOR.advanced_guess_keysize(buffer)

        key_size.between?(KEY_SIZE_BYTES - 1, KEY_SIZE_BYTES + 1)
      end

      def repeated_blocks?(hex_s)
        blocks = hex_s.scan(/../).each_slice(KEY_SIZE_BYTES).to_a
        
        blocks.uniq.size != blocks.size
      end

    end
  end
end 