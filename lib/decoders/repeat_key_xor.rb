module Decoder
  module RepeatKeyXOR
    module_function
    # Key size in bytes
    KEY_SIZE_MIN         = 2
    KEY_SIZE_MAX         = 40

    def decode(hex_s, key)
    end

    def guess_key(hex_s)
      buffer = hex_s.bytes
      # Find the keysize
      sample   = buffer.first(KEY_SIZE_MAX * 2)
      key_size = guess_keysize(sample)
      
      # Break ciphertext into blocks of keysize length
      buffer.each_slice(key_size) do |block|
      # Transpose blocks - make a block that is first byte of every block, 
      # a block that is the second etc...

      end
      # Solve each block (1st byte, second byte etc) using single char XOR
      byte_blocks.each.reduce("") do
        # return the single character XOR key
      end
      # For each block the single byte key that produces best score is single byte key
      # Put each byte key together to get the document key
    end

    private_class_method

    def advanced_guess_keysize(bytes)
      # Do keysize twice on different blocks
      # Average score
      # Return keysize with smallest average distance
    end

    def guess_keysize(bytes)
      all_keysizes.reduce(KeysizeGuess.new) do |result, size|
        chunks  = bytes.shift(size), bytes.shift(size)
        norm_hd = Analyzer::HammingDistance.from_bytes(*chunks) / size.to_f
        
        if norm_hd < result.hamming_distance
          result.size             = size
          result.hamming_distance = norm_hd
        end
        result
      end
    end

    def all_keysizes
      (KEY_SIZE_MIN..KEY_SIZE_MAX).to_a
    end

    class KeysizeGuess
      # Number of bits in max key size
      MAX_HAMMING_DISTANCE = KEY_SIZE_MAX * 8

      attr_accessor :size, :hamming_distance

      def initialize
        @hamming_distance = MAX_HAMMING_DISTANCE
      end
    end
  end
end