require_relative 'single_char_xor'

module Decoder
  module RepeatKeyXOR
    module_function
    # Key size in bytes
    KEY_SIZE_MIN           = 5
    KEY_SIZE_MAX           = 40

    def decode(hex_s, hex_key)
      blocks = hex_s.chars.each_slice(hex_key.size).map { |block_chars| block_chars.join('') }

      plain_blocks = blocks.map do |block|
        Hex.bitwise_xor(block, hex_key)
      end

      Hex.to_ascii(plain_blocks.join(''))
    end 

    def guess_key(hex_s)
      buffer = Hex.to_bytes(hex_s)
      
      # Find the keysize
      key_size = advanced_guess_keysize(buffer)
      
      # Break ciphertext into blocks of keysize length
      same_key_blocks = hex_s.scan(/../).each_slice(key_size).to_a

      # Drop the last block which might be padded
      same_key_blocks.pop

      # Transpose blocks - make a block that is first byte of every block, 
      # a block that is the second etc...
      same_key_blocks = same_key_blocks.transpose

      # Solve each block (1st byte, second byte etc) using single char XOR
      key_chars = same_key_blocks.map do |block|
        Decoder::SingleCharXOR.decode(block.join(''))
      end

      # Put each byte key together to get the document key
      key_chars.map(&:key).join('')
    end

    private_class_method

    def advanced_guess_keysize(bytes)
      guesses = bytes.each_slice(KEY_SIZE_MAX * 2).to_a
      guesses.pop
      guesses = guesses.map { |block| guess_keysize(block) }

      guesses.map(&:value).group_by{|i| i}.max{|x,y| x[1].length <=> y[1].length}[0]
    end

    def guess_keysize(bytes)
      all_keysizes.reduce(KeysizeGuess.new) do |result, size|
        chunks  = bytes.each_slice(size).first(2)
        norm_hd = Analyzer::HammingDistance.from_bytes(*chunks) / size.to_f
        
        if norm_hd < result.hamming_distance
          result.value            = size
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

      attr_accessor :value, :hamming_distance

      def initialize
        @hamming_distance = MAX_HAMMING_DISTANCE
      end
    end
  end
end