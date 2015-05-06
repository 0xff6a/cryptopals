require_relative 'single_char_xor'

module Decoder
  module RepeatKeyXOR
    module_function

    KEY_SIZE_MIN  = 5
    KEY_SIZE_MAX  = 40

    def decode(hex_s, hex_key)
      cipher_blocks = chunk(hex_s, hex_key.size)

      plain_blocks = cipher_blocks.map do |block|
        Hex.bitwise_xor(block, hex_key)
      end

      Hex.to_ascii(plain_blocks.join(''))
    end 

    def guess_key(hex_s)
      key_size = advanced_guess_keysize(Hex.to_bytes(hex_s))
      blocks   = hex_char_chunks(hex_s, key_size)

      blocks.pop
      blocks = blocks.transpose

      key_chars = blocks.map do |block|
        Decoder::SingleCharXOR.decode(block.join(''))
      end

      key_chars.map(&:key).join('')
    end

    private_class_method

    def advanced_guess_keysize(bytes)
      blocks = bytes.each_slice(KEY_SIZE_MAX * 2).to_a
      blocks.pop
      guesses = blocks.map { |block| guess_keysize(block) }

      mode(guesses.map(&:value))
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

    def mode(fixnum_arr)
      fixnum_arr.group_by{|i| i}.max{|x,y| x[1].length <=> y[1].length}[0]
    end

    def chunk(string, block_size)
      string.chars.each_slice(block_size).map { |block_chars| block_chars.join('') }
    end

    def hex_char_chunks(string, block_size)
      string.scan(/../).each_slice(block_size).to_a
    end

    class KeysizeGuess
      MAX_HAMMING_DISTANCE = KEY_SIZE_MAX * 8

      attr_accessor :value, :hamming_distance

      def initialize
        @hamming_distance = MAX_HAMMING_DISTANCE
      end
    end
  end
end