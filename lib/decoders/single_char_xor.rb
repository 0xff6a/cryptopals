module Decoder
  module SingleCharXOR
    module_function
    
    def decode(hex_s)
      buffer_size = hex_s.size / 2
      all_hex_chars.reduce(DecoderResult.new) do |result, hex_c|

        xord    = Hex::bitwise_xor(hex_s, hex_c * buffer_size)
        string  = Hex::to_ascii(xord)
        score   = Analyzer::TextScorer.calculate(string)
        
        if score < result.score
          result.plaintext = string
          result.score     = score
        end

        result
      end
    end

    private_class_method

    def all_hex_chars
      (0..255).to_a.map{ |b| b.chr.unpack('H*')[0] }
    end

    class DecoderResult
      INITIAL_SCORE =  1

      attr_accessor :plaintext, :score
      
      def initialize
        @score = INITIAL_SCORE
      end
    end
  end
end
