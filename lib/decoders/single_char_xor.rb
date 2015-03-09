module Decoder
  module SingleCharXOR
    module_function
    INITIAL_SCORE =  1

    def decode(hex_s)
      result, best_score = "", 1

      all_hex_chars.each do |hex_c|
        xord    = Hex::bitwise_xor(hex_s, hex_c * (hex_s.size / 2))
        string  = Hex::to_ascii(xord)
        score   = TextScorer.calculate(string)
        
        if score < best_score
          result      = string
          best_score  = score
        end
      end
      result
    end

    def all_hex_chars
      (0..255).to_a.map{ |b| b.chr.unpack('H*')[0] }
    end
  end
end
