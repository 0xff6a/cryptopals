require_relative '../encoding/ascii'

module Analyzer
  module HammingDistance
    module_function

    def calculate(s1, s2)
      Ascii.to_bin(
        Ascii::bitwise_xor(
          s1,s2
        )
      ).count("1")
    end

  end
end