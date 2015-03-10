require_relative '../encoding/bytes'

module Analyzer
  module HammingDistance
    module_function

    def calculate(s1, s2)
      # Using string methods for efficiency
      # Convert to bytes, xor bytes, convert to binary and count 1s
      Bytes::to_bin(
        Bytes::xor(
          s1.bytes,
          s2.bytes
        )
      ).count("1")
    end

  end
end