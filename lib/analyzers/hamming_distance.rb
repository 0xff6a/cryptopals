require_relative '../encoding/bytes'
require_relative '../encoding/hex'

module Analyzer
  module HammingDistance
    module_function

    def from_ascii(s1, s2)
      from_bytes(
        s1.bytes,
        s2.bytes
      )
    end

    def from_hex(h1, h2)
     from_bytes(
        Hex.to_bytes(h1),
        Hex.to_bytes(h2)
      )
    end

    def from_bytes(b1, b2)
      Bytes.to_bin(
        Bytes.xor(b1, b2)
      ).count("1")
    end
  end
end