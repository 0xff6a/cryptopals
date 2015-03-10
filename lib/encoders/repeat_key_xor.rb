require 'encoding/bytes'

module Encoder
  module RepeatKeyXOR
    module_function

    def encode_to_hex(string, key)
      Bytes.to_hex(encode(string, key))
    end

    private_class_method

    def encode(string, key)
      string.bytes.map.with_index do |byte, index|
        k = key.bytes[index % key.length]
        byte ^ k
      end
    end
  end
end