module Decoder
  module RepeatKeyXOR
    module_function
    KEY_SIZE_MIN = 2
    KEY_SIZE_MAX = 40

    def decode(hex_s)
      # Find the keysize
      # Break ciphertext into blocks of keysize length
      # Break blocks into byte chunks
      # Solve each block using single char XOR
      # For each block the single byte key that produces best score is single byte key
      # Put each byte key together to get the document key
    end

    private_class_method

    def advanced_keysize(hex)
      # Do keysize twice on different blocks
      # Average score
      # Return keysize with smallest average distance
    end

    def keysize(hex_s)
      # for each keysize
      # take bytes[0..keysize - 1]
      # get hamming distance vs [keysize..2keysize -1]
      # Return keysize with smallest distance
    end
  end
end