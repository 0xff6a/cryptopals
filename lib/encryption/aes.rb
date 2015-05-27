require 'securerandom'

module Encryption
  module AES
    module_function

    MODES =
    {
      1 => :ECB,
      2 => :CBC
    }

    BLOCK_SIZE_BYTES = 16 

    def random_encode(ascii_s)
      plaintext = random_pad + ascii_s + random_pad

      case encryption_mode
      when :ECB
        Encryption::AES::ECB.encode(plaintext, random_block)
      when :CBC
        Encryption::AES::CBC.encode(plaintext, random_block, random_block)
      end
    end

    def random_pad
      SecureRandom.random_bytes(rand(10))
    end

    def random_block
      SecureRandom.hex(BLOCK_SIZE_BYTES)
    end

    private_class_method

    def encryption_mode
      MODES[rand(2)]
    end
  end
end