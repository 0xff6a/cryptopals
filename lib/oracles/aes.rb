require_relative '../encryption/repeat_key_xor'
require_relative '../encryption/aes'
require_relative '../encryption/aes_ecb'
require_relative '../encryption/aes_cbc'
require_relative '../utils/hex'

module Oracle
  module AES
    module_function

    BLOCK_SIZE_BYTES = Encryption::AES::BLOCK_SIZE_BYTES

    def mode(hex_s)
      ecb_encrypted?(hex_s) ? :ECB : :CBC
    end

    def ecb_encrypted?(hex_s)
      repeated_blocks?(hex_s)
    end

    def random_encode(ascii_s)
      plaintext = random_pad + ascii_s + random_pad

      case encryption_mode
      when :ECB
        Encryption::AES::ECB.encode(plaintext, random_block)
      when :CBC
        Encryption::AES::CBC.encode(plaintext, random_block, random_block)
      end
    end

    private_class_method

    def random_pad
      SecureRandom.random_bytes(rand(10))
    end

    def random_block
      SecureRandom.random_bytes(BLOCK_SIZE_BYTES)
    end

    def encryption_mode
      MODES[rand(2)]
    end

    def repeated_blocks?(hex_s)
      blocks = hex_s.scan(/../).each_slice(BLOCK_SIZE_BYTES).to_a

      blocks.uniq.size != blocks.size
    end
  end
end 


