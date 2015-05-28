# encoding: BINARY

require 'base64'

require_relative '../encryption/repeat_key_xor'
require_relative '../encryption/aes'
require_relative '../encryption/aes_ecb'
require_relative '../encryption/aes_cbc'
require_relative '../utils/hex'
require_relative 'black_box'

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

    def reveal_content(black_box)
      # Discover cipher block size
      block_size = reveal_block_size(black_box)
      
      # Detect ecb encryption
      validate_ecb(black_box, block_size)

      # Feed shorter block ''
      ct = Hex.chunk(black_box.encode('A' * (block_size - 1)), block_size).first

      # Create dictionary
      dictionary = {}

      (0..255).each do |byte|
        clear_block     = 'A' * (block_size - 1) + byte.chr
        encrypted_block = Hex.chunk(black_box.encode(clear_block), block_size).first

        dictionary[encrypted_block] = byte
      end
      
      byte = dictionary[ct]
      binding.pry
    end

    private_class_method

    def validate_ecb(black_box, block_size)
      test_s = black_box.encode('A' * (2 * block_size))

      raise ArgumentError, 'Unknow ciphertext is not AES::ECB encrypted' unless ecb_encrypted?(test_s)
    end

    def reveal_block_size(black_box)
      initial_size = black_box.encode('').size
      ctr          = 0
      
      loop do
        ctr += 1
        size = black_box.encode('A' * ctr).size

        return ((size - initial_size) / 2) if size != initial_size
      end
    end

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

