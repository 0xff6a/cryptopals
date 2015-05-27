require_relative '../encryption/aes'

module PKCS7
  module_function

  def pad_aes(string)
    pad(string, Encryption::AES::BLOCK_SIZE_BYTES)
  end

  def pad(string, block_size)
    return string if (string.size % block_size == 0)
    
    blocks    = Ascii.chunk(string, block_size) 
    pad_size  = block_size - blocks[-1].size

    blocks[-1] += pad_size.chr * pad_size
    
    blocks.join('')
  end

  def trim_aes(hex_s)
    trim(hex_s, Encryption::AES::BLOCK_SIZE_BYTES)
  end

  def trim(hex_s, block_size)
    blocks = Hex.chunk(hex_s, block_size) 
    return hex_s if invalid_pad?(blocks[-1])

    pad_size   = blocks[-1][-2..-1].hex
    blocks[-1] = blocks[-1][0...-(2*pad_size)]
    
    blocks.join('')
  end

  private_class_method

  def invalid_pad?(hex_block)
    last_byte = hex_block[-2..-1]
    pad_size  = last_byte.hex

    Hex.chunk(hex_block[0...-pad_size], 1).any?{ |b| b != last_byte }
  end
end