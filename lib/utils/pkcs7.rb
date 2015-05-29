# encoding: BINARY

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

  def trim(ascii_s, block_size)
    blocks = Ascii.chunk(ascii_s, block_size) 

    raise ArgumentError, 'Invalid PKCS7 padding on supplied string' if invalid_pad?(blocks[-1])

    pad_size   = blocks[-1][-1].ord
    blocks[-1] = blocks[-1][0...-pad_size]
    
    blocks.join('')
  end

  private_class_method

  def invalid_pad?(block)
    last_byte = block[-1]
    pad_size  = last_byte.ord

    return true if pad_size > block.size

    Ascii.chunk(block[-pad_size..-1], 1).any?{ |b| b != last_byte }
  end
end


