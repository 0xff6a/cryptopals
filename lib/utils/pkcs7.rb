require_relative '../encryption/aes_ecb'

module PKCS7
  module_function

  def pad_aes(string)
    pad(string, Encryption::AES::ECB::BLOCK_SIZE_BYTES)
  end

  def pad(string, block_size)
    blocks    = Ascii.chunk(string, block_size) 
    pad_size  = block_size - blocks[-1].size

    blocks[-1] += pad_size.chr * pad_size
    
    blocks.join('')
  end
end