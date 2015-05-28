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
  end
end