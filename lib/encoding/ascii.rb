module Ascii
  module_function

  def to_hex(ascii_s)
    ascii_s.unpack('H*')[0]
  end
end