module Hex
  module_function

  def to_ascii(hex_s)
    [hex_s].pack('H*')
  end

  def to_base64(hex_s)
    [to_ascii(hex_s)].pack('m0')
  end

  def xor(hex_s1, hex_s2)
    Bytes::xor(
      to_ascii(hex_s1).bytes,
      to_ascii(hex_s2).bytes
    )
    .map(&:chr)
    .join
    .unpack('H*')[0]
  end
end

module Ascii
  module_function

  def to_hex(ascii_s)
    ascii_s.unpack('H*')[0]
  end
end

module Bytes
  module_function
  
  def xor(buffer_1, buffer_2)
    buffer_1.map.with_index { |byte, i| byte ^ buffer_2[i] }
  end
end