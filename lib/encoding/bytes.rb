module Bytes
  module_function

  def xor(buffer_1, buffer_2)
    buffer_1.map.with_index { |byte, i| byte ^ buffer_2[i] }
  end

  def to_hex(buffer)
    buffer
      .map(&:chr)
      .join
      .unpack('H*')[0]
  end
end