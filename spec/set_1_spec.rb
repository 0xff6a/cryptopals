require 'set_1'

describe 'Set 1' do
  context 'Challenge 1' do
    let(:hex_s) {
      "49276d206b696c6c696e6720796f757220627261696e206c" + 
      "696b65206120706f69736f6e6f7573206d757368726f6f6d"
    }

    it '#to_bin should convert a hex string to an ASCII string' do
      expect(Hex::to_ascii(hex_s)).to eq "I'm killing your brain like a poisonous mushroom"
    end

    it '#hex_to_base64 should convert a hex string to base64' do
      b64_s = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

      expect(Hex::to_base64(hex_s)).to eq b64_s
    end   
  end 

  context 'Challenge 2' do
    it '#xor_hex should produce the XOR combination of 2 equal length hex buffers' do
      hex_1 = '1c0111001f010100061a024b53535009181c'
      hex_2 = '686974207468652062756c6c277320657965'

      expect(Hex::xor(hex_1, hex_2)).to eq '746865206b696420646f6e277420706c6179'
    end
  end
end