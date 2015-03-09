require 'decoders/single_char_xor'
require 'decoders/text_scorer'
require 'encoding/hex'

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

      expect(Hex::bitwise_xor(hex_1, hex_2)).to eq '746865206b696420646f6e277420706c6179'
    end
  end

  context 'Challenge 3' do
    it 'can evaluate the frequency of characters in a string' do
      expect(TextScorer.frequency('abbcccddddeeeee')).to eq({
        "a" => 1, "b" => 2, "c" => 3, "d" => 4, "e" => 5
      })
    end

    it 'can score strings based on character frequency vs average' do
      english = TextScorer.calculate('hello my name is jeremy')
      bad     = TextScorer.calculate('hello fhcsjkbv')
      worse   = TextScorer.calculate('shvsbvkbs')

      expect([bad, english, worse].sort).to eq [english, bad, worse] 
    end

    it 'can decrypt a single character xor-encoded hex string' do
      s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
      expect(Decoder::SingleCharXOR.decode(s)).to eq "Cooking MC's like a pound of bacon"
    end
  end
end