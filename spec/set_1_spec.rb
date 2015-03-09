require 'decoders/single_char_xor'
require 'decoders/text_scorer'
require 'encoding/hex'
require 'encoders/repeat_key_xor'

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
    it 'TextScorer can evaluate the frequency of characters in a string' do
      expect(TextScorer.absolute_frequency('abbcccddddeeeee')).to eq({
        "a" => 1, "b" => 2, "c" => 3, "d" => 4, "e" => 5
      })
    end

    it 'TextScorer can score strings based on character frequency vs average' do
      english = TextScorer.calculate('hello my name is jeremy')
      bad     = TextScorer.calculate('hello fhcsjkbv')
      worse   = TextScorer.calculate('shvsbvkbs')

      expect([bad, english, worse].sort).to eq [english, bad, worse] 
    end

    it 'Decoder can decrypt a single character xor-encoded hex string' do
      input_s   =  '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
      output_s  = "Cooking MC's like a pound of bacon"

      expect(Decoder::SingleCharXOR.decode(input_s).plaintext).to eq output_s
    end
  end

  xcontext 'Challenge 4 (skip for speed)' do
    it 'can identify the string encrypted with single character XOR' do
      input = File.readlines('resources/4.txt').map(&:chomp)
      result = input.map { |s| Decoder::SingleCharXOR.decode(s) }
      string = result.sort_by(&:score).first.plaintext

      expect(string).to eq "Now that the party is jumping\n"
    end
  end

  context 'Challenge 5' do
    it 'Encoder can apply repeating key XOR' do
      key     = 'ICE'
      string  = "Burning 'em, if you ain't quick and nimble\n" +
                "I go crazy when I hear a cymbal"
      
      expect(Encoder::RepeatKeyXOR.encode_to_hex(string, key)).to eq(
        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' +
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
      )
    end
  end
end