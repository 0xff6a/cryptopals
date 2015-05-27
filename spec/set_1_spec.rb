require 'spec_helper'

require 'encryption/aes_ecb'
require 'encryption/single_char_xor'
require 'encryption/repeat_key_xor'

require 'analyzers/text_scorer'
require 'analyzers/hamming_distance'

require 'oracles/aes_ecb'

describe 'Set 1' do
  context 'Challenge 1' do
    let(:hex_s) {
      "49276d206b696c6c696e6720796f757220627261696e206c" + 
      "696b65206120706f69736f6e6f7573206d757368726f6f6d"
    }

    it '#to_bin should convert a hex string to an ASCII string' do
      expect(Hex.to_ascii(hex_s)).to eq "I'm killing your brain like a poisonous mushroom"
    end

    it '#hex_to_base64 should convert a hex string to base64' do
      b64_s = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

      expect(Hex.to_base64(hex_s)).to eq b64_s
    end   
  end 

  context 'Challenge 2' do
    it '#xor_hex should produce the XOR combination of 2 equal length hex buffers' do
      hex_1 = '1c0111001f010100061a024b53535009181c'
      hex_2 = '686974207468652062756c6c277320657965'

      expect(Hex.bitwise_xor(hex_1, hex_2)).to eq '746865206b696420646f6e277420706c6179'
    end
  end

  context 'Challenge 3' do
    it 'Analyzer can evaluate the frequency of characters in a string' do
      expect(Analyzer::TextScorer.absolute_frequency('abbcccddddeeeee')).to eq({
        "a" => 1, "b" => 2, "c" => 3, "d" => 4, "e" => 5
      })
    end

    it 'Analyzer can score strings based on character frequency vs average' do
      english = Analyzer::TextScorer.calculate('hello my name is jeremy')
      bad     = Analyzer::TextScorer.calculate('hello fhcsjkbv')
      worse   = Analyzer::TextScorer.calculate('shvsbvkbs')

      expect([bad, english, worse].sort).to eq [english, bad, worse] 
    end

    it 'Decoder can decrypt a single character xor-encoded hex string' do
      input_s   =  '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
      output_s  = "Cooking MC's like a pound of bacon"

      expect(Encryption::SingleCharXOR.decode(input_s).plaintext).to eq output_s
    end
  end

  xcontext 'Challenge 4 (skip for speed)' do
    it 'can identify the string encrypted with single character XOR' do
      input = File.readlines('resources/4.txt').map(&:chomp)
      result = input.map { |s| Encryption::SingleCharXOR.decode(s) }
      string = result.sort_by(&:score).first.plaintext

      expect(string).to eq "Now that the party is jumping\n"
    end
  end

  context 'Challenge 5' do
    it 'Encoder can apply repeating key XOR' do
      key     = 'ICE'
      string  = "Burning 'em, if you ain't quick and nimble\n" +
                "I go crazy when I hear a cymbal"
      
      expect(Encryption::RepeatKeyXOR.encode(string, key)).to eq(
        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' +
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
      )
    end
  end

  context 'Challenge 6' do
    let(:input) { Base64.decode64(File.read('resources/6.txt')) }

    it 'Analyzer can compute the hamming distance between two strings' do
      s1 = 'this is a test'
      s2 = 'wokka wokka!!!'
      h1 = Ascii.to_hex(s1)
      h2 = Ascii.to_hex(s2)

      expect(Analyzer::HammingDistance.from_ascii(s1,s2)).to eq 37
      expect(Analyzer::HammingDistance.from_hex(h1,h2)).to eq 37
    end

    it 'can guess the keysize for a ciphertext' do
      key_size = Encryption::RepeatKeyXOR.advanced_guess_keysize(input.bytes)
      expect(key_size).to eq 29
    end

    it 'can decode a repeat-key XOR encoded message' do
      key = Encryption::RepeatKeyXOR.guess_key(Ascii.to_hex(input))
      msg = Encryption::RepeatKeyXOR.decode(Ascii.to_hex(input), key)

      expect(msg).to include(
        "I'm back and I'm ringin' the bell \n" +
        "A rockin' on the mike while the fly girls yell \n" +
        "In ecstasy in the back of me "
      )
    end
  end

  context 'Challenge 7' do
    let(:input) { Base64.decode64(File.read('resources/7.txt')) }

    it 'can decrypt an AES-ECB encoded file given the key' do
      key = 'YELLOW SUBMARINE'
      msg = Encryption::AES::ECB.decode(Ascii.to_hex(input), Ascii.to_hex(key))

      expect(msg).to include(
        "I'm back and I'm ringin' the bell \n" +
        "A rockin' on the mike while the fly girls yell \n" +
        "In ecstasy in the back of me "
      )
    end
  end

  context 'Challenge 8' do
    let(:input) { File.read('resources/8.txt').split("\n") }

    it 'can detect an AES-ECB encrypted text' do
      index = input.index { |s| Oracle::AES::ECB.detected?(Ascii.to_hex(s)) }
      size  = input.count { |s| Oracle::AES::ECB.detected?(Ascii.to_hex(s)) }

      expect(size).to eq 1
      expect(index).to eq 132
    end
  end
end