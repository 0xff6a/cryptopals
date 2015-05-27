require 'spec_helper'

require 'encryption/aes_cbc'

describe 'Set 2' do
  context 'Challenge 1' do
    it 'should implement PKCS7 padding' do
      s        = 'YELLOW SUBMARINE'
      padded_s = PKCS7.pad(s, 20)

      expect(padded_s).to eq "YELLOW SUBMARINE\x04\x04\x04\x04"
    end

    it 'should implement PKCS7 padding for AES blocks' do
      s        = 'YELLOW SUB'
      padded_s = PKCS7.pad_aes(s)

      expect(padded_s).to eq "YELLOW SUB\x06\x06\x06\x06\x06\x06"
    end

    it 'should pad only the last block for multiblock strings' do
      s        = 'YELLOW SUBMARINE YELLOW SUB'
      padded_s = PKCS7.pad(s, 16)

      expect(padded_s).to eq "YELLOW SUBMARINE YELLOW SUB\x05\x05\x05\x05\x05"
    end
  end

  context 'Challenge 2' do
    let(:iv)        { "\x00" * 16                                    }
    let(:key)       { 'YELLOW SUBMARINE'                             }
    let(:input)     { Base64.decode64(File.read('resources/10.txt')) }
    let(:plaintext) {
      Encryption::AES::CBC.decode(
        Ascii.to_hex(input), 
        Ascii.to_hex(key), 
        Ascii.to_hex(iv)
      )
    }

    it 'should implement CBC mode decryption' do
      expect(plaintext).to include(
        "I'm back and I'm ringin' the bell \n" +
        "A rockin' on the mike while the fly girls yell \n" +
        "In ecstasy in the back of me "
      )
    end

    it 'should implement CBC mode encryption' do
      ciphertext = Encryption::AES::CBC.encode(plaintext, key, iv)

      expect(ciphertext).to eq Ascii.to_hex(input)
    end
  end
end