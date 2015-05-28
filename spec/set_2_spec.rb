require 'spec_helper'

require 'encryption/aes_cbc'
require 'oracles/aes'

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

    it 'does not pad if the string size is a multiple of block size' do
      s        = 'YELLOW SUBMARINE'
      padded_s = PKCS7.pad_aes(s)

      expect(padded_s).to eq s
    end

    it 'can remove padding' do
      s         = "2afc4bacab28ef5c3686de177c030303"
      trimmed_s = PKCS7.trim_aes(s)

      expect(trimmed_s).to eq "2afc4bacab28ef5c3686de177c"
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

  context 'Challenge 3' do
    let(:plaintext) { File.read('resources/plain.txt') }

    it 'should determine whether a plaintext has been encrypted with ECB' do
      allow(Oracle::AES).to receive(:encryption_mode).and_return(:ECB)
      ciphertext = Oracle::AES.random_encode(plaintext)

      expect(Oracle::AES.mode(ciphertext)).to eq :ECB
    end

    it 'should determine whether a plaintext has been encrypted with CBC' do
      allow(Oracle::AES).to receive(:encryption_mode).and_return(:CBC)
      ciphertext = Oracle::AES.random_encode(plaintext)

      expect(Oracle::AES.mode(ciphertext)).to eq :CBC
    end
  end
end