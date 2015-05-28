require 'spec_helper'

require 'encryption/aes_cbc'
require 'oracles/aes'
require 'utils/url'

describe 'Set 2' do
  context 'Challenge 9' do
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

  context 'Challenge 10' do
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

  context 'Challenge 11' do
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

  context 'Challenge 12' do
    let(:target) { 
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" + 
      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
      "YnkK"
    }

    it 'should decrypt AES ECB encryption from a black box encoder' do
      box     = Oracle::AES::BlackBox.new(target)
      content = Oracle::AES.reveal_content(box)

      expect(content).to eq(
        "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe " +
        "girlies on standby waving just to say hi\nDid you stop? No, I just " +
        "drove by\n\x01-----"
      )
    end
  end

  context 'Challenge 13' do
    it 'should be able to parse a structured cookie string' do
      expect(URL.kv_parse("foo=bar&baz=qux&zap=zazzle")).to eq({
        foo: 'bar',
        baz: 'qux',
        zap: 'zazzle'
      })
    end

    it '#profile_for - should be able to create a user profile hash from an email' do
      email = 'foo@bar.com'
      allow(email).to receive(:hash).and_return 10

      expect(URL.profile_for(email)).to eq({
        email: email,
        uid:   10,
        role:  'user'
      })
    end

    it '#profile_for - should not allow encoding metacharacters' do
      email = 'foo@bar.com&role=admin'
      allow(email).to receive(:hash).and_return 10

      expect(URL.profile_for(email)).to eq({
        email: 'foo@bar.com%26role%3Dadmin',
        uid:   10,
        role:  'user'
      })
    end
  end
end