# Daelyn Jones
# V00805241

# This program takes a cipher text, the accompanying plain text, as well as the
# IV used in the CBC encryption and encrypts words of size less than 16 from
# the english dictionary, decrypts the encrypted text, and checks if the plain
# text is in it. This tells us what the key is that was used to encrypt the
# text.

require 'openssl'

class BruteForceKey
  def call
    plain_text = 'This is a top secret.'

    # We need to turn these hexadecimal strings into binary data as that is
    # what we need if we want to make comparisons with it.
    # The IV also needs to be size 16 bytes for us to be able to use it.
    @cipher_text =
      '764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2'.scan(
        /../
      )
        .map { |x| x.hex.chr }.join
    @iv =
      'aabbccddeeff00998877665544332211'.scan(/../).map { |x| x.hex.chr }.join

    # We loop through the words in the file that are the right size, remove
    # any \n characters, and pad the strings up to size 16 with pound symbols.
    # We check if our decrypted cipher text includes the plain text as the
    # decrypted text will have padding in it and we don't care to remove it
    # as we can just use the .include? method to check for the plain text.
    File.open('words.txt').each do |word|
      if (word.length < 16)
        stripped_word = word.strip
        padded_word = stripped_word.concat('#' * (16 - stripped_word.length))

        return word if decrypt_cipher(key: padded_word).include?(plain_text)
      end
    end
  end

  private

  # We use the openssl library to perform an AES128 CBC decryption on our
  # cipher text using the IV and key, where the key is a word from the
  # dictionary that we have padded accordingly.
  def decrypt_cipher(key:)
    decipher = OpenSSL::Cipher::AES.new(128, :CBC).decrypt
    decipher.iv = @iv
    decipher.key = key
    decipher.padding = 0

    decipher.update(@cipher_text) + decipher.final
  end
end

# The BruteForceKey service object will return us the word that was used to
# encrypt the plain text.
puts "key is: #{BruteForceKey.new.call}"
