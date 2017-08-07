#!/usr/bin/python2.7
import binascii 
import base64

def hex_to_base64(hexstr):
    ascii_string = binascii.unhexlify(hexstr);
    base64_string = base64.b64encode(ascii_string);
    return base64_string;

def fixed_xor(hex_string1, hex_string2):

    string1 = binascii.unhexlify(hex_string1);
    string2 = binascii.unhexlify(hex_string2);
    char__list = ''.join(chr(ord(i) ^ ord(j)) for i, j in zip(string1, 
        string2));
    
    return  binascii.hexlify(char__list);

# Challenge 3
def single_byte_xor_cipher(hexstring):
    english_letter_frequency = "etaoinshrdlcumwfgypbvkjxqz"
    xor_candidate_byte = range(0, 256)
    string = binascii.unhexlify(hexstring);

    # score_table is dictionary 
    score_table = dict()
    for candidate in xor_candidate_byte:
        # p is plain text
        p = ''
        score = 0
        # Making new string
        for char in string:
            p += chr(candidate ^ ord(char))
        # Score new string 
        for index in range(0, len(english_letter_frequency) - 1):
            score += (26 - index) * p.count(english_letter_frequency[index])
        score_table[p] = score
    # print dicionary by score 
    return score_table

def printdictionary_helper(dic):
    counter = 0
    for key, value in sorted(dic.iteritems(), key = lambda (k,v): (v,k), 
            reverse=True):
        if counter == 5:
            break
        print '[*] Sentence: {} Score: {}'.format(key, value)
        counter += 1

# Challenge 4
def detect_single_character_xor():
    with open("single_xor_list.txt",'r') as f:
        text_table = {}
        for line in f:
            line = line[:len(line) - 1]
            if len(line) % 2 != 0:
                continue
            text_table.update(single_byte_xor_cipher(line))
        printdictionary_helper(text_table)

# Challenge 5
def implement_repeating_key_xor(p, k):
    """Encrypt plian text p using key k"""
    c = ""
    i = 0
    strlen = len(k)
    for char in p:
        c = c + format(ord(char) ^ ord(k[i%strlen]), '02x')
        i += 1

    return c

# Challenge 6
def break_reapeating_key_xor():
    s1 = "this is a test"
    s2 = "wokka wokka!!!"

    bs = ""
    for i, j in zip(s1, s2):
        bs = bs + format(ord(i) ^ ord(j), '02b')
    
    hamming_distance = bs.count("1")

def main():
    # Challenge 1
    challenge1_a = '49276d206b696c6c696e6720796f757220627261696e206c696b652061'
    '20706f69736f6e6f7573206d757368726f6f6d';
    print '[*] Set 1 Challenge 1'
    print hex_to_base64(challenge1_a) + '\n';

    # Challenge 2
    challenge2_a = '1c0111001f010100061a024b53535009181c'
    challenge2_b = '686974207468652062756c6c277320657965'
    print '[*] Set 1 Challenge 2'
    print fixed_xor(challenge2_a, challenge2_b) + '\n';

    # Challenge 3
    print '[*] Set 1 Challenge 3'
    challenge3_hexstring = '1b37373331363f78151b7f2b783431333d78397828372d363c'
    '78373e783a393b3736'
    printdictionary_helper(single_byte_xor_cipher(challenge3_hexstring))
    print '\n'
    
    # Challlenge 4
    print '[*] Set 1 Challenge 4'
    detect_single_character_xor()
    print '\n'

    # Challenge 5
    p1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    print implement_repeating_key_xor(p1, 'ICE')

    # Challenge 6
    
if __name__ == "__main__":
    main()

