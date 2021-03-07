package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"sort"
) // "os"; "log"; "bufio")//; "crypto/sha256")//; "reflect")

func decodeHex(input []byte) ([]byte, error) {
	dst := make([]byte, hex.DecodedLen(len(input)))
	_, err := hex.Decode(dst, input)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func hexEncode(input []byte) []byte {
	eb := make([]byte, hex.EncodedLen(len(input)))
	hex.Encode(eb, input)
	return eb
}

func base64Encode(input []byte) []byte {
	eb := make([]byte, base64.StdEncoding.EncodedLen(len(input)))
	base64.StdEncoding.Encode(eb, input)
	return eb
}

func base64Decode(input []byte) []byte {
	output := make([]byte, base64.StdEncoding.DecodedLen(len(input)))
	base64.StdEncoding.Decode(output, input)
	return output
}

func ecksor(input1, input2 []byte) ([]byte, error) {
	if len(input1) != len(input2) {
		return nil, errors.New("byte arrays different lengths")
	}
	output := make([]byte, len(input1))
	for i := 0; i < len(input1); i++ {
		output[i] = input1[i] ^ input2[i]
	}
	return output, nil
}

func characterWeight(a byte) int {
	letterMap := map[byte]int{
		byte('U'): 2,
		byte('u'): 2,
		byte('L'): 3,
		byte('l'): 3,
		byte('D'): 4,
		byte('d'): 4,
		byte('R'): 5,
		byte('r'): 5,
		byte('H'): 6,
		byte('h'): 6,
		byte('S'): 7,
		byte('s'): 7,
		byte(' '): 8,
		byte('N'): 9,
		byte('n'): 9,
		byte('I'): 10,
		byte('i'): 10,
		byte('O'): 11,
		byte('o'): 11,
		byte('A'): 12,
		byte('a'): 12,
		byte('T'): 13,
		byte('t'): 13,
		byte('E'): 14,
		byte('e'): 14,
	}

	return letterMap[a]
}

func SingleXorCipher(codedMessage []byte) ([]byte, int, byte) {
	b := codedMessage
	var output []byte
	var score int
	var key byte
	for i := 0; i < 256; i++ { //trying out every character to Xor against the input
		r := make([]byte, len(b))
		var s int
		for j := 0; j < len(b); j++ { // here run across the message
			c := b[j] ^ byte(i)
			s += characterWeight(c)
			r[j] = c //store the character at position j in new array
		}
		if s > score {
			output = r
			score = s
			key = byte(i)
		}
		s = 0 //reset s for next run
	}
	return output, score, key
}

func keyRepeatingExxor(plaintext, key string) []byte {
	encryptionKey := make([]byte, len([]byte(key)))
	keyRune := []rune(key)
	for i := 0; i < len(keyRune); i++ {
		encryptionKey[i] = byte(keyRune[i])
	}
	encryptedString := make([]byte, len([]byte(plaintext)))
	bytePlaintext := []byte(plaintext)

	for i := 0; i < len(bytePlaintext); i++ {
		encryptedString[i] = bytePlaintext[i] ^ encryptionKey[i%len(encryptionKey)]
	}
	return encryptedString
}

func bit_counter(input byte) int { //counts number of nonzero entries in a byte
	output := 0
	for i := 0; i < 8; i++ {
		a := input >> i
		output += int(a & 1)
	}
	return output
}

func hammingBytes(input1, input2 []byte) int { //computes hamming distance between two byte arrays
	var output int
	for index, _ := range input1 {
		bit := input1[index] ^ input2[index]
		output += bit_counter(bit)
	}
	return output
}

type keyLength struct {
	length   int
	strength float64
}

func getKeyLengths(encryptedString []byte) []keyLength {
	keyLengths := make([]keyLength, 0)

	for keySize := 2; keySize < 41; keySize++ {
		byte1, byte2 := encryptedString[0:keySize], encryptedString[keySize:2*keySize]
		byte3, byte4 := encryptedString[2*keySize:3*keySize], encryptedString[3*keySize:4*keySize]

		distanceNormal := 0.5 * (float64(hammingBytes(byte1, byte2)) + float64(hammingBytes(byte3, byte4))) / float64(keySize) //normalised hamming distance
		keyLengths = append(keyLengths, keyLength{strength: distanceNormal, length: keySize})
	}
	sort.Slice(keyLengths, func(i, j int) bool {
		return keyLengths[i].strength < keyLengths[j].strength
	})
	return keyLengths
}

func makeByteChunks(keyLength int, encryptedBytes []byte) [][]byte {
	chunks := make([][]byte, keyLength)
	for i, c := range encryptedBytes {
		chunks[i%keyLength] = append(chunks[i%keyLength], c)
	}
	return chunks
}

func rebuildString(unencChunks [][]byte) []byte {
	r := make([]byte, 0)
	for i := 0; i < len(unencChunks[0]); i++ {
		for _, sl := range unencChunks {
			if i < len(sl) {
				r = append(r, sl[i])
			}
		}
	}
	return r
}

// func DecryptEcb(cipherBytes, key []byte) ([]byte, error){
// 	aes, err := aes.NewCipher(key)
// 	if err != nil{
// 		return nil, err
// 	}
// 	plainText := make([]byte, len(cipherBytes))

// 	if len(cipherBytes) % len(key) != 0{
// 		dumm := make(type, 0)
// 	}
// }

func DetectECB(filename string) (int, error) {
	var input [][]byte
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return -1, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(f))
	for scanner.Scan() {
		hdl := make([]byte, hex.DecodedLen(len(scanner.Bytes())))
		_, err := hex.Decode(hdl, scanner.Bytes())
		if err != nil {
			return -1, err
		}
		input = append(input, hdl)
	}
	res := Detect(input)
	return res, nil
}

func Detect(input [][]byte) int {
	for i, ln := range input {
		chunks := make([][]byte, 0)
		for j := 0; j < len(ln); j += 16 {
			batch := ln[j:min(j+15, len(ln))]
			for _, c := range chunks {
				if bytes.Equal(c, batch) {
					return i + 1
				}
			}
			chunks = append(chunks, batch)
		}
	}
	return 0
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}
