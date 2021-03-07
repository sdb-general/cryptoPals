package main

import (
	"fmt"
)

func main() {
	/////////// q1 ///////////////
	/*input := []byte(`49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d`)

	decodedInput, _ := decodeHex(input)
	decodedInput = base64Encode(decodedInput)
	fmt.Printf("%s", decodedInput)*/

	/////////// q2 ///////////////
	/*
		string1, _ := decodeHex([]byte(`1c0111001f010100061a024b53535009181c`))
		string2, _ := decodeHex([]byte(`686974207468652062756c6c277320657965`))
		output, _ := ecksor(string1, string2)
		fmt.Printf("%x", output)*/

	/////////// q3 ///////////////
	/*input, _ := decodeHex([]byte(`1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736`))
	output, _, _ := SingleXorCipher(input)
	fmt.Printf("%s", output)*/

	/////////// q4 ///////////////

	/*f, _ := ioutil.ReadFile("4.txt")
	lines := strings.Split(string(f), "\n")
	var result []byte
	var score int

	for _, line := range lines {
		input, _ := decodeHex([]byte(line))
		ans, dummyScore, _ := SingleXorCipher(input)
		//fmt.Printf("%s\n", ans)
		if dummyScore > score {
			result = ans
			score = dummyScore
			fmt.Printf("%s\n", result)
		}
	}
	fmt.Printf("%s", result)*/

	/////////// q5 ///////////////

	/*input := `Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal`
	output := keyRepeatingExxor(input, "ICE")

	fmt.Printf("%x", output)*/

	///////////////////////////////// q6 /////////////////////////////////
	//x := []byte("this is a test")
	//y := []byte("wokka wokka!!!")
	//fmt.Println(hammingBytes(x, y))

	/*encryptedString, _ := ioutil.ReadFile("6.txt")
	encryptedString = base64Decode(encryptedString)
	//pass this into a function to return the best keylengths and their strengths
	keys := getKeyLengths(encryptedString)
	//now that we probably know the key, we can break it down into chunk
	//let's try with the top 5 keylengths
	answers := make([][]byte, 6)
	for i := 0; i < len(answers); i++ {
		keySize := keys[i].length
		chunks := makeByteChunks(keySize, encryptedString)

		decryptedChunks := make([][]byte, len(chunks))

		for index, _ := range decryptedChunks {
			a, _, _ := SingleXorCipher(chunks[index])
			decryptedChunks[index] = a
		}
		rebuilt := rebuildString(decryptedChunks)
		answers[i] = rebuilt
	}
	for _, elt := range answers {
		//temp := base64Decode(elt)
		fmt.Printf("%s\n", elt)
	}*/

	//////////////////////////// q7 ///////////////////////////

	/*cipherText, _ := ioutil.ReadFile("7.txt")
	cipherText = base64Decode(cipherText)
	key := []byte("YELLOW SUBMARINE")
	plainText := make([]byte, len(key))

	aes, _ := aes.NewCipher(key)

	for i := 0; i < len(cipherText)/len(key); i++ {
		dummyPT := make([]byte, len(key))
		aes.Decrypt(dummyPT, cipherText[i*len(key):(i+1)*len(key)])
		plainText = append(plainText, dummyPT...)
	}

	fmt.Printf("%s", plainText)*/

	////////////////////////// q8 //////////////////////////////////
	//we break into 16 byte chunks
	//if any of the chunks match, we return which string is the
	//culprit

	fmt.Println(DetectECB("8.txt"))

}
