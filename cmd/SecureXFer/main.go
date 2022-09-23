package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash/crc32"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
)

const (
	IEEE = 0xedb88320 //CRC-32
	// Castagnoli's polynomial, used in iSCSI.
	// Has better error detection characteristics than IEEE.
	// https://dx.doi.org/10.1109/26.231911
	// Castagnoli = 0x82f63b78
	// Koopman's polynomial.
	// Also has better error detection characteristics than IEEE.
	// https://dx.doi.org/10.1109/DSN.2002.1028931
	// Koopman = 0xeb31d82e
)

var (
	cipherKey256 = []byte("_08_bit__16_bit__24_bit__32_bit_") //32-bit key for AES-256
	//cipherKey192 = []byte("_08_bit__16_bit__24_bit_") //24-bit key for AES-192
	//cipherKey128 = []byte("_08_bit__16_bit_") //16-bit key for AES-128

	temps  *template.Template
	Harici string = "Harici"

	mode      = flag.String("mode", "server", "server to listen, client to send")
	proto     = flag.String("proto", "tcp", "Transmission Protocol between peers (tcp -Default- or udp)")
	enc       = flag.Int("enc", 0, "Encryption enable (TRUE:1 or FALSE:0)")
	ipAddress = flag.String("ipAddress", "", "IP Address (A.B.C.D format in decimal")
	port      = flag.String("port", "5000", "IP port number - Default 5000")
	msg       = flag.String("msg", "", "Message to send to the other party (in quotes), if none, then user input via keyboard would be initialized")
)

func init() {

	temps = template.Must(template.ParseGlob("./../../templates/*.templ"))

}

func main() {

	go server("tcp", "5001")

	http.HandleFunc("/", index)
	// Nhttp.HandleFunc("/", processor)
	http.ListenAndServe(":5555", nil)

}

func index(w http.ResponseWriter, r *http.Request) {

	message2Send := r.FormValue("message")
	protocol := r.FormValue("proto")
	d := struct {
		Message   string // Last  string
		Protocol  string
		MessageRX string
	}{
		Message:   message2Send, // Last:  lname,,
		Protocol:  protocol,
		MessageRX: Harici,
	}

	// Harici = protocol
	if r.Method != "POST" { //POST or GET
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	temps.ExecuteTemplate(w, "index.templ", d)

	fmt.Println("hello", message2Send)
	fmt.Println("hello", protocol)
	fmt.Println("Harici: ", Harici)

	client("tcp", 1, "127.0.0.1", "5001", message2Send)

}

/*
 *	FILE			: client.go
 *	PROJECT			: Secure Message Transfer - Client/Server
 *	PROGRAMMER		: Ayhan GENC, ref: https://github.com/ayhangenc
 *	FIRST VERSION	: 19 Sept. 2022
 *	DESCRIPTION		:
 *		Client code for SecureXFER
 *		The project is a learning exercise for go. There would be different functions, including byte operations,
 *		CRC generation and checking, encryption/decryption and TCP/UDP comm. using the Golang standard libraries
 *		for AES(CFB), CRC etc...
 *		DISCLAIMER: This is only for my personal learning. So NO WARRANTIES....
 *		Credits: Daniel Pieczewski, ref: https://github.com/mickelsonm for AES encryption/decryption clues... .
 * 				 Kevin FOO , ref: https://oofnivek.medium.com for CRC-32 clues
 */

func client(proto string, enc int, ipAddress string, port string, msg string) {

	/* messageFromCLI := msg
	inputMessage := ""
	if messageFromCLI == "" {
		messageReader := bufio.NewReader(os.Stdin)
		fmt.Print("Please type your message here: ")
		inputMessage, _ = messageReader.ReadString('\n')
		inputMessage = strings.TrimSuffix(inputMessage, "\n") // remove CR from end
	} else {
		inputMessage = messageFromCLI
	}
	*/

	inputMessage := msg
	var messagetoCRC []byte
	switch enc {
	case 0: // no encryption
		messagetoCRC = []byte(inputMessage)

	case 1: //encrypt the message
		encrypted, err := encryptMessage(cipherKey256, inputMessage)
		if err != nil { //IF the encryption failed:
			log.Println(err) //Print error message:
			os.Exit(-3)      // -3: Encryption error
		}
		messagetoCRC = []byte(encrypted)
	}
	messageCRC := crcGenerate(messagetoCRC)                         // CRC Generation
	messageHeader := headerGenerate(messagetoCRC, messageCRC, &enc) // Header Generation
	fullMessage2Send := append(messageHeader[:], messagetoCRC[:]...)
	addresstoSend := ipAddress + ":" + port
	tcpAddr, err := net.ResolveTCPAddr(proto, addresstoSend)
	checkError(err)
	conn, err := net.DialTCP(proto, nil, tcpAddr)
	checkError(err)
	_, err = conn.Write(fullMessage2Send)
	checkError(err)
	fmt.Println("Message sent!...")

}

/*
 *	FUNCTION		: encrypt
 *	DESCRIPTION		:
 *		This function takes a string and a cipher key and uses AES to encrypt the message
 *
 *	PARAMETERS		:
 *		byte[] key	: Byte array containing the cipher key
 *		string message	: String containing the message to encrypt
 *
 *	RETURNS			:
 *		string encoded	: String containing the encoded user input
 *		error err	: Error message
 */

func encryptMessage(cipherKey []byte, messagetoEncrypt string) (encodedMessage string, err error) {

	messageText := []byte(messagetoEncrypt)          //Create byte array from the input string
	encryptionBlock, err := aes.NewCipher(cipherKey) //Create a new AES cipher using the key
	if err != nil {                                  //if failed, exit:
		return
	}
	cipherText := make([]byte, aes.BlockSize+len(messageText))           //Make the cipher text a byte array of size BlockSize + the length of the message
	intermediateText := cipherText[:aes.BlockSize]                       //intermediateText is the ciphertext up to the blocksize (16)
	if _, err = io.ReadFull(rand.Reader, intermediateText); err != nil { //if failed, exit:
		return
	}
	encryptedStream := cipher.NewCFBEncrypter(encryptionBlock, intermediateText) //Encrypt the message
	encryptedStream.XORKeyStream(cipherText[aes.BlockSize:], messageText)

	return base64.RawStdEncoding.EncodeToString(cipherText), err //Return string encoded in base64
}

/*
 *	FUNCTION		: CRC Generation
 *	DESCRIPTION		:
 *		This function takes a string generate CRC-32
 *
 *	PARAMETERS		:
 *		TBD
 *		XX byte[] key	: Byte array containing the cipher key
 *		XX string secure	: String containing an encrypted message
 *
 *	RETURNS			:
 *		TBD
 *		XX string decoded	: String containing the decrypted equivalent of secure
 *		XX error err	: Error message
 */

func crcGenerate(message2CRC []byte) (crcFromMessage []byte) {
	crc32Table := crc32.MakeTable(IEEE)
	crcIntermediate := crc32.Checksum(message2CRC, crc32Table)
	crcFromMessage = make([]byte, 4)
	binary.BigEndian.PutUint16(crcFromMessage, uint16(crcIntermediate))
	return crcFromMessage
}

/*
 *	FUNCTION		: Header Generation
 *	DESCRIPTION		:
 *		This function takes the message and CRC values to generate the header for the message to wire..
 *
 *	PARAMETERS		:
 *		TBD
 *		XX byte[] key	: Byte array containing the cipher key
 *		XX string secure	: String containing an encrypted message
 *
 *	RETURNS			:
 *		TBD
 *		XX string decoded	: String containing the decrypted equivalent of secure
 *		XX error err	: Error message
 */

func headerGenerate(message2Send []byte, crcfromMessage []byte, enc *int) (headertoMessage []byte) {

	var headerSignature []byte
	switch *enc {
	case 0:
		headerSignature = []byte{0xF0, 0x00}
	case 1:
		headerSignature = []byte{0xF0, 0x01}
	}
	crcString := fmt.Sprintf("%x", crcfromMessage)
	headerCRC, _ := hex.DecodeString(crcString)
	messageLen := make([]byte, 2)
	binary.BigEndian.PutUint16(messageLen, uint16(len(message2Send)))
	headerI := append(headerSignature[:], headerCRC[:]...)
	header := append(headerI[:], messageLen[:]...)

	return header
}

func handleConnection(conn net.Conn) {

	input := make([]byte, 1024)
	nRead, err := conn.Read(input[0:])
	checkError(err)
	fullMessageReceived := input[:nRead]

	headSign := fullMessageReceived[:2] // check if message is authentic (header first 2-digits are FO:O0/01)
	if headSign[0] == 0xf0 {
		if headSign[1] == 0x00 || headSign[1] == 0x01 {
			fmt.Println("Message Is Authentic.")
		} else {
			fmt.Println("Message Is NOT Authentic!..")
			return
		}
	} else {
		fmt.Println("Message Is NOT Authentic!..")
		return
	}

	lenFromHeader := fullMessageReceived[6:8] // message lenght check (header digits 6 & 7 are lenght of message in hex)
	lenFromMessage := len(fullMessageReceived) - 8
	lenXCheck := int(lenFromHeader[0])*256 + int(lenFromHeader[1]) // (hex to int)
	if lenXCheck != lenFromMessage {
		fmt.Println("Message size is DIFFERENT from header!...")
		os.Exit(5) //message altered or corrupt during transmission
	}

	crcFromHeader := fullMessageReceived[2:6] // message crc check (header digits 2,3,4,5 are CRC digits in hex)
	crcFromMessage := crcGenerate(fullMessageReceived[8:])
	crcXCheck := bytes.Compare(crcFromHeader, crcFromMessage)
	if crcXCheck != 0 {
		fmt.Println("Message CRC is DIFFERENT from header!...")
		os.Exit(6) //message altered or corrupt during transmission
	}

	var messageRXBody []byte
	switch headSign[1] { // check if message is encrypted
	case 0x01: // encrypted
		fmt.Println("Message Is Encypted!...")
		messageRXBodySTR, err := decryptMessage(cipherKey256, string(fullMessageReceived[8:]))

		messageRXBody = []byte(messageRXBodySTR)

		if err != nil { //if message decrypt fails...
			log.Println(err)
			os.Exit(-3)
		}
	case 0x00: // not encrypted
		fmt.Println("Message Is Not Encrypted!..")
		messageRXBody = fullMessageReceived[8:]
	}
	//fmt.Printf("Message RECEIVED from other party (be it encrypted or not) : %s\n", messageRXBody)
	Harici = string(messageRXBody)
}

func server(proto string, port string) { // (proto string, port string)

	tcpAddr, err := net.ResolveTCPAddr(proto, fmt.Sprintf("127.0.0.1:%s", port))
	checkError(err)
	fmt.Println("IP add: ", tcpAddr)
	listener, err := net.ListenTCP(proto, tcpAddr)
	checkError(err)

	for {
		connectTo, err := listener.Accept()
		checkError(err)

		go handleConnection(connectTo)
	}
}

/*
 *	FUNCTION		: decrypt
 *	DESCRIPTION		:
 *		This function takes a string and a key and uses AES to decrypt the string into plain text
 *
 *	PARAMETERS		:
 *		byte[] key	: Byte array containing the cipher key
 *		string secure	: String containing an encrypted message
 *
 *	RETURNS			:
 *		string decoded	: String containing the decrypted equivalent of secure
 *		error err	: Error message
 */

func decryptMessage(cipherKey []byte, secureMessage string) (decodedMessage string, err error) {

	cipherText, err := base64.RawStdEncoding.DecodeString(secureMessage) // decode base64
	if err != nil {                                                      //IF DecodeString failed, exit:
		return
	}
	decryptionBlock, err := aes.NewCipher(cipherKey) //Create a new AES cipher with the key and encrypted message
	if err != nil {                                  //IF NewCipher failed, exit:
		return
	}
	if len(cipherText) < aes.BlockSize { //IF the length of the cipherText is less than 16 Bytes:
		log.Println("Ciphertext block size is too short!", err)
		os.Exit(-3)
	}
	intermediateText := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(decryptionBlock, intermediateText) //Decrypt the message
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), err
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func maingone() {

	flag.Parse()

	switch *mode {
	case "server":
		fmt.Println("mode: server")

		// Listen & Decode by calling server.go  - parameters: *proto, *port
		server(*proto, *port)
	case "client":

		// // Initiate & Encode by calling client.go in loop  - parameters: *proto, *enc, *msg, *ipAddress, *port
		for {
			client(*proto, *enc, *ipAddress, *port, *msg)
		}
	}
}

/*
func processor(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" { //POST or GET
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	message2Send := r.FormValue("message")
	// lname := r.FormValue("laster")

	d := struct {
		Message string // Last  string
	}{

		Message: message2Send, // Last:  lname,
	}

	temps.ExecuteTemplate(w, "index.templ", d)
}

*/
