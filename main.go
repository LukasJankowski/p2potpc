package main

import (
	"os"
	"fmt"
	"net"
	"log"
	"bufio"
	"bytes"
	"strings"
	"strconv"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/base64"
	"github.com/abiosoft/ishell"
)

func main() {
	shell := ishell.New()
	shell.Println("End2End OTP Encrypted Communication v1.1.0")

	// Set the operating mode of the application
	shell.AddCmd(&ishell.Cmd{
		Name: "mode",
		Help: "set the operation mode of the application",
		Func: func(c *ishell.Context) {
			c.ShowPrompt(false)
			c.Print("Select an operating mode [server = 1, client = 2 (default), relay(todo) = 3]:")
			choiceArg := c.ReadLine()
			if choiceArg == "" {
				choiceArg = "2"
			}
			choice, err := strconv.Atoi(choiceArg)
			if err != nil {
				c.Println("Error: Failed to get valid mode. Please enter only numbers")
				return
			}
			if choice <= 0 || choice >= 4 {
				c.Println("Error: Mode too low / high. Please enter a number between 1-3")
				return
			}
			/*choice := c.MultiChoice([]string{
				"Server",
				"Client",
				"Relay (disabled)",
			}, "Select an operating mode:")*/

			if choice == 1 {
				// Start up server mode
				c.Println("Starting server mode")
				c.ShowPrompt(false)

				// Set the port to listen on
				c.Print("Port to listen on [default 32175]: ")
				portArg := c.ReadLine()
				if portArg == "" {
					portArg = "32175"
				}
				port, err := strconv.Atoi(portArg)
				if err != nil {
					c.Println("Error: Failed to get valid port. Please enter only numbers")
					return
				}
				if port <= 1023 || port >= 65536 {
					c.Println("Error: Port too low / high. Please enter a number between 1024-65535")
					return
				}

				// Start the server
				startModeServer(port)

			} else if choice == 2 {
				// Start up client mode
				c.Println("Starting client mode")
				c.ShowPrompt(false)

				// Set the server ip and port to connect to
				c.Print("Server IP to connect to [default 127.0.0.1]: ")
				serverIP := c.ReadLine()
				if serverIP == "" {
					serverIP = "127.0.0.1"
				}

				// Set the port to connect on
				c.Print("Port to connect on [default 32175]: ")
				portArg := c.ReadLine()
				if portArg == "" {
					portArg = "32175"
				}
				port, err := strconv.Atoi(portArg)
				if err != nil {
					c.Println("Error: Failed to get valid port. Please enter only numbers")
					return
				}
				if port <= 1023 || port >= 65536 {
					c.Println("Error: Port too low / high. Please enter a number between 1024-65535")
					return
				}

				// Set the OTP for encryption
				c.Print("OTP file to use [default otp_src.dat]: ")
				fileName := c.ReadLine()
				if fileName == "" {
					fileName = "otp_src.dat"
				}

				err = startModeClient(serverIP, port, fileName)
				if err != nil {
					c.Println("Error setting up the connection")
					return
				}

			} else {
				c.Println("No valid mode selected")
			}

			c.ShowPrompt(true)
		},
	})

	// Register the OTP reproducible generator command
	shell.AddCmd(&ishell.Cmd{
		Name: "reproduce",
		Help: "reproduce an OTP File [ default name: otp_rep.dat, default size: 10Megabyte ](DEBUG, do not use)",
		Func: func(c *ishell.Context) {
			// Hide the '>>>' prompt
			c.ShowPrompt(false)
			defer c.ShowPrompt(true)

			// Set the file name for the OTP
			c.Print("Set the OTP file name [default: otp_rep.dat]: ")
			fileName := c.ReadLine()
			if fileName == "" {
				fileName = "otp_rep.dat"
			}

			// Set the file size for the OTP
			c.Print("Set the OTP file size in megabyte [default: 10]: ")
			sizeArg := c.ReadLine()
			if sizeArg == "" {
				sizeArg = "10"
			}
			size, err := strconv.Atoi(sizeArg)
			if err != nil {
				c.Println("Error: Failed to get valid size. Please enter only numbers")
				return
			}
			if size <= 0 || size >= 1001 {
				c.Println("Error: OTP file size too small / big. Please enter a number between 1-1000")
				return
			}

			// Set the secret / salt to generate reproduable OTPs
			c.Print("Set the secret for the OTP: ")
			secret := c.ReadLine()
			if secret == "" {
				c.Println("Error: OTP secret must be a string between 1-512 chars")
				return
			}

			c.Println("Generating \"", fileName, "\" OTP file")
			c.ProgressBar().Indeterminate(true)
			c.ProgressBar().Start()

			// Generate the OTP file
			err = generateReproducibleOTP(fileName, size, secret)
			if err != nil {
				c.ProgressBar().Stop()
				c.Println("Error: Failed to generate OTP file")
				c.Err(err)
				return
			}
			c.ProgressBar().Stop()
			c.Println("Reproducible OTP file successfully generated")
		},
	})

	// Register the OTP generator command
	shell.AddCmd(&ishell.Cmd{
		Name: "generate",
		Help: "generate an OTP File [ default name: otp_src.dat, default size: 10Megabyte ](DEBUG, do not use)",
		Func: func(c *ishell.Context) {
			// Hide the '>>>' prompt
			c.ShowPrompt(false)
			defer c.ShowPrompt(true)

			// Set the file name for the OTP
			c.Print("Set the OTP file name [default: otp_src.dat]: ")
			fileName := c.ReadLine()
			if fileName == "" {
				fileName = "otp_src.dat"
			}

			// Set the file size for the OTP
			c.Print("Set the OTP file size in megabyte [default: 10]: ")
			sizeArg := c.ReadLine()
			if sizeArg == "" {
				sizeArg = "10"
			}
			size, err := strconv.Atoi(sizeArg)
			if err != nil {
				c.Println("Error: Failed to get valid size. Please enter only numbers")
				return
			}
			if size <= 0 || size >= 1001 {
				c.Println("Error: OTP file size too small / big. Please enter a number between 1-1000")
				return
			}

			c.Println("Generating \"", fileName, "\" OTP file")
			c.ProgressBar().Indeterminate(true)
			c.ProgressBar().Start()

			// Generate the OTP file
			err = generateOTP(fileName, size)
			if err != nil {
				c.ProgressBar().Stop()
				c.Println("Error: Failed to generate OTP file")
				c.Err(err)
				return
			}
			c.ProgressBar().Stop()
			c.Println("OTP file successfully generated")
		},
	})

	// Register the encrypt command
	shell.AddCmd(&ishell.Cmd{
		Name: "encrypt",
		Help: "encrypt a string with the OTP file [ default file: otp_src.dat ] (DEBUG, do not use)",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 2 {
				c.Println("Error: 1. argument must be the OTP file, 2. argument the plaintext to encrypt surrounded by \"\"")
				return
			}

			// Set the OTP file name
			fileName := c.Args[0]
			if fileName == "" {
				fileName = "otp_src.dat"
			}

			// Set the plaintext to encrypt
			plainText := c.Args[1]
			if plainText == "" {
				c.Println("Error: Plaintext to encrypt cannot be empty")
				return
			}

			// Encrypt the plaintext with the OTP file
			cipherText, err := encrypt(fileName, plainText)
			if err != nil {
				c.Println("Error: Failed to encrypt plaintext")
				c.Err(err)
				return
			}
			c.Println("Ciphertext:", cipherText)
		},
	})

	// Register the decrypt command
	shell.AddCmd(&ishell.Cmd{
		Name: "decrypt",
		Help: "decrypt a string with the OTP file [ default file: otp_src.dat ]",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 2 {
				c.Println("Error: 1. argument must be the OTP file, 2. argument the ciphertext to decrypt surrounded by \"\"")
				return
			}

			// Set the OTP file name
			fileName := c.Args[0]
			if fileName == "" {
				fileName = "otp_src.dat"
			}

			// Set the ciphertext to decrypt
			cipherText := c.Args[1]
			if cipherText == "" {
				c.Println("Error: Ciphertext to decrypt cannot be empty")
				return
			}

			// Encrypt the plaintext with the OTP file
			plainText, err := decrypt(fileName, cipherText)
			if err != nil {
				c.Println("Error: Failed to decrypt ciphertext")
				c.Err(err)
				return
			}
			c.Println("Plaintext:", plainText)
		},
	})

	// Run the interactive prompt
	shell.Run()
	// Teardown the interactive prompt
	shell.Close()
}

/**
 * Decrypt the cipherText with the OTP from fileName
 * Return the decrypted plainText or error if any
 */
func decrypt(fileName string, cipherText string) (plainText string, err error) {

	// Trim newlines / whitespaces from the plaintext
	cipherText = strings.TrimSpace(cipherText)
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	// Open the OTP file
	fd, err := os.OpenFile(fileName, os.O_RDWR, 0666)
	if err != nil {
		return "", err
	}

	// Set the OTP & ciphertext buffer to the same length as the plaintext
	cipherTextLength := int64(len(cipherBytes))
	oneTimePad := make([]byte, cipherTextLength)
	plainTextBytes := make([]byte, cipherTextLength)

	//  Move the offset to EOF - the length of the plaintext
	offset, err := fd.Seek(-cipherTextLength, os.SEEK_END)
	if err != nil {
		return "", err
	}
	// Read in the OTP
	fd.Read(oneTimePad)

	// Remove the used OTP from the file
	err = fd.Truncate(offset)
	// Close it
	defer fd.Close()

	// XOR (instead of modular addition) the ciphertext with the OTP
	for i, cipherTextByte := range cipherBytes {
		plainTextBytes[i] = byte(cipherTextByte) ^ oneTimePad[i]
	}

	// Return the the decrypted plaintext
	return string(plainTextBytes), nil
}

/**
 * Encrypt the plainText with the OTP from fileName
 * Return the encrypted cipherText or error if any
 */
func encrypt(fileName string, plainText string) (cipherText string, err error) {
	// Open the OTP file
	fd, err := os.OpenFile(fileName, os.O_RDWR, 0666)
	if err != nil {
		return "", err
	}

	// Trim newlines / whitespaces from the plaintext
	plainText = strings.TrimSpace(plainText)
	// Set the OTP & ciphertext buffer to the same length as the plaintext
	plainTextLength := int64(len(plainText))
	oneTimePad := make([]byte, plainTextLength)
	cipherTextBytes := make([]byte, plainTextLength)

	//  Move the offset to EOF - the length of the plaintext
	offset, err := fd.Seek(-plainTextLength, os.SEEK_END)
	if err != nil {
		return "", err
	}
	// Read in the OTP
	fd.Read(oneTimePad)

	// Remove the used OTP from the file
	err = fd.Truncate(offset)
	// Close it
	defer fd.Close()

	// XOR (instead of modular addition) the plaintext with the OTP
	for i, plainTextByte := range plainText {
		cipherTextBytes[i] = byte(plainTextByte) ^ oneTimePad[i]
	}

	// Return the base64 encoded ciphertext
	return base64.StdEncoding.EncodeToString(cipherTextBytes) + "\n", nil
}

/**
 * Create an OTP file named fileName of size 1024bytes * 1024bytes * size = megabytes
 * Return error if any
 */
func generateOTP(fileName string, size int) error {
	// Create the file
	fd, err := os.Create(fileName)
	if err != nil {
		return err
	}
	fd.Close()

	// Keep it open in write / append only mode
	fd, err = os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}

	// Create a binary buffer
	binaryBuffer := new(bytes.Buffer)
	// Create the random bytes buffer
	randByteBuffer := make([]byte, 1024 * 1024)

	for i := 1; i <= size; i++ {
		_, err := rand.Read(randByteBuffer)
		if err != nil {
			return err
		}

		// Write the random bytes into the binary buffer
		binary.Write(binaryBuffer, binary.LittleEndian, randByteBuffer)
		// Write the binary buffer to file
		fd.Write(binaryBuffer.Bytes())
		// Reset the buffer
		binaryBuffer.Reset()
	}

	// Close the file
	defer fd.Close()

	return nil
}

/**
 * Create an reproducible OTP named fileName of size 1024bytes * 1024bytes * size = megabytes from secret
 * Return error if any
 * Note: This defeats the method behind an OTP, use for debugging only
 */
func generateReproducibleOTP(fileName string, size int, secret string) error {
	// Create the file
	fd, err := os.Create(fileName)
	if err != nil {
		return err
	}
	fd.Close()

	// Keep it open in write / append only mode
	fd, err = os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}

	// Pregenerate a hash to start off with
	secretBytes := []byte(secret)
	sum := sha512.Sum512(secretBytes)
	// SHA512 generates 64byte, so (1024 * 1024 * size) / 64 = numOfIterations
	for i := 1; i <= (1024 * 1024 * size) / 64; i++ {
			sumBytes := sum[:]
			fd.Write(sumBytes)
			sum = sha512.Sum512(append(secretBytes, sumBytes...))
	}

	// Close the file
	defer fd.Close()

	return nil
}

/**
 * Start up a listening server to broadcast messages to all clients connected
 */
func startModeServer(port int) {
	// Number of people whom ever connected
	clientCount := 0

	// All people who are connected; a map wherein
	// the keys are net.Conn objects and the values
	// are client "ids", an integer.
	allClients := make(map[net.Conn]int)

	// Channel into which the TCP server will push
	// new connections.
	newConnections := make(chan net.Conn)

	// Channel into which we'll push dead connections
	// for removal from allClients.
	deadConnections := make(chan net.Conn)

	// Channel into which we'll push messages from
	// connected clients so that we can broadcast them
	// to every connection in allClients.
	messages := make(chan string)

	// Start the TCP server
	server, err := net.Listen("tcp", ":" + strconv.Itoa(port))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	log.Printf("Started server, listening on %s", strconv.Itoa(port))

	// Tell the server to accept connections forever
	// and push new connections into the newConnections channel.
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			newConnections <- conn
		}
	}()

	// Loop endlessly
	for {

		// Handle 1) new connections; 2) dead connections;
		// and, 3) broadcast messages.
		select {

		// Accept new clients
		case conn := <-newConnections:

			log.Printf("Accepted new client, #%d", clientCount)

			// Add this connection to the `allClients` map
			allClients[conn] = clientCount
			clientCount += 1

			// Constantly read incoming messages from this
			// client in a goroutine and push those onto
			// the messages channel for broadcast to others.
			go func(conn net.Conn, clientId int) {
				reader := bufio.NewReader(conn)
				for {
					incoming, err := reader.ReadString('\n')
					if err != nil {
						break
					}
					messages <- fmt.Sprintf("%d>%s", clientId, incoming)
				}

				// When we encouter `err` reading, send this
				// connection to `deadConnections` for removal.
				deadConnections <- conn

			}(conn, allClients[conn])

		// Accept messages from connected clients
		case message := <-messages:
			clientIndex := message[:strings.IndexByte(message, '>')]
			clientId, err := strconv.Atoi(clientIndex)
			if err != nil {
				log.Printf("Could not determine client, discarding message")
				continue
			}

			// Loop over all connected clients
			for conn, id := range allClients {
				if id == clientId {
					continue
				}

				// Send them a message in a go-routine
				// so that the network operation doesn't block
				go func(conn net.Conn, message string) {
					_, err := conn.Write([]byte(message))

					// If there was an error communicating
					// with them, the connection is dead.
					if err != nil {
						deadConnections <- conn
					}
				}(conn, message[strings.IndexByte(message, '>') + 1:])
			}
			log.Printf("New message: %s", message[strings.IndexByte(message, '>') + 1:])
			log.Printf("Broadcast to %d clients", len(allClients) - 1)

			// Remove dead clients
		case conn := <-deadConnections:
			clientId := allClients[conn]
			log.Printf("Client %d disconnected", clientId)
			delete(allClients, conn)
			messages <- fmt.Sprintf("Client %d disconnected", clientId)
		}
	}
}

/**
 * Start up a client connecting to serverIP on port
 */
func startModeClient(serverIP string, port int, fileName string) error {
	// Establish connection to the server
	conn, err := net.Dial("tcp", serverIP + ":" + strconv.Itoa(port))
	if err != nil {
		log.Printf("Unable to establish connection to %s on port %s", serverIP, strconv.Itoa(port))
		return err
	}

	// The receiver channel
	received := make(chan string)
	// The sender channel
	sent := make(chan string)


	// Receive messages in a routine
	go func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		for {
			incoming, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			received <- fmt.Sprintf("%s", incoming)
		}
	}(conn)

	// Send messages in a routine (read from STDIN)
	go func(conn net.Conn) {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("You>")
			message, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			sent <- fmt.Sprintf("%s", message)
		}
	}(conn)

	// Loop endlessly
	for {

		// Handle 1) receive messages; 2) send messages;
		select {
			case recvMsg := <- received:
				go func(recvMsg string) {
					recvMsg, err = decrypt(fileName, recvMsg)
					if err != nil {
						fmt.Println("Error: Failure to decrypt message. Please renegotiate an OTP with the partner")
						panic(err)
					}

					fmt.Printf("\nCli>%s\n", recvMsg)
					fmt.Print("You>")
				}(recvMsg)

			case sendMsg := <- sent:
				go func(sendMsg string, conn net.Conn) {
					sendMsg, err = encrypt(fileName, sendMsg)
					if err != nil {
						fmt.Println("Error: Failure to encrypt message. Please renegotiate an OTP with the partner")
						panic("Encryption failed")
					}

					_, err := conn.Write([]byte(sendMsg))
					if err != nil {
						panic("QUIT")
					}
				}(sendMsg, conn)
		}
	}

	return nil
}