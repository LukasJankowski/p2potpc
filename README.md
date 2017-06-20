Peer-to-Peer One-Time-Pad Encrypted Communication
=================================================
__IMPORTANT:__ This is merely a proof of concept and should __NOT__ be used in a production
enviroment. I am neither a security expert nor a cryptographer. This application is almost
guranteed to contain flaws, which could allow a third party to obtain sensitive information.
You've been warned.

About
-----
This is nothing more than a fun little project I worked on in order to learn Go(lang) and its
binary utilities a little better, so expect code duplication / inproper error handling etc.
That aside it is basically an interactive CLI app to allow encrypted communication via one time pads.
You first go ahead and start the app, which will allow you a couple of options, ranging from creating
one-time-pads to connecting to a server and engaging a chat with another client.
I don't consider it stable, it works for now and I will probably continue working on it.
That said feel free to play around with it.

Installation
------------
A simple "go build main.go" should do the trick, you might need to pull in [ishell](https://github.com/abiosoft/ishell/) and its dependencies.
Also I noticed an error when trying to run this in windows in line 166 of ishells actions.go, a simple fix like that does the trick:
*Note: I might be mistaken here or overlooked something, the fix did the job so I didn't look further into it.*
```golang
func clearScreen(s *Shell) error {
	// _, err := readline.ClearScreen(s.writer)
	err := readline.ClearScreen(s.writer)
	return err
}
````

Usage
-----
In order to encrypt anything or engage a chat with another party, it is required that both parties have the same OTP file.
That means that one party should generate an OTP and send (or give it in person) to the other.
(If you're testing it, you can also use the "reproduce" option and share the secret)
Now both parties can engage in an encrypted communication if they use the same OTP file, which they will be prompted for.
You could also manually encrypt the messages and decrypt them using the "encrypt" and "decrypt" commands.
*Note: If the OTP files get out of sync, they need to be manually cut to the right size again or trashed entirely and regenerated anew.*

How
---
The principle behind this application is simple:
 1. First an OTP file is generated from a random source (crypt/rand)
 2. The bits'n bytes are written to the file in binary
 3. If an encryption is now requested, the application pulls the same length that the plaintext has from the end of the OTP file
   (this makes it easier to truncate and shave off the used bytes) and XORs them with the plaintext bytes
4. The resulting ciphertext is base64 encoded so that it can safely be displayed in the command-line or send to the server
5. // ---> If a server is used
6. The server simply accepts incoming connections and sends the received message to the other client(s)
  (At no point does anyone beside the client who generated the ciphertext know the plaintext, given that the OTP is only shared with the desired receiver)
7. // ---> /server end
8. The receiver receives the base64 encoded ciphertext and goes ahead and decodes it.
9. The application pulls the same length in bytes that the ciphertext has from the end of the OTP file
   (again it makes it easier to truncate the file afterwards) and XORs them with the plaintext bytes
10. The resulting plaintext can be safely displayed to the receiver and both OTP files (the client who encrypted the plaintext, and the one who decrypted it
    are still in sync)

Help
----
You have a couple of commands at your disposal:
```txt
generate  // be guided through the generation of an OTP file
reproduce // be guided through the generation of a reproducible OTP file (Note: This defeats the purpose of OTPs and should only be used for testing)
encrypt   // generate an encrypted string based off the plaintext and the OTP file you choose
decrypt   // decrypt an encrypted string based off the ciphertext and the OTP file used to encrypt it
mode      // Enter communications mode
---server // Act as the server relaying / broadcasting the encrypted messages between the clients connected to it
---client // Connect to a server and engage in an encrypted communication with another client
---relay  // Not yet implemented
clear     // clear the screen
help      // display the help
exit      // quit the application
```
You can Ctrl-C at any time to quit the application (may require you to press it twice, since it's using [ishell](https://github.com/abiosoft/ishell/) behind the scenes)

Theory
------
To quote [wikipedia](https://en.wikipedia.org/wiki/One-time_pad):
>In cryptography, the one-time pad (OTP) is an encryption technique that cannot be cracked, but requires the use of a one-time pre-shared key the same size as, or longer than, the message being sent. In this technique, a plaintext is paired with a random secret key (also referred to as a one-time pad). Then, each bit or character of the plaintext is encrypted by combining it with the corresponding bit or character from the pad using modular addition. If the key is truly random, is at least as long as the plaintext, is never reused in whole or in part, and is kept completely secret, then the resulting ciphertext will be impossible to decrypt or break.[1][2][3] It has also been proven that any cipher with the perfect secrecy property must use keys with effectively the same requirements as OTP keys.[4] However, practical problems have prevented one-time pads from being widely used.

This application still has the same practical flaws the article is talking about. Some of them are:
* The OTP must be known to both parties, and there is not always the option of seeing the other party in person and giving them an USB device containing the OTP.
  That means the transport of the OTP must be done over other channels, thereby exposing it to third-parties.
* Once (through internet connection loss etc.) a message is lost both OTPs are out of sync and a new OTP (or shorting the existing one) must be created (see Todo)
* Once an OTP runs out of random bytes (size: 0) all encryption is lost and an OTP must be generated and shared again, thereby exposing it to problem 1
* Once an OTP is compromised the third-party can eavesdrop on the communication in plaintext (but that is a problem with most ciphers once the secret is known)
* Tons of other problems I can't even think about...

TODO
----
Some of the problems listed above can be circumvented. Out-of-sync OTPs can be avoided through a better communication stack, checking the online status of each client,
rejecting messages if one party is losing connection etc.

Another way to fix some of the out-of-sync problems could be to validate both OTPs with a checksum, let both parties agree to use a common length to short the OTP to
etc.

Renegotiating a new OTP once the old one is running short can also be done by using the "reproduce" option with a secret shared over the old one's last few bytes, thereby preserving the secrets integrity and rebuilding an OTP without the need to share an USB device.

Split the main.go file into smaller chunks / remove code duplication / do proper error checking etc.

A lot of small improvements...