package main

import "fmt"

// SERVER

// Server banner
func serverBanner(hostname string) []byte {
	return []byte(fmt.Sprintf("220 %s ESMTP Postfix\r\n", hostname))
}

// EHLO multi-line response advertising VRFY
func serverEhloResponse(hostname string) []byte {
	return []byte(fmt.Sprintf(
		"250-%s\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN\r\n",
		hostname,
	))
}

// VRFY positive reply (user exists)
func serverVrfyPositive(mailbox string) []byte {
	return []byte(fmt.Sprintf("250 2.1.5 <%s>\r\n", mailbox))
}

// VRFY negative reply
func serverVrfyNegative() []byte {
	return []byte("550 5.1.1 User unknown\r\n")
}

// MAIL FROM OK
func serverMailFromOk() []byte {
	return []byte("250 2.1.0 Ok\r\n")
}

// RCPT TO OK (mailbox exists)
func serverRcptToOk() []byte {
	return []byte("250 2.1.5 Ok\r\n")
}

// RCPT TO user unknown
func serverRcptToUnknown() []byte {
	return []byte("550 5.1.1 No such user\r\n")
}

// RSET OK
func serverRsetOk() []byte {
	return []byte("250 2.0.0 Ok\r\n")
}

// QUIT goodbye
func serverQuitBye() []byte {
	return []byte("221 2.0.0 Bye\r\n")
}

// CLIENT

func clientEhlo(domain string) []byte {
	return []byte(fmt.Sprintf("EHLO %s\r\n", domain))
}

func clientVrfy(mailbox string) []byte {
	return []byte(fmt.Sprintf("VRFY %s\r\n", mailbox))
}

func clientMailFrom(address string) []byte {
	return []byte(fmt.Sprintf("MAIL FROM:<%s>\r\n", address))
}

func clientRcptTo(address string) []byte {
	return []byte(fmt.Sprintf("RCPT TO:<%s>\r\n", address))
}

func clientRset() []byte {
	return []byte("RSET\r\n")
}

func clientQuit() []byte {
	return []byte("QUIT\r\n")
}
func sendpacket() {

}
