package dtls

import ()

type handshakeContext struct {
	*Conn
	CipherSuite
	*KeyAgreement

	isServer                  bool
	cookie                    []byte
	nextReceiveSequenceNumber uint64
	sequenceNumber            uint64
	sessionID                 []byte
	clientRandom              Random
	serverRandom              Random
	currentFlight             int

	//We omit the pre-flight, i.e. HelloVerify because otherwise we would need to keep state
	//defeating the purpos of HelloVerify
	//Flight 1
	clientHello *Handshake

	//Flight 2
	serverHello        *Handshake
	serverCertificate  *Handshake
	serverKeyExchange  *Handshake
	certificateRequest *Handshake
	severHelloDone     *Handshake

	//Flight 3
	clientCertificate *Handshake
	clientKeyExchange *Handshake
	certificateVerify *Handshake
	clientFinished    *Handshake

	//Flight 4
	serverFinished *Handshake

	fragmentBuffer map[uint64][]byte
	messageBuffer  chan *Handshake
}

func (hc *handshakeContext) receiveMessage(message *Handshake) {
	if message.SequenceNumber < hc.nextReceiveSequenceNumber {
		return
	}
	if message.SequenceNumber > hc.nextReceiveSequenceNumber {
		hc.messageBuffer <- message
		return
	}
	hc.storeMessage(message)
	hc.nextReceiveSequenceNumber += 1
	if hc.isCurrentFlightComplete() {
		hc.currentFlight += 1
		hc.doNextFlight()
		hc.currentFlight += 1
	}
}

func (hc *handshakeContext) doNextFlight() {
	switch hc.currentFlight {
	case 1:
		hc.doFlightOne()
	case 2:
		hc.doFlightTwo()
	case 3:
		hc.doFlightThree()
	case 4:
		hc.doFlightFour()
	default:
		panic("Impossible handshake state")
	}
}
func (hc *handshakeContext) doFlightTwo() {
	//TODO
}

func (hc *handshakeContext) isCurrentFlightComplete() bool {
	switch hc.currentFlight {
	case 1:
		return hc.isFlightOneComplete()
	case 2:
		return hc.isFlightTwoComplete()
	case 3:
		return hc.isFlightThreeComplete()
	case 4:
		return hc.isFlightFourComplete()
	default:
		panic("Impossible handshake state")
	}
}

func (hc *handshakeContext) storeMessage(message *Handshake) {
	if hc.currentFlight == 1 && message.Type == ClientHello {
		hc.clientHello = message
		return
		//TODO: handle out of order handshake messages?
	}
	if hc.currentFlight == 2 {
		switch message.Type {
		case ServerHello:
			hc.serverHello = message
		case Certificate:
			hc.serverCertificate = message
		case ServerKeyExchange:
			hc.serverKeyExchange = message
		case CertificateRequest:
			hc.certificateRequest = message
		case ServerHelloDone:
			hc.serverHelloDone = message
		default:
			//TODO: how do we handle invalid handshake messages?
		}
		return
	}
	if hc.currentFlight == 3 {
		switch message.Type {
		case Certificate:
			hc.clientCertificate = message
		case ClientKeyExchange:
			hc.clientKeyExchange = message
		case CertificateVerify:
			hc.certificateVerify = message
		case Finished:
			hc.clientFinished = message
		default:
			//TODO: how do we handle invalid handshake messages?
		}
		return
	}
	if hc.currentFlight == 4 && message.Type == Finished {
		hc.serverFinished = message
		//TODO: handle out of order handshake messages?
		return
	}
}
