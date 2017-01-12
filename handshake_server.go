package dtls

func (hc *handshakeContext) isFlightOneComplete() bool {
	if hc.clientHello == nil {
		return false
	}
	return true
}

func (hc *handshakeContext) isFlightThreeComplete() bool {
	if hc.certificateRequest != nil && hc.clientCertificate == nil {
		return false
	}
	if hc.clientKeyExchange == nil {
		return false
	}
	// TODO: except when certificate contains fixed Diffie-Hellman parameters
	// https://tools.ietf.org/html/rfc4346#section-7.4.8
	if hc.clientCertificate != nil && hc.certificateVerify == nil {
		return false
	}
	if hc.clientFinished == nil {
		return false
	}
	return true
}
