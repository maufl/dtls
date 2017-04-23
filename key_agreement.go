package dtls

import (
	"github.com/maufl/dhkx"
	"math/big"
)

type keyAgreement interface {
	processServerKeyExchange(clientRandom, serverRandom random, serverKeyExchange handshakeServerKeyExchange) error
	generateClientKeyExchange() ([]byte, handshakeClientKeyExchange, error)
	generateServerKeyExchange() ([]byte, error)
	processClientKeyExchange(handshakeClientKeyExchange) ([]byte, error)
}

type dheKeyAgreement struct {
	PrivateKey *dhkx.DHKey
	PublicKey  *dhkx.DHKey
	Group      *dhkx.DHGroup
}

func (ka *dheKeyAgreement) processServerKeyExchange(clientRandom, serverRandom random, serverKeyExchange handshakeServerKeyExchange) (err error) {
	ka.PublicKey = dhkx.NewPublicKey(serverKeyExchange.Params.PublicKey)

	var p, g big.Int
	p.SetBytes(serverKeyExchange.Params.P)
	g.SetBytes(serverKeyExchange.Params.G)

	ka.Group = dhkx.CreateGroup(&p, &g)
	ka.PrivateKey, err = ka.Group.GeneratePrivateKey(nil)
	return
}

func (ka *dheKeyAgreement) generateClientKeyExchange() (preMasterSecret []byte, clientKeyExchange handshakeClientKeyExchange, err error) {
	clientKeyExchange.clientDiffieHellmanPublic.PublicKey = ka.PrivateKey.Bytes()
	if key, err := ka.Group.ComputeKey(ka.PublicKey, ka.PrivateKey); err == nil {
		preMasterSecret = key.Bytes()
	}
	return
}

func (ka *dheKeyAgreement) generateServerKeyExchange() (serverKeyExchange []byte, err error) {
	if ka.Group, err = dhkx.GetGroup(0); err != nil {
		return
	}
	if ka.PrivateKey, err = ka.Group.GeneratePrivateKey(nil); err != nil {
		return
	}
	return handshakeServerKeyExchange{Params: serverDHParams{P: ka.Group.P().Bytes(), G: ka.Group.G().Bytes(), PublicKey: ka.PrivateKey.Bytes()}}.Bytes(), nil
}

func (ka *dheKeyAgreement) processClientKeyExchange(clientKeyExchange handshakeClientKeyExchange) (preMasterSecret []byte, err error) {
	ka.PublicKey = dhkx.NewPublicKey(clientKeyExchange.PublicKey)
	if key, err := ka.Group.ComputeKey(ka.PublicKey, ka.PrivateKey); err == nil {
		preMasterSecret = key.Bytes()
	}
	return
}
