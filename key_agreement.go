package dtls

import (
	"github.com/monnand/dhkx"
	"math/big"
)

type KeyAgreement interface {
	ProcessServerKeyExchange(clientRandom, serverRandom Random, serverKeyExchange HandshakeServerKeyExchange) error
	GenerateClientKeyExchange() ([]byte, HandshakeClientKeyExchange, error)
}

type DHKeyAgreement struct {
	PrivateKey *dhkx.DHKey
	PublicKey  *dhkx.DHKey
	Group      *dhkx.DHGroup
}

func (ka *DHKeyAgreement) ProcessServerKeyExchange(clientRandom, serverRandom Random, serverKeyExchange HandshakeServerKeyExchange) (err error) {
	ka.PublicKey = dhkx.NewPublicKey(serverKeyExchange.Params.PublicKey)

	var p, g big.Int
	p.SetBytes(serverKeyExchange.Params.P)
	g.SetBytes(serverKeyExchange.Params.G)

	ka.Group = dhkx.CreateGroup(&p, &g)
	ka.PrivateKey, err = ka.Group.GeneratePrivateKey(nil)
	return
}

func (ka *DHKeyAgreement) GenerateClientKeyExchange() (preMasterSecret []byte, clientKeyExchange HandshakeClientKeyExchange, err error) {
	clientKeyExchange.ClientDiffieHellmanPublic.PublicKey = ka.PrivateKey.Bytes()
	if key, err := ka.Group.ComputeKey(ka.PublicKey, ka.PrivateKey); err == nil {
		preMasterSecret = key.Bytes()
	}
	return
}
