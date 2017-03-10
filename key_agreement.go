package dtls

import (
	"github.com/maufl/dhkx"
	"math/big"
)

type KeyAgreement interface {
	ProcessServerKeyExchange(clientRandom, serverRandom Random, serverKeyExchange HandshakeServerKeyExchange) error
	GenerateClientKeyExchange() ([]byte, HandshakeClientKeyExchange, error)
	GenerateServerKeyExchange() ([]byte, error)
	ProcessClientKeyExchange(HandshakeClientKeyExchange) ([]byte, error)
}

type DHEKeyAgreement struct {
	PrivateKey *dhkx.DHKey
	PublicKey  *dhkx.DHKey
	Group      *dhkx.DHGroup
}

func (ka *DHEKeyAgreement) ProcessServerKeyExchange(clientRandom, serverRandom Random, serverKeyExchange HandshakeServerKeyExchange) (err error) {
	ka.PublicKey = dhkx.NewPublicKey(serverKeyExchange.Params.PublicKey)

	var p, g big.Int
	p.SetBytes(serverKeyExchange.Params.P)
	g.SetBytes(serverKeyExchange.Params.G)

	ka.Group = dhkx.CreateGroup(&p, &g)
	ka.PrivateKey, err = ka.Group.GeneratePrivateKey(nil)
	return
}

func (ka *DHEKeyAgreement) GenerateClientKeyExchange() (preMasterSecret []byte, clientKeyExchange HandshakeClientKeyExchange, err error) {
	clientKeyExchange.ClientDiffieHellmanPublic.PublicKey = ka.PrivateKey.Bytes()
	if key, err := ka.Group.ComputeKey(ka.PublicKey, ka.PrivateKey); err == nil {
		preMasterSecret = key.Bytes()
	}
	return
}

func (ka *DHEKeyAgreement) GenerateServerKeyExchange() (serverKeyExchange []byte, err error) {
	if ka.Group, err = dhkx.GetGroup(0); err != nil {
		return
	}
	if ka.PrivateKey, err = ka.Group.GeneratePrivateKey(nil); err != nil {
		return
	}
	return HandshakeServerKeyExchange{Params: ServerDHParams{P: ka.Group.P().Bytes(), G: ka.Group.G().Bytes(), PublicKey: ka.PrivateKey.Bytes()}}.Bytes(), nil
}

func (ka *DHEKeyAgreement) ProcessClientKeyExchange(clientKeyExchange HandshakeClientKeyExchange) (preMasterSecret []byte, err error) {
	ka.PublicKey = dhkx.NewPublicKey(clientKeyExchange.PublicKey)
	if key, err := ka.Group.ComputeKey(ka.PublicKey, ka.PrivateKey); err == nil {
		preMasterSecret = key.Bytes()
	}
	return
}
