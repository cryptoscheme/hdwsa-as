package hdwsaas

import (
	"github.com/Nik-U/pbc"
)

type PublicParams struct {
	rbits uint32
	qbits uint32

	pairing *pbc.Pairing
	P       *pbc.Element // generator for G1
	PBytes  []byte       // generator for G1 in bytes form
}

type WalletSecretKey struct {
	alpha *pbc.Element //  Zp
	beta  *pbc.Element //  Zp
	WalletPublicKey
}

type WalletPublicKey struct {
	AID *pbc.Element //  G1
	BID *pbc.Element //  G1
}

type DVK struct {
	Qr  *pbc.Element // Qr =  rP  G1
	Qvk *pbc.Element // G2
}

type signature struct {
	XPrime *pbc.Element // G2
	SPrime *pbc.Element // G1
	TPrime *pbc.Element // G1
}

type aggregatesignature struct {
	Xn []*pbc.Element // G2
	Sn *pbc.Element   // G1
	Tn *pbc.Element   // G1
}

type DSK struct {
	dsk *pbc.Element // G1
}
