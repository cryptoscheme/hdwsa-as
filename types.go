package hdwsa2

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
	Qr       *pbc.Element // Qr =  rP  G1
	Qvk_zero *pbc.Element // G2
	Qvk_one  *pbc.Element // G2
}

type signature struct {
	XPrime *pbc.Element // G2
	SPrime *pbc.Element // G1
}

type aggregatesignature struct {
	X  []*pbc.Element
	Sn *pbc.Element // G1
}

type DSK struct {
	dsk_zero *pbc.Element // G1
	dsk_one  *pbc.Element // G1
}
