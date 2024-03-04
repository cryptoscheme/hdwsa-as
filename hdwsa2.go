// package hdwsa2 implements `HDWSA2: A Secure Hierarchical Deterministic Wallet Supporting Stealth Address and Signature Aggregation`
package hdwsaas

import (
	"crypto/sha256"
	"strings"
	"sync"

	"github.com/Nik-U/pbc"
)

var hashFunc = sha256.New() // pbc.SetFromStringHash API will always reset hashFunc inner state before write.

// domain separation tag
const (
	DSTForH0 = "hdwsa-sa.h0"
	DSTForH1 = "hdwsa-sa.h1"
	DSTForH2 = "hdwsa-sa.h2"
	DSTForH3 = "hdwsa-sa.h3"
	DSTForH4 = "hdwsa-sa.h4"
	DSTForH5 = "hdwsa-sa.h5"
	DSTForH6 = "hdwsa-sa.h6"
)

func Setup(rbits, qbits uint32) *PublicParams {
	params := pbc.GenerateA(rbits, qbits)
	pairing := params.NewPairing()
REPEAT:
	P := pairing.NewG1().Rand() // generator P for G1
	if P.Is0() {
		goto REPEAT
	}
	return &PublicParams{
		rbits:   rbits,
		qbits:   qbits,
		pairing: pairing,
		P:       P,
		PBytes:  P.Bytes(),
	}
}

func (pp *PublicParams) RootWalletKeyGen(ids []string) (WalletSecretKey, WalletPublicKey) {
	var alpha, beta *pbc.Element // master secret key
REPEAT0:
	if alpha = pp.pairing.NewZr().Rand(); alpha.Is0() {
		goto REPEAT0
	}
	AIDC := make(chan *pbc.Element, 1)
	go func() {
		AIDC <- pp.pairing.NewG1().PowZn(pp.P, alpha)
		close(AIDC)
	}()

REPEAT1:
	if beta = pp.pairing.NewZr().Rand(); beta.Is0() {
		goto REPEAT1
	}

	BID := pp.pairing.NewG1().PowZn(pp.P, beta)
	AID := <-AIDC
	return WalletSecretKey{
			alpha: alpha,
			beta:  beta,
			WalletPublicKey: WalletPublicKey{
				AID: AID,
				BID: BID,
			},
		},
		WalletPublicKey{
			AID: AID,
			BID: BID,
		}
}

func (pp *PublicParams) WalletKeyDelegate(idt []string, wpk WalletPublicKey, wsk WalletSecretKey) (WalletPublicKey, WalletSecretKey) {
	// compute QID
REPEAT0:
	Qid := pp.pairing.NewG1().SetFromStringHash(DSTForH0+strings.Join(idt, ""), hashFunc) // QID
	if Qid.Is0() {
		goto REPEAT0
	}

	var alphaID, betaID *pbc.Element // Zp
REPEAT1:
	if alphaID = pp.pairing.NewZr().SetFromStringHash(DSTForH1+Qid.String()+pp.pairing.NewG1().PowZn(Qid, wsk.alpha).String(), hashFunc); alphaID.Is0() {
		goto REPEAT1
	}

	AIDC := make(chan *pbc.Element, 1)
	go func() {
		AIDC <- pp.pairing.NewG1().PowZn(pp.P, alphaID)
		close(AIDC)
	}()

REPEAT2:
	if betaID = pp.pairing.NewZr().SetFromStringHash(DSTForH2+Qid.String()+pp.pairing.NewG1().PowZn(Qid, wsk.beta).String(), hashFunc); betaID.Is0() {
		goto REPEAT2
	}

	BID := pp.pairing.NewG1().PowZn(pp.P, betaID)
	AID := <-AIDC
	return WalletPublicKey{
			AID: AID,
			BID: BID,
		},
		WalletSecretKey{
			alpha: alphaID,
			beta:  betaID,
			WalletPublicKey: WalletPublicKey{
				AID: AID,
				BID: BID,
			},
		}
}

func (pp *PublicParams) VerifyKeyDerive(idt []string, wpk *WalletPublicKey) *DVK {
REPEAT0:
	r := pp.pairing.NewZr().Rand() // pick a random r
	if r.Is0() {
		goto REPEAT0
	}
	QrC := make(chan *pbc.Element, 1)
	go func() {
		QrC <- pp.pairing.NewG1().PowZn(pp.P, r) // Qr = rP
		close(QrC)
	}()

	qid := pp.pairing.NewG1().PowZn(wpk.BID, r) // rBID
	var build strings.Builder
	build.WriteString(DSTForH3)
	build.WriteString(wpk.BID.String())
	Qr := <-QrC
	build.WriteString(Qr.String())
	build.WriteString(qid.String())
REPEAT1:
	sha256Func := sha256.New()
	h3 := pp.pairing.NewG1().SetFromStringHash(build.String(), sha256Func)
	if h3.Is0() {
		goto REPEAT1
	}
	return &DVK{Qr, pp.pairing.NewGT().Set1().Pair(h3, pp.pairing.NewG1().Neg(wpk.AID))}
}

func (pp *PublicParams) VerifyKeyCheck(dvk *DVK, ID []string, wpk WalletPublicKey, wsk WalletSecretKey) bool {
	sha256Func := sha256.New()
	h3 := pp.pairing.NewG1().SetFromStringHash(DSTForH3+wpk.BID.String()+dvk.Qr.String()+
		pp.pairing.NewG1().PowZn(dvk.Qr, wsk.beta).String(), sha256Func)
	pair := pp.pairing.NewGT().Pair(h3, pp.pairing.NewG1().Neg(wpk.AID))
	return dvk.Qvk.Equals(pair)
}

func (pp *PublicParams) SignKeyDerive(dvk *DVK, idt []string, wpk WalletPublicKey, wsk WalletSecretKey) *DSK {
	Q1Ch := make(chan *pbc.Element, 1)
	go func() {
		Q1Ch <- pp.pairing.NewG1().PowZn(dvk.Qr, wsk.beta) // compute beta * Qr
		close(Q1Ch)
	}()
	var build strings.Builder
	build.WriteString(DSTForH3)
	build.WriteString(wpk.BID.String())
	build.WriteString(dvk.Qr.String())
	Q1 := <-Q1Ch
	build.WriteString(Q1.String())
	sha256Func := sha256.New()
	h3 := pp.pairing.NewG1().SetFromStringHash(build.String(), sha256Func) // compute H3(*, *, *)
	return &DSK{pp.pairing.NewG1().PowZn(h3, wsk.alpha)}
}

func (pp *PublicParams) SSign(w string, m []byte, dvk *DVK, dsk *DSK) *signature {
	// pick random x
REPEAT0:
	x := pp.pairing.NewZr().Rand() // pick a random number x
	if x.Is0() {
		goto REPEAT0
	}
	xPCh := make(chan *pbc.Element, 1)
	// compute xP
	go func() {
		xPCh <- pp.pairing.NewG1().PowZn(pp.P, x)
		close(xPCh)
	}()
	// compute T' = rP
	r := pp.pairing.NewZr().Rand() // pick a random number r
	if r.Is0() {
		goto REPEAT0
	}
	rPCh := make(chan *pbc.Element, 1)
	go func() {
		rPCh <- pp.pairing.NewG1().PowZn(pp.P, r) // compute rP
		close(rPCh)
	}()

	xP := <-xPCh
	// compute X'
	XPrime := pp.pairing.NewGT().Pair(xP, pp.P)

	rstItemC := make(chan *pbc.Element, 1)
	go func() {
		sha256Func := sha256.New()
	REPEAT1:
		c := pp.pairing.NewZr().SetFromStringHash(DSTForH4+dvk.Qr.String()+dvk.Qvk.String()+string(m)+XPrime.String(), sha256Func)
		if c.Is0() {
			goto REPEAT1
		}
		// compute h = H6(dvk, m, w)
	REPEAT2:
		h := pp.pairing.NewZr().SetFromStringHash(DSTForH6+dvk.Qr.String()+dvk.Qvk.String()+string(m)+XPrime.String()+w, sha256Func)
		if h.Is0() {
			goto REPEAT2
		}
		// compute c*h
		ch := pp.pairing.NewZr().MulZn(c, h)
		rstItem := pp.pairing.NewG1().PowZn(dsk.dsk, ch) // compute c*h*dsk
		rstItemC <- rstItem
		close(rstItemC)
	}()

REPEAT3:
	sha256Func := sha256.New()
	Pw := pp.pairing.NewG1().SetFromStringHash(DSTForH5+w, sha256Func)
	if Pw.Is0() {
		goto REPEAT3
	}
	ndItem := pp.pairing.NewG1().PowZn(Pw, r) // compute rPw
	SPrime := (<-rstItemC).ThenAdd(ndItem).ThenAdd(xP)
	return &signature{XPrime: XPrime, SPrime: SPrime, TPrime: <-rPCh}
}

func (pp *PublicParams) SVerify(w string, m []byte, sigma *signature, dvk *DVK) bool {
	if sigma != nil || dvk != nil {
		// compute e(S', P)
		lshCh := make(chan *pbc.Element, 1)
		go func() {
			lshCh <- pp.pairing.NewGT().Pair(sigma.SPrime, pp.P)
			close(lshCh)
		}()
		tempCh := make(chan *pbc.Element, 1)
		go func() {
			sha256Func := sha256.New()
			c := pp.pairing.NewZr().SetFromStringHash(DSTForH4+dvk.Qr.String()+dvk.Qvk.String()+string(m)+sigma.XPrime.String(), sha256Func)
			h := pp.pairing.NewZr().SetFromStringHash(DSTForH6+dvk.Qr.String()+dvk.Qvk.String()+string(m)+sigma.XPrime.String()+w, sha256Func)
			ch := pp.pairing.NewZr().MulZn(c, h)
			tempCh <- pp.pairing.NewGT().PowZn(dvk.Qvk, pp.pairing.NewZr().Neg(ch))
			close(tempCh)
		}()

		Pw := pp.pairing.NewG1().Set0()
		sha256Func := sha256.New()
		Pw = Pw.SetFromStringHash(DSTForH5+w, sha256Func)
		pair := pp.pairing.NewGT().Pair(sigma.TPrime, Pw)
		gt := pp.pairing.NewGT().Set1()
		rsh := gt.Mul(<-tempCh, pair)
		finalgt := pp.pairing.NewGT().Set1()
		finalgt.Mul(rsh, sigma.XPrime)

		lsh := <-lshCh
		return lsh.Equals(finalgt)
	}
	return false
}

// Assume all signature have the same w.
func (pp *PublicParams) Aggregation(w string, sigma ...*signature) aggregatesignature {
	Xn := make([]*pbc.Element, len(sigma))
	Sn := pp.pairing.NewG1().Set0()
	Tn := pp.pairing.NewG1().Set0()

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func(_sigma ...*signature) {
		defer wg.Done()
		for i := range _sigma {
			if _sigma[i] == nil {
				continue
			}
			Xn[i] = pp.pairing.NewG1().Set0()
			Xn[i] = _sigma[i].XPrime
			Sn.ThenAdd(_sigma[i].SPrime)
		}
	}(sigma...)

	go func(_sigma ...*signature) {
		defer wg.Done()
		for i := range _sigma {
			if _sigma[i] == nil {
				continue
			}
			if Tn == nil {
				Tn = pp.pairing.NewG1().Set0()
			}
			Tn.ThenAdd(_sigma[i].TPrime)
		}
	}(sigma...)
	wg.Wait()
	return aggregatesignature{Xn, Sn, Tn}
}

func (pp *PublicParams) AggVerify(w string, ms [][]byte, as aggregatesignature, dvks []DVK) bool {
	sha256Func := sha256.New()
	Pw := pp.pairing.NewG1().SetFromStringHash(DSTForH5+w, sha256Func)
	// compute e(Sn, P)
	lshC := make(chan *pbc.Element, 1)
	go func() {
		lshC <- pp.pairing.NewGT().Set1().Pair(as.Sn, pp.P)
		close(lshC)
	}()

	// compute e(Tn, Pw)
	rshTermTwoC := make(chan *pbc.Element, 1)
	go func() {
		rshTermTwoC <- pp.pairing.NewGT().Set1().Pair(as.Tn, Pw)
		close(rshTermTwoC)
	}()

	// compute π(Xi)
	π_XiC := make(chan *pbc.Element, 1)
	go func() {
		π_Xi := pp.pairing.NewGT().Set1()
		for i := range as.Xn {
			π_Xi.ThenMul(as.Xn[i])
		}
		π_XiC <- π_Xi
		close(π_XiC)
	}()

	c_i_C := make(chan []*pbc.Element, 1)
	go func() {
		sha256Func := sha256.New()
		c_i := make([]*pbc.Element, len(ms))
		for i := 0; i < len(ms); i++ {
			c_i[i] = pp.pairing.NewZr().SetFromStringHash(DSTForH4+dvks[i].Qr.String()+dvks[i].Qvk.String()+string(ms[i])+as.Xn[i].String(), sha256Func)
		}
		c_i_C <- c_i
		close(c_i_C)
	}()

	h_i_C := make(chan []*pbc.Element, 1)
	go func() {
		sha256Func := sha256.New()
		h_i := make([]*pbc.Element, len(ms))
		for i := 0; i < len(ms); i++ {
			h_i[i] = pp.pairing.NewZr().SetFromStringHash(DSTForH6+dvks[i].Qr.String()+dvks[i].Qvk.String()+string(ms[i])+as.Xn[i].String()+w, sha256Func)
		}
		h_i_C <- h_i
		close(h_i_C)
	}()

	// compute term in the right side
	π_QvkiC := make(chan *pbc.Element, 1)
	go func() {
		π_Qvki := pp.pairing.NewGT().Set1()
		c_i := <-c_i_C
		h_i := <-h_i_C
		for i := 0; i < len(ms); i++ {
			ch := pp.pairing.NewZr().MulZn(c_i[i], h_i[i])
			π_Qvki.ThenMul(pp.pairing.NewGT().Set1().PowZn(dvks[i].Qvk, pp.pairing.NewZr().Neg(ch)))
		}
		π_QvkiC <- π_Qvki
		close(π_QvkiC)
	}()

	rsh := pp.pairing.NewGT().Set1()
	rsh.ThenMul(<-π_QvkiC).ThenMul(<-rshTermTwoC).ThenMul(<-π_XiC)

	return (<-lshC).Equals(rsh)
}
