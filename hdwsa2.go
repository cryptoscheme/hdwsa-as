// package hdwsa2 implements `HDWSA2: A Secure Hierarchical Deterministic Wallet Supporting Stealth Address and Signature Aggregation`
package hdwsa2

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
	DSTForH7 = "hdwsa-sa.h7"
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
	Qr := <-QrC

	Qvk_zero := make(chan *pbc.Element, 1)
	go func() {
		sha256Func := sha256.New()
		var builder strings.Builder
		builder.WriteString(DSTForH3)
		builder.WriteString(wpk.BID.String())
		builder.WriteString(Qr.String())
		builder.WriteString(qid.String())
		sha256Func.Reset()
	REPEAT2:
		h4 := pp.pairing.NewG1().SetFromStringHash(builder.String(), sha256Func)
		if h4.Is0() {
			goto REPEAT2
		}
		Qvk_zero <- pp.pairing.NewGT().Set1().Pair(h4, pp.pairing.NewG1().Neg(wpk.AID))
		close(Qvk_zero)
	}()

	Qvk_one := make(chan *pbc.Element, 1)
	go func() {
		sha256Func := sha256.New()
		var builder strings.Builder
		builder.WriteString(DSTForH4)
		builder.WriteString(wpk.BID.String())
		builder.WriteString(Qr.String())
		builder.WriteString(qid.String())
		sha256Func.Reset()
	REPEAT2:
		h4 := pp.pairing.NewG1().SetFromStringHash(builder.String(), sha256Func)
		if h4.Is0() {
			goto REPEAT2
		}
		Qvk_one <- pp.pairing.NewGT().Set1().Pair(h4, pp.pairing.NewG1().Neg(wpk.AID))
		close(Qvk_one)
	}()

	return &DVK{
		Qr,
		<-Qvk_zero,
		<-Qvk_one,
	}
}

func (pp *PublicParams) VerifyKeyCheck(dvk *DVK, ID []string, wpk WalletPublicKey, wsk WalletSecretKey) bool {
	sha256Func := sha256.New()
	h3 := pp.pairing.NewG1().SetFromStringHash(DSTForH3+wpk.BID.String()+dvk.Qr.String()+
		pp.pairing.NewG1().PowZn(dvk.Qr, wsk.beta).String(), sha256Func)
	pair_zero := pp.pairing.NewGT().Pair(h3, pp.pairing.NewG1().Neg(wpk.AID))

	sha256Func.Reset()
	h4 := pp.pairing.NewG1().SetFromStringHash(DSTForH4+wpk.BID.String()+dvk.Qr.String()+
		pp.pairing.NewG1().PowZn(dvk.Qr, wsk.beta).String(), sha256Func)
	pair_one := pp.pairing.NewGT().Pair(h4, pp.pairing.NewG1().Neg(wpk.AID))
	return dvk.Qvk_zero.Equals(pair_zero) && dvk.Qvk_one.Equals(pair_one)
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

	var builder strings.Builder
	builder.WriteString(DSTForH4)
	builder.WriteString(wpk.BID.String())
	builder.WriteString(dvk.Qr.String())
	builder.WriteString(Q1.String())
	h4 := pp.pairing.NewG1().SetFromStringHash(builder.String(), sha256Func) // compute H4(*, *, *)
	return &DSK{pp.pairing.NewG1().PowZn(h3, wsk.alpha), pp.pairing.NewG1().PowZn(h4, wsk.alpha)}
}

func (pp *PublicParams) SSign(w string, m []byte, dvk *DVK, dsk *DSK) *signature {
	// pick random x
REPEAT0:
	x := pp.pairing.NewZr().Rand() // pick a random number x
	if x.Is0() {
		goto REPEAT0
	}
	xPCh := make(chan *pbc.Element, 1)
	// compute X' = xP
	go func() {
		xPCh <- pp.pairing.NewG1().PowZn(pp.P, x)
		close(xPCh)
	}()

	xP := <-xPCh

	rstItemC := make(chan *pbc.Element, 1)
	go func() {
		sha256Func := sha256.New()
	REPEAT2:
		c := pp.pairing.NewZr().SetFromStringHash(DSTForH6+dvk.Qr.String()+dvk.Qvk_zero.String()+dvk.Qvk_one.String()+string(m)+xP.String()+w, sha256Func)
		h := pp.pairing.NewZr().SetFromStringHash(DSTForH7+dvk.Qr.String()+dvk.Qvk_zero.String()+dvk.Qvk_one.String()+string(m)+xP.String()+c.String()+w, sha256Func)
		if h.Is0() {
			goto REPEAT2
		}
		rstItem := pp.pairing.NewG1().PowZn(dsk.dsk_zero, h) // compute h*dsk_0

		sha256Func.Reset()
		rstItem.ThenAdd(pp.pairing.NewG1().PowZn(dsk.dsk_one, c)) // + c*dsk_1

		Pw := pp.pairing.NewG1().SetFromStringHash(DSTForH5+w, sha256Func)

		rstItem.ThenAdd(pp.pairing.NewG1().PowZn(Pw, x)) // + x * Pw

		rstItemC <- rstItem
		close(rstItemC)
	}()
	return &signature{XPrime: xP, SPrime: <-rstItemC}
}

func (pp *PublicParams) SVerify(w string, m []byte, sigma *signature, dvk *DVK) bool {
	if sigma != nil || dvk != nil {
		// compute e(S', P)
		lshCh := make(chan *pbc.Element, 1)
		go func() {
			lshCh <- pp.pairing.NewGT().Pair(sigma.SPrime, pp.P)
			close(lshCh)
		}()

		Qvk_zero := make(chan *pbc.Element, 1)
		cCh := make(chan *pbc.Element, 1)
		go func() {
			sha256Func := sha256.New()
			c := pp.pairing.NewZr().SetFromStringHash(DSTForH6+dvk.Qr.String()+dvk.Qvk_zero.String()+dvk.Qvk_one.String()+string(m)+sigma.XPrime.String()+w, sha256Func)
			cCh <- c

			sha256Func.Reset()
			h := pp.pairing.NewZr().SetFromStringHash(DSTForH7+dvk.Qr.String()+dvk.Qvk_zero.String()+dvk.Qvk_one.String()+string(m)+sigma.XPrime.String()+c.String()+w, sha256Func)

			Qvk_zero <- pp.pairing.NewGT().PowZn(dvk.Qvk_zero, pp.pairing.NewZr().Neg(h))
			close(Qvk_zero)
		}()

		Qvk_one := make(chan *pbc.Element, 1)
		go func() {
			Qvk_one <- pp.pairing.NewGT().PowZn(dvk.Qvk_one, pp.pairing.NewZr().Neg(<-cCh))
			close(Qvk_one)
		}()

		Pw := pp.pairing.NewG1().Set0()
		sha256Func := sha256.New()
		Pw = Pw.SetFromStringHash(DSTForH5+w, sha256Func)
		pair := pp.pairing.NewGT().Pair(sigma.XPrime, Pw) // e(X', Pw)
		gt := pp.pairing.NewGT().Set1()
		rsh := gt.Mul(<-Qvk_zero, <-Qvk_one)

		rsh.ThenMul(pair)

		lsh := <-lshCh

		return lsh.Equals(rsh)
	}
	return false
}

// Assume all signature have the same w.
func (pp *PublicParams) Aggregation(w string, sigma ...*signature) aggregatesignature {
	X := make([]*pbc.Element, len(sigma))
	Sn := pp.pairing.NewG1().Set0()

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func(_sigma ...*signature) {
		defer wg.Done()
		for i := range _sigma {
			if _sigma[i] == nil {
				continue
			}
			X[i] = _sigma[i].XPrime
		}
	}(sigma...)

	go func(_sigma ...*signature) {
		defer wg.Done()
		for i := range _sigma {
			if _sigma[i] == nil {
				continue
			}
			Sn.ThenAdd(_sigma[i].SPrime)
		}
	}(sigma...)
	wg.Wait()

	return aggregatesignature{X, Sn}
}

func (pp *PublicParams) AggVerify(w string, ms [][]byte, as aggregatesignature, dvks []DVK) bool {
	XnC := make(chan *pbc.Element, 1)
	go func() {
		Xn := pp.pairing.NewG1().Set0()
		for i := range as.X {
			if as.X[i] == nil {
				continue
			}
			Xn.ThenAdd(as.X[i])
		}
		XnC <- Xn
		close(XnC)
	}()

	sha256Func := sha256.New()
	Pw := pp.pairing.NewG1().SetFromStringHash(DSTForH5+w, sha256Func)
	// compute e(Sn, P)
	lshC := make(chan *pbc.Element, 1)
	go func() {
		lshC <- pp.pairing.NewGT().Set1().Pair(as.Sn, pp.P)
		close(lshC)
	}()

	c_i_C := make(chan []*pbc.Element, 1)
	h_i_C := make(chan []*pbc.Element, 1)
	go func() {
		sha256Func := sha256.New()
		c_i := make([]*pbc.Element, len(ms))
		h_i := make([]*pbc.Element, len(ms))
		for i := 0; i < len(ms); i++ {
			c_i[i] = pp.pairing.NewZr().SetFromStringHash(
				DSTForH6+dvks[i].Qr.String()+dvks[i].Qvk_zero.String()+dvks[i].Qvk_one.String()+string(ms[i])+as.X[i].String()+w,
				sha256Func)
			h_i[i] = pp.pairing.NewZr().SetFromStringHash(
				DSTForH7+dvks[i].Qr.String()+dvks[i].Qvk_zero.String()+dvks[i].Qvk_one.String()+string(ms[i])+as.X[i].String()+c_i[i].String()+w,
				sha256Func)
		}
		h_i_C <- h_i
		c_i_C <- c_i
		close(c_i_C)
		close(h_i_C)
	}()

	// compute term in the right side
	π_QvkiC_one := make(chan *pbc.Element, 1)
	go func() {
		π_Qvki := pp.pairing.NewGT().Set1()
		c_i := <-c_i_C
		for i := 0; i < len(ms); i++ {
			π_Qvki.ThenMul(pp.pairing.NewGT().Set1().PowZn(dvks[i].Qvk_one, pp.pairing.NewZr().Neg(c_i[i])))
		}
		π_QvkiC_one <- π_Qvki
		close(π_QvkiC_one)
	}()

	// compute term in the right side
	π_Qvk_zero := pp.pairing.NewGT().Set1()
	h_i := <-h_i_C
	for i := 0; i < len(ms); i++ {
		π_Qvk_zero.ThenMul(pp.pairing.NewGT().Set1().PowZn(dvks[i].Qvk_zero, pp.pairing.NewZr().Neg(h_i[i])))
	}

	gt := pp.pairing.NewGT().Set1()
	rsh_three := gt.Pair(<-XnC, Pw)

	rsh := pp.pairing.NewGT().Set1()
	rsh.ThenMul(rsh_three)
	rsh.ThenMul(π_Qvk_zero)

	rsh.ThenMul(<-π_QvkiC_one)

	return (<-lshC).Equals(rsh)
}
