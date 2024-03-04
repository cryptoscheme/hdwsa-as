package hdwsa2

import (
	"crypto/rand"
	"errors"
	"testing"
)

// security parameters
var (
	qbits uint32 = 512
	rbits uint32 = 160

	rootID = []string{"id0"}
	level1 = []string{"id0", "id1"}
)

const (
	messageSize = 256 // bytes

	w = "1000"
)

var errmsg = errors.New("bad signature")

// TestScheme is for testing the correctness of the scheme.
// run `go test -v -count=1 -run TestScheme`
func TestScheme(t *testing.T) {
	pp := Setup(rbits, qbits)
	{
		// derive from level 0
		wsk0, wpk0 := pp.RootWalletKeyGen([]string{"id0"})
		dvk1 := pp.VerifyKeyDerive(rootID, &wpk0)
		if !pp.VerifyKeyCheck(dvk1, rootID, wpk0, wsk0) {
			panic("VerifyKeyCheck wrong")
		}
		dvk2 := pp.VerifyKeyDerive(rootID, &wpk0)
		if !pp.VerifyKeyCheck(dvk2, rootID, wpk0, wsk0) {
			panic("VerifyKeyCheck wrong")
		}
		dvk3 := pp.VerifyKeyDerive(rootID, &wpk0)
		if !pp.VerifyKeyCheck(dvk3, rootID, wpk0, wsk0) {
			panic("VerifyKeyCheck wrong")
		}
		dvks := []DVK{*dvk1, *dvk2, *dvk3}
		dsk1 := pp.SignKeyDerive(dvk1, rootID, wpk0, wsk0)
		dsk2 := pp.SignKeyDerive(dvk2, rootID, wpk0, wsk0)
		dsk3 := pp.SignKeyDerive(dvk3, rootID, wpk0, wsk0)
		dsks := []DSK{*dsk1, *dsk2, *dsk3}
		msgs := make([][]byte, 3)
		for i := range msgs {
			msgs[i] = make([]byte, 256)
			rand.Reader.Read(msgs[i])
		}
		signatures := make([]*signature, len(msgs))
		for i := range msgs {
			signatures[i] = pp.SSign(w, msgs[i], &dvks[i], &dsks[i])
			if !pp.SVerify(w, msgs[i], signatures[i], &dvks[i]) {
				panic(errmsg)
			}
		}

		as := pp.Aggregation(w, signatures...)
		if !pp.AggVerify(w, msgs, as, dvks) {
			panic("AggVerify failed")
		}
	}
}

var pp *PublicParams = Setup(rbits, qbits)

func BenchmarkSchemeL1Sign(b *testing.B)   { level1Sign(b, pp) }
func BenchmarkSchemeL1Verify(b *testing.B) { level1Verify(b, pp) }

func level0Sign(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)
	dvk := pp.VerifyKeyDerive(rootID, &wpk0)
	if !pp.VerifyKeyCheck(dvk, rootID, wpk0, wsk0) {
		panic("error")
	}
	dsk := pp.SignKeyDerive(dvk, rootID, wpk0, wsk0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.SSign(w, nil, dvk, dsk)
	}
}

func level0Verify(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	dvk := pp.VerifyKeyDerive(rootID, &wpk0)
	if !pp.VerifyKeyCheck(dvk, rootID, wpk0, wsk0) {
		panic("error")
	}

	dsk := pp.SignKeyDerive(dvk, rootID, wpk0, wsk0)
	sig := pp.SSign(w, nil, dvk, dsk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.SVerify(w, nil, sig, dvk)
	}
}

func benchmarkLevel1SignThenVerify(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)
	wpk1, wsk1 := pp.WalletKeyDelegate(level1, wpk0, wsk0)
	dvk := pp.VerifyKeyDerive(level1, &wpk1)
	if !pp.VerifyKeyCheck(dvk, level1, wpk1, wsk1) {
		panic("error")
	}
	dsk := pp.SignKeyDerive(dvk, level1, wpk1, wsk1)
	msgs := make([]byte, messageSize)
	rand.Reader.Read(msgs)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.SSign(w, msgs, dvk, dsk)
	}
	b.ResetTimer()
	sig := pp.SSign(w, msgs, dvk, dsk)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.SVerify(w, msgs, sig, dvk)
	}
}

func level1Sign(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)
	wpk1, wsk1 := pp.WalletKeyDelegate(level1, wpk0, wsk0)
	dvk := pp.VerifyKeyDerive(level1, &wpk1)
	if !pp.VerifyKeyCheck(dvk, level1, wpk1, wsk1) {
		panic("error")
	}
	dsk := pp.SignKeyDerive(dvk, level1, wpk1, wsk1)
	msgs := make([]byte, messageSize)
	rand.Reader.Read(msgs)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.SSign(w, msgs, dvk, dsk)
	}
}

func level1Verify(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)
	wpk1, wsk1 := pp.WalletKeyDelegate(level1, wpk0, wsk0)
	dvk := pp.VerifyKeyDerive(level1, &wpk1)
	if !pp.VerifyKeyCheck(dvk, level1, wpk1, wsk1) {
		panic("error")
	}
	dsk := pp.SignKeyDerive(dvk, level1, wpk1, wsk1)
	msgs := make([]byte, messageSize)
	rand.Reader.Read(msgs)
	sig := pp.SSign(w, msgs, dvk, dsk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.SVerify(w, msgs, sig, dvk)
	}
}

func BenchmarkLevel1Aggregation(b *testing.B) {
	batch := 2
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)
	wpk1, wsk1 := pp.WalletKeyDelegate(level1, wpk0, wsk0)
	dvks := make([]DVK, batch)
	dsks := make([]DSK, batch)
	signatures := make([]*signature, batch)
	for i := 0; i < batch; i++ {
		dvks[i] = *(pp.VerifyKeyDerive(level1, &wpk1))
		if !pp.VerifyKeyCheck(&dvks[i], level1, wpk1, wsk1) {
			b.Logf("Aggregation: index %d failed to pass check, just mark it", i)
			continue
		}
		dsks[i] = *(pp.SignKeyDerive(&dvks[i], level1, wpk1, wsk1))
		msgs := make([]byte, messageSize)
		rand.Reader.Read(msgs)
		signatures[i] = pp.SSign(w, msgs, &dvks[i], &dsks[i])
	}
	level1Aggregation(b, signatures...)
}

func level1Aggregation(b *testing.B, sigma ...*signature) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.Aggregation(w, sigma...)
	}
}

func BenchmarkLevel1AggVerify(b *testing.B) {
	batch := 2
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)
	wpk1, wsk1 := pp.WalletKeyDelegate(level1, wpk0, wsk0)
	dvks := make([]DVK, batch)
	dsks := make([]DSK, batch)
	signatures := make([]*signature, batch)
	msgs := make([][]byte, batch)
	for i := 0; i < batch; i++ {
		dvks[i] = *(pp.VerifyKeyDerive(level1, &wpk1))
		if !pp.VerifyKeyCheck(&dvks[i], level1, wpk1, wsk1) {
			b.Logf("AggVerify: index %d failed to pass check, just mark it", i)
			continue
		}
		dsks[i] = *(pp.SignKeyDerive(&dvks[i], level1, wpk1, wsk1))
		msgs[i] = make([]byte, messageSize)
		rand.Reader.Read(msgs[i])
		signatures[i] = pp.SSign(w, msgs[i], &dvks[i], &dsks[i])
	}
	sa := pp.Aggregation(w, signatures...)
	benchmarkLevel1AggVerify(b, msgs, sa, dvks)
}

func benchmarkLevel1AggVerify(b *testing.B, msgs [][]byte, sa aggregatesignature, dvks []DVK) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.AggVerify(w, msgs, sa, dvks)
	}
}
