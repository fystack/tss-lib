package spike_import

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"crypto/hmac"
	"encoding/binary"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bnb-chain/tss-lib/v3/common"
	"github.com/bnb-chain/tss-lib/v3/crypto"
	"github.com/bnb-chain/tss-lib/v3/crypto/ckd"
	"github.com/bnb-chain/tss-lib/v3/crypto/vss"
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	ecdsaResharing "github.com/bnb-chain/tss-lib/v3/ecdsa/resharing"
	ecdsaSigning "github.com/bnb-chain/tss-lib/v3/ecdsa/signing"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v3/eddsa/keygen"
	eddsaResharing "github.com/bnb-chain/tss-lib/v3/eddsa/resharing"
	eddsaSigning "github.com/bnb-chain/tss-lib/v3/eddsa/signing"
	"github.com/bnb-chain/tss-lib/v3/test"
	"github.com/bnb-chain/tss-lib/v3/tss"
)

const (
	newPartyCount = 3
	newThreshold  = 1
)

func dealerContext() (*tss.PartyID, *tss.PeerContext) {
	dealer := tss.NewPartyID("dealer", "dealer", big.NewInt(424242))
	sorted := tss.SortPartyIDs(tss.UnSortedPartyIDs{dealer})
	return sorted[0], tss.NewPeerContext(sorted)
}

func ethAddress(pub *ecdsa.PublicKey) string {
	buf := make([]byte, 64)
	pub.X.FillBytes(buf[:32])
	pub.Y.FillBytes(buf[32:])
	h := sha3.NewLegacyKeccak256()
	h.Write(buf)
	return "0x" + hex.EncodeToString(h.Sum(nil)[12:])
}

func routeReshare(t *testing.T, msg tss.Message, old, new []tss.Party, errCh chan *tss.Error) {
	dest := msg.GetTo()
	require.NotNil(t, dest, "reshare messages are never broadcast")
	if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
		for _, d := range dest[:len(old)] {
			go test.SharedPartyUpdater(old[d.Index], msg, errCh)
		}
	}
	if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
		for _, d := range dest {
			go test.SharedPartyUpdater(new[d.Index], msg, errCh)
		}
	}
}

func routeSign(t *testing.T, msg tss.Message, parties []tss.Party, errCh chan *tss.Error) {
	dest := msg.GetTo()
	if dest == nil {
		for _, p := range parties {
			if p.PartyID().Index != msg.GetFrom().Index {
				go test.SharedPartyUpdater(p, msg, errCh)
			}
		}
		return
	}
	go test.SharedPartyUpdater(parties[dest[0].Index], msg, errCh)
}

func startAll(parties []tss.Party, errCh chan *tss.Error) {
	for _, p := range parties {
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}
}

// ---------- ECDSA ----------

func fixturePreParams(t *testing.T) []ecdsaKeygen.LocalPreParams {
	fixtures, _, err := ecdsaKeygen.LoadKeygenTestFixtures(newPartyCount)
	require.NoError(t, err)
	out := make([]ecdsaKeygen.LocalPreParams, newPartyCount)
	for j := range out {
		out[j] = fixtures[j].LocalPreParams
	}
	return out
}

func importECDSA(t *testing.T, x *big.Int) ([]ecdsaKeygen.LocalPartySaveData, tss.SortedPartyIDs) {
	return importECDSAWith(t, x, fixturePreParams(t), false)
}

func importECDSAWith(t *testing.T, x *big.Int, preParams []ecdsaKeygen.LocalPreParams, withProofs bool) ([]ecdsaKeygen.LocalPartySaveData, tss.SortedPartyIDs) {
	ec := tss.S256()
	X := crypto.ScalarBaseMult(ec, x)
	dealerPID, oldCtx := dealerContext()

	dealerSave := ecdsaKeygen.NewLocalPartySaveData(1)
	dealerSave.Xi = new(big.Int).Set(x)
	dealerSave.ShareID = dealerPID.KeyInt()
	dealerSave.Ks = []*big.Int{dealerPID.KeyInt()}
	dealerSave.BigXj = []*crypto.ECPoint{X}
	dealerSave.ECDSAPub = X
	dealerSave.NTildej[0], dealerSave.H1j[0], dealerSave.H2j[0] = big.NewInt(0), big.NewInt(0), big.NewInt(0)

	newPIDs := tss.GenerateTestPartyIDs(newPartyCount)
	newCtx := tss.NewPeerContext(newPIDs)

	errCh := make(chan *tss.Error, 16)
	outCh := make(chan tss.Message, 64)
	oldEnd := make(chan *ecdsaKeygen.LocalPartySaveData, 1)
	newEnd := make(chan *ecdsaKeygen.LocalPartySaveData, newPartyCount)

	oldParams := tss.NewReSharingParameters(ec, oldCtx, newCtx, dealerPID, 1, 0, newPartyCount, newThreshold)
	old := []tss.Party{ecdsaResharing.NewLocalParty(oldParams, dealerSave, outCh, oldEnd)}
	news := make([]tss.Party, 0, newPartyCount)
	for j, pid := range newPIDs {
		params := tss.NewReSharingParameters(ec, oldCtx, newCtx, pid, 1, 0, newPartyCount, newThreshold)
		if !withProofs {
			params.SetNoProofMod()
			params.SetNoProofFac()
		}
		save := ecdsaKeygen.NewLocalPartySaveData(newPartyCount)
		save.LocalPreParams = preParams[j]
		news = append(news, ecdsaResharing.NewLocalParty(params, save, outCh, newEnd))
	}
	startAll(news, errCh)
	startAll(old, errCh)

	keys := make([]ecdsaKeygen.LocalPartySaveData, newPartyCount)
	oldDone, newDone := 0, 0
	for oldDone < 1 || newDone < newPartyCount {
		select {
		case e := <-errCh:
			t.Fatalf("reshare: %v", e)
		case msg := <-outCh:
			routeReshare(t, msg, old, news, errCh)
		case <-oldEnd:
			oldDone++
		case save := <-newEnd:
			idx, err := save.OriginalIndex()
			require.NoError(t, err)
			keys[idx] = *save
			newDone++
		}
	}
	return keys, newPIDs
}

func signECDSA(t *testing.T, keys []ecdsaKeygen.LocalPartySaveData, pids tss.SortedPartyIDs, hash []byte, delta *big.Int) *common.SignatureData {
	signPIDs := tss.SortPartyIDs(tss.UnSortedPartyIDs{pids[0], pids[2]})
	ctx := tss.NewPeerContext(signPIDs)
	errCh := make(chan *tss.Error, 8)
	outCh := make(chan tss.Message, 64)
	endCh := make(chan *common.SignatureData, len(signPIDs))
	parties := make([]tss.Party, 0, len(signPIDs))
	for _, pid := range signPIDs {
		key := keyFor(t, keys, pid)
		params := tss.NewParameters(tss.S256(), ctx, pid, len(signPIDs), newThreshold)
		parties = append(parties, ecdsaSigning.NewLocalPartyWithKDD(new(big.Int).SetBytes(hash), params, key, delta, outCh, endCh, len(hash)))
	}
	startAll(parties, errCh)
	var sig *common.SignatureData
	for done := 0; done < len(parties); {
		select {
		case e := <-errCh:
			t.Fatalf("sign: %v", e)
		case msg := <-outCh:
			routeSign(t, msg, parties, errCh)
		case sig = <-endCh:
			done++
		}
	}
	return sig
}

func keyFor(t *testing.T, keys []ecdsaKeygen.LocalPartySaveData, pid *tss.PartyID) ecdsaKeygen.LocalPartySaveData {
	for _, k := range keys {
		if k.ShareID.Cmp(pid.KeyInt()) == 0 {
			return k
		}
	}
	t.Fatalf("no key for %s", pid.Id)
	return ecdsaKeygen.LocalPartySaveData{}
}

func cloneECDSAKeys(t *testing.T, keys []ecdsaKeygen.LocalPartySaveData) []ecdsaKeygen.LocalPartySaveData {
	raw, err := json.Marshal(keys)
	require.NoError(t, err)
	var out []ecdsaKeygen.LocalPartySaveData
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func requireSharesReconstruct(t *testing.T, keys []ecdsaKeygen.LocalPartySaveData, x *big.Int) {
	shares := vss.Shares{
		{Threshold: newThreshold, ID: keys[0].ShareID, Share: keys[0].Xi},
		{Threshold: newThreshold, ID: keys[2].ShareID, Share: keys[2].Xi},
	}
	got, err := shares.ReConstruct(tss.S256())
	require.NoError(t, err)
	require.Zero(t, got.Cmp(x), "any t+1 shares must reconstruct the imported key")
}

// A plain wallet key is split into 2-of-3 MPC shares and the MPC signature verifies under the original key.
func TestImportPlainECDSAKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(tss.S256(), rand.Reader)
	require.NoError(t, err)
	wantAddr := ethAddress(&priv.PublicKey)

	keys, pids := importECDSA(t, priv.D)

	for _, k := range keys {
		require.Zero(t, k.ECDSAPub.X().Cmp(priv.X))
		require.Zero(t, k.ECDSAPub.Y().Cmp(priv.Y))
		require.True(t, k.BigXj[0] != nil)
	}
	requireSharesReconstruct(t, keys, priv.D)

	hash := sha256.Sum256([]byte("fystack import spike"))
	sig := signECDSA(t, keys, pids, hash[:], nil)
	ok := ecdsa.Verify(&priv.PublicKey, hash[:], new(big.Int).SetBytes(sig.R), new(big.Int).SetBytes(sig.S))
	require.True(t, ok, "MPC signature must verify under the original wallet key")
	t.Logf("imported %s into %d-of-%d, MPC signature verifies", wantAddr, newThreshold+1, newPartyCount)
}

const hardened = uint32(0x80000000)

type bip32Node struct {
	k *big.Int
	c []byte
}

func compressed(k *big.Int) []byte {
	P := crypto.ScalarBaseMult(tss.S256(), k)
	out := make([]byte, 33)
	out[0] = 0x02 + byte(P.Y().Bit(0))
	P.X().FillBytes(out[1:])
	return out
}

func bip32Master(seed []byte) bip32Node {
	m := hmac.New(sha512.New, []byte("Bitcoin seed"))
	m.Write(seed)
	I := m.Sum(nil)
	return bip32Node{k: new(big.Int).SetBytes(I[:32]), c: I[32:]}
}

func (n bip32Node) child(i uint32) bip32Node {
	data := make([]byte, 0, 37)
	if i >= hardened {
		data = append(data, 0)
		data = append(data, n.k.FillBytes(make([]byte, 32))...)
	} else {
		data = append(data, compressed(n.k)...)
	}
	data = binary.BigEndian.AppendUint32(data, i)
	m := hmac.New(sha512.New, n.c)
	m.Write(data)
	I := m.Sum(nil)
	k := new(big.Int).Add(new(big.Int).SetBytes(I[:32]), n.k)
	k.Mod(k, tss.S256().Params().N)
	return bip32Node{k: k, c: I[32:]}
}

func (n bip32Node) path(p ...uint32) bip32Node {
	for _, i := range p {
		n = n.child(i)
	}
	return n
}

func (n bip32Node) pub() *ecdsa.PublicKey {
	P := crypto.ScalarBaseMult(tss.S256(), n.k)
	return &ecdsa.PublicKey{Curve: tss.S256(), X: P.X(), Y: P.Y()}
}

// BIP32 test vector 1, chain m/0H/1, proves bip32Node matches the spec apex's hdkeychain implements.
func TestBIP32HelperMatchesSpecVector(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	got := bip32Master(seed).path(hardened+0, 1)
	raw := base58.Decode("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
	require.Len(t, raw, 82)
	require.Equal(t, raw[13:45], got.c)
	require.Equal(t, raw[46:78], got.k.FillBytes(make([]byte, 32)))
}

// Mirrors apex legacy Hyper derivation m/44'/60/0/0/i: import node m/44'/60/0/0 once, MPC-derive child i.
func TestImportBIP32NodeKeepsHyperAddresses(t *testing.T) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	node := bip32Master(seed).path(hardened+44, 60, 0, 0)

	keys, pids := importECDSA(t, node.k)

	for _, index := range []uint32{1, 2, 7, 1000} {
		childPub := node.child(index).pub()
		wantAddr := ethAddress(childPub)

		mpcPub := keys[0].ECDSAPub
		parent := &ckd.ExtendedKey{
			PublicKey: ecdsa.PublicKey{Curve: tss.S256(), X: mpcPub.X(), Y: mpcPub.Y()},
			ChainCode: node.c,
			ParentFP:  []byte{0, 0, 0, 0},
			Version:   chaincfg.MainNetParams.HDPrivateKeyID[:],
		}
		delta, derived, err := ckd.DeriveChildKeyFromHierarchy([]uint32{index}, parent, tss.S256().Params().N, tss.S256())
		require.NoError(t, err)
		require.Equal(t, wantAddr, ethAddress(&derived.PublicKey), "MPC-derived child must equal Hyper address at index %d", index)

		childKeys := cloneECDSAKeys(t, keys)
		require.NoError(t, ecdsaSigning.UpdatePublicKeyAndAdjustBigXj(delta, childKeys, &derived.PublicKey, tss.S256()))
		hash := sha256.Sum256([]byte{byte(index)})
		sig := signECDSA(t, childKeys, pids, hash[:], delta)
		ok := ecdsa.Verify(childPub, hash[:], new(big.Int).SetBytes(sig.R), new(big.Int).SetBytes(sig.S))
		require.True(t, ok, "MPC child signature must verify under Hyper child key %d", index)
		t.Logf("index %d: %s derived + signed via MPC", index, wantAddr)
	}
}

func generatePreParams(t *testing.T) []ecdsaKeygen.LocalPreParams {
	out := make([]ecdsaKeygen.LocalPreParams, newPartyCount)
	errs := make(chan error, newPartyCount)
	start := time.Now()
	for j := range out {
		go func(j int) {
			pp, err := ecdsaKeygen.GeneratePreParams(10 * time.Minute)
			if err == nil {
				out[j] = *pp
			}
			errs <- err
		}(j)
	}
	for range out {
		require.NoError(t, <-errs)
	}
	for _, pp := range out {
		require.True(t, pp.ValidateWithProof(), "fresh preparams must carry P, Q for mod/fac proofs")
	}
	t.Logf("generated %d fresh preparams in %s", newPartyCount, time.Since(start).Round(time.Second))
	return out
}

// Same as the Hyper-address test, but with fresh Paillier preparams and mod/fac proofs enabled (production settings).
func TestImportBIP32NodeWithRealPreParamsAndProofs(t *testing.T) {
	if testing.Short() {
		t.Skip("safe-prime generation is slow")
	}
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	node := bip32Master(seed).path(hardened+44, 60, 0, 0)

	start := time.Now()
	keys, pids := importECDSAWith(t, node.k, generatePreParams(t), true)
	t.Logf("dealer reshare with proofs took %s", time.Since(start).Round(time.Millisecond))

	for j, k := range keys {
		require.True(t, k.LocalPreParams.ValidateWithProof())
		for i := range keys {
			require.NotNil(t, k.NTildej[i], "party %d missing NTilde of %d", j, i)
			require.NotNil(t, k.PaillierPKs[i], "party %d missing Paillier PK of %d", j, i)
		}
	}
	requireSharesReconstruct(t, keys, node.k)

	index := uint32(3)
	childPub := node.child(index).pub()
	mpcPub := keys[0].ECDSAPub
	parent := &ckd.ExtendedKey{
		PublicKey: ecdsa.PublicKey{Curve: tss.S256(), X: mpcPub.X(), Y: mpcPub.Y()},
		ChainCode: node.c,
		ParentFP:  []byte{0, 0, 0, 0},
		Version:   chaincfg.MainNetParams.HDPrivateKeyID[:],
	}
	delta, derived, err := ckd.DeriveChildKeyFromHierarchy([]uint32{index}, parent, tss.S256().Params().N, tss.S256())
	require.NoError(t, err)
	require.Equal(t, ethAddress(childPub), ethAddress(&derived.PublicKey))

	childKeys := cloneECDSAKeys(t, keys)
	require.NoError(t, ecdsaSigning.UpdatePublicKeyAndAdjustBigXj(delta, childKeys, &derived.PublicKey, tss.S256()))
	hash := sha256.Sum256([]byte("real preparams"))
	sig := signECDSA(t, childKeys, pids, hash[:], delta)
	require.True(t, ecdsa.Verify(childPub, hash[:], new(big.Int).SetBytes(sig.R), new(big.Int).SetBytes(sig.S)))
	t.Logf("child %d %s signed via MPC with proofs on", index, ethAddress(childPub))
}

// ---------- EdDSA ----------

func ed25519Scalar(seed []byte) *big.Int {
	h := sha512.Sum512(seed)
	a := h[:32]
	a[0] &= 248
	a[31] &= 127
	a[31] |= 64
	le := make([]byte, 32)
	for i := range a {
		le[31-i] = a[i]
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(le), tss.Edwards().Params().N)
}

func importEdDSA(t *testing.T, a *big.Int) ([]eddsaKeygen.LocalPartySaveData, tss.SortedPartyIDs) {
	ec := tss.Edwards()
	A := crypto.ScalarBaseMult(ec, a)
	dealerPID, oldCtx := dealerContext()

	dealerSave := eddsaKeygen.NewLocalPartySaveData(1)
	dealerSave.Xi = new(big.Int).Set(a)
	dealerSave.ShareID = dealerPID.KeyInt()
	dealerSave.Ks = []*big.Int{dealerPID.KeyInt()}
	dealerSave.BigXj = []*crypto.ECPoint{A}
	dealerSave.EDDSAPub = A

	newPIDs := tss.GenerateTestPartyIDs(newPartyCount)
	newCtx := tss.NewPeerContext(newPIDs)
	errCh := make(chan *tss.Error, 16)
	outCh := make(chan tss.Message, 64)
	oldEnd := make(chan *eddsaKeygen.LocalPartySaveData, 1)
	newEnd := make(chan *eddsaKeygen.LocalPartySaveData, newPartyCount)

	oldParams := tss.NewReSharingParameters(ec, oldCtx, newCtx, dealerPID, 1, 0, newPartyCount, newThreshold)
	old := []tss.Party{eddsaResharing.NewLocalParty(oldParams, dealerSave, outCh, oldEnd)}
	news := make([]tss.Party, 0, newPartyCount)
	for _, pid := range newPIDs {
		params := tss.NewReSharingParameters(ec, oldCtx, newCtx, pid, 1, 0, newPartyCount, newThreshold)
		news = append(news, eddsaResharing.NewLocalParty(params, eddsaKeygen.NewLocalPartySaveData(newPartyCount), outCh, newEnd))
	}
	startAll(news, errCh)
	startAll(old, errCh)

	keys := make([]eddsaKeygen.LocalPartySaveData, newPartyCount)
	oldDone, newDone := 0, 0
	for oldDone < 1 || newDone < newPartyCount {
		select {
		case e := <-errCh:
			t.Fatalf("reshare: %v", e)
		case msg := <-outCh:
			routeReshare(t, msg, old, news, errCh)
		case <-oldEnd:
			oldDone++
		case save := <-newEnd:
			idx, err := save.OriginalIndex()
			require.NoError(t, err)
			keys[idx] = *save
			newDone++
		}
	}
	return keys, newPIDs
}

// A plain ed25519 (Solana-style) key is split into shares; the MPC signature passes stdlib ed25519.Verify.
func TestImportPlainEd25519Key(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keys, pids := importEdDSA(t, ed25519Scalar(priv.Seed()))

	edPub := edwards.PublicKey{Curve: tss.Edwards(), X: keys[0].EDDSAPub.X(), Y: keys[0].EDDSAPub.Y()}
	require.Equal(t, []byte(pub), edPub.SerializeCompressed(), "MPC pubkey must equal the original ed25519 pubkey")

	msg := []byte("fystack import spike: solana tx bytes")
	signPIDs := tss.SortPartyIDs(tss.UnSortedPartyIDs{pids[0], pids[1]})
	ctx := tss.NewPeerContext(signPIDs)
	errCh := make(chan *tss.Error, 8)
	outCh := make(chan tss.Message, 64)
	endCh := make(chan *common.SignatureData, len(signPIDs))
	parties := make([]tss.Party, 0, len(signPIDs))
	for _, pid := range signPIDs {
		var key eddsaKeygen.LocalPartySaveData
		for _, k := range keys {
			if k.ShareID.Cmp(pid.KeyInt()) == 0 {
				key = k
			}
		}
		params := tss.NewParameters(tss.Edwards(), ctx, pid, len(signPIDs), newThreshold)
		parties = append(parties, eddsaSigning.NewLocalParty(new(big.Int).SetBytes(msg), params, key, outCh, endCh, len(msg)))
	}
	startAll(parties, errCh)
	var sig *common.SignatureData
	for done := 0; done < len(parties); {
		select {
		case e := <-errCh:
			t.Fatalf("sign: %v", e)
		case m := <-outCh:
			routeSign(t, m, parties, errCh)
		case sig = <-endCh:
			done++
		}
	}
	require.True(t, ed25519.Verify(pub, msg, sig.Signature), "MPC signature must pass stdlib ed25519.Verify")
	t.Logf("imported ed25519 %s, MPC signature verifies", hex.EncodeToString(pub))
}
