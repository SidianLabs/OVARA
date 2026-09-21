package gwidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
)

// Proof-of-possession for gateway identity (P2.3.1).
//
// Signed message — explicit domain separation, length-prefixed fields
// (same canonical encoding convention as identity/canon.go; the
// delegation canonicalization itself is untouched):
//
//	lp("OVARA-GATEWAY-POP-V1") ‖ lp(gateway_id) ‖ lp(key_id) ‖ lp(challenge)
//
// The challenge is issued fresh by the verifier (32 random bytes), so
// a captured response cannot be replayed into a new authentication —
// and the bound (gateway_id, key_id) makes a response minted for one
// gateway worthless for another.
const PopDomain = "OVARA-GATEWAY-POP-V1"
const ChallengeLen = 32

// Challenge issues a fresh unpredictable PoP challenge.
func Challenge() ([]byte, error) {
	c := make([]byte, ChallengeLen)
	if _, err := rand.Read(c); err != nil {
		return nil, err
	}
	return c, nil
}

// lp is the local length-prefix encoder — u32be(len) ‖ bytes — the
// same wire format the identity package's canonical builder uses.
func lp(b []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	return append(l[:], b...)
}

func popMessage(gatewayID, keyID string, challenge []byte) []byte {
	out := lp([]byte(PopDomain))
	out = append(out, lp([]byte(gatewayID))...)
	out = append(out, lp([]byte(keyID))...)
	out = append(out, lp(challenge)...)
	return out
}

// Prove signs a verifier-issued challenge with the gateway's private
// key. The private key never leaves the holder — only the signature
// is transmitted.
func Prove(priv ed25519.PrivateKey, gatewayID, keyID string, challenge []byte) []byte {
	return ed25519.Sign(priv, popMessage(gatewayID, keyID, challenge))
}
