// The MIT License
//
// Copyright (c) 2019 Apple, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package odoh

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/cisco/go-hpke"
	"log"
)

type ObliviousDNSPublicKey struct {
	KemID          hpke.KEMID
	KdfID          hpke.KDFID
	AeadID         hpke.AEADID
	PublicKeyBytes []byte
}

func (k ObliviousDNSPublicKey) KeyID() []byte {
	h := sha256.New()

	identifiers := make([]byte, 8)
	binary.BigEndian.PutUint16(identifiers[0:], uint16(k.KemID))
	binary.BigEndian.PutUint16(identifiers[2:], uint16(k.KdfID))
	binary.BigEndian.PutUint16(identifiers[4:], uint16(k.AeadID))
	binary.BigEndian.PutUint16(identifiers[6:], uint16(len(k.PublicKeyBytes)))
	message := append(identifiers, k.PublicKeyBytes...)

	h.Write(message)
	keyIdHash := h.Sum(nil)

	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, uint16(len(keyIdHash)))
	return append(result, keyIdHash...)
}

func (k ObliviousDNSPublicKey) GetPublicKeyBytes() []byte {
	return k.PublicKeyBytes
}

func (k ObliviousDNSPublicKey) CipherSuite() (hpke.CipherSuite, error) {
	return hpke.AssembleCipherSuite(k.KemID, k.KdfID, k.AeadID)
}

type ObliviousDNSKeyPair struct {
	PublicKey ObliviousDNSPublicKey
	SecretKey hpke.KEMPrivateKey
}

func (k ObliviousDNSKeyPair) CipherSuite() (hpke.CipherSuite, error) {
	return hpke.AssembleCipherSuite(k.PublicKey.KemID, k.PublicKey.KdfID, k.PublicKey.AeadID)
}

func CreateKeyPair(kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID) (ObliviousDNSKeyPair, error) {
	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		return ObliviousDNSKeyPair{}, err
	}

	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)
	sk, pk, err := suite.KEM.DeriveKeyPair(ikm)
	if err != nil {
		return ObliviousDNSKeyPair{}, err
	}

	publicKey := ObliviousDNSPublicKey{
		KemID:          kemID,
		KdfID:          kdfID,
		AeadID:         aeadID,
		PublicKeyBytes: suite.KEM.Serialize(pk),
	}

	return ObliviousDNSKeyPair{publicKey, sk}, nil
}

func (targetKey ObliviousDNSPublicKey) EncryptQuery(query ObliviousDNSQuery) (ObliviousDNSMessage, error) {
	suite, err := hpke.AssembleCipherSuite(targetKey.KemID, targetKey.KdfID, targetKey.AeadID)
	if err != nil {
		return ObliviousDNSMessage{}, err
	}

	pkR, err := suite.KEM.Deserialize(targetKey.PublicKeyBytes)
	if err != nil {
		return ObliviousDNSMessage{}, err
	}

	enc, ctxI, err := hpke.SetupBaseS(suite, rand.Reader, pkR, []byte("odns-query"))
	if err != nil {
		return ObliviousDNSMessage{}, err
	}

	encodedMessage := query.Marshal()
	aad := append([]byte{0x01}, targetKey.KeyID()...)
	ct := ctxI.Seal(aad, encodedMessage)

	return ObliviousDNSMessage{
		MessageType:      QueryType,
		KeyID:            targetKey.KeyID(),
		EncryptedMessage: append(enc, ct...),
	}, nil
}

func (privateKey ObliviousDNSKeyPair) DecryptQuery(message ObliviousDNSMessage) (*ObliviousDNSQuery, error) {
	suite, err := hpke.AssembleCipherSuite(privateKey.PublicKey.KemID, privateKey.PublicKey.KdfID, privateKey.PublicKey.AeadID)
	if err != nil {
		return nil, err
	}

	log.Printf("PublicKey = %x\n", privateKey.PublicKey.PublicKeyBytes)

	enc := message.EncryptedMessage[0:32]
	ct := message.EncryptedMessage[32:]
	log.Printf("enc = %x\n", enc)
	log.Printf("ct = %x\n", ct)

	ctxR, err := hpke.SetupBaseR(suite, privateKey.SecretKey, enc, []byte("odns-query"))
	if err != nil {
		return nil, err
	}

	aad := append([]byte{byte(QueryType)}, privateKey.PublicKey.KeyID()...)
	log.Printf("aad = %x\n", aad)

	dnsMessage, err := ctxR.Open(aad, ct)
	if err != nil {
		return nil, err
	}

	return UnmarshalQueryBody(dnsMessage)
}
