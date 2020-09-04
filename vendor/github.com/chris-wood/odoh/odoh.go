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
	"errors"
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

	return keyIdHash
}

func (k ObliviousDNSPublicKey) Marshal() []byte {
	identifiers := make([]byte, 8)
	binary.BigEndian.PutUint16(identifiers[0:], uint16(k.KemID))
	binary.BigEndian.PutUint16(identifiers[2:], uint16(k.KdfID))
	binary.BigEndian.PutUint16(identifiers[4:], uint16(k.AeadID))
	binary.BigEndian.PutUint16(identifiers[6:], uint16(len(k.PublicKeyBytes)))

	response := append(identifiers, k.PublicKeyBytes...)
	return response
}

func UnMarshalObliviousDNSPublicKey(buffer []byte) ObliviousDNSPublicKey {
	kemId := binary.BigEndian.Uint16(buffer[0:])
	kdfId := binary.BigEndian.Uint16(buffer[2:])
	AeadId := binary.BigEndian.Uint16(buffer[4:])
	pkLen := binary.BigEndian.Uint16(buffer[6:])

	pkBytes := buffer[8 : 8+pkLen]

	var KemID hpke.KEMID
	var KdfID hpke.KDFID
	var AeadID hpke.AEADID

	switch kemId {
	case 0x0010:
		KemID = hpke.DHKEM_P256
		break
	case 0x0012:
		KemID = hpke.DHKEM_P521
		break
	case 0x0020:
		KemID = hpke.DHKEM_X25519
		break
	case 0x0021:
		KemID = hpke.DHKEM_X448
		break
	case 0xFFFE:
		KemID = hpke.KEM_SIKE503
		break
	case 0xFFFF:
		KemID = hpke.KEM_SIKE751
		break
	default:
		log.Fatalln("Unable to find the correct KEM ID Type")
	}

	switch kdfId {
	case 0x0001:
		KdfID = hpke.KDF_HKDF_SHA256
		break
	case 0x0002:
		KdfID = hpke.KDF_HKDF_SHA384
		break
	case 0x0003:
		KdfID = hpke.KDF_HKDF_SHA512
		break
	default:
		log.Fatalln("Unable to find correct KDF ID Type")
	}

	switch AeadId {
	case 0x0001:
		AeadID = hpke.AEAD_AESGCM128
		break
	case 0x0002:
		AeadID = hpke.AEAD_AESGCM256
		break
	case 0x0003:
		AeadID = hpke.AEAD_CHACHA20POLY1305
		break
	default:
		log.Fatalln("Unable to find correct AEAD ID Type")
	}

	return ObliviousDNSPublicKey{
		KemID:          KemID,
		KdfID:          KdfID,
		AeadID:         AeadID,
		PublicKeyBytes: pkBytes,
	}
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

func DeriveFixedKeyPairFromSeed(kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID, ikm []byte) (ObliviousDNSKeyPair, error) {
	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		return ObliviousDNSKeyPair{}, err
	}

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

	keySize := suite.KEM.PublicKeySize()
	enc := message.EncryptedMessage[0:keySize]
	ct := message.EncryptedMessage[keySize:]

	ctxR, err := hpke.SetupBaseR(suite, privateKey.SecretKey, enc, []byte("odns-query"))
	if err != nil {
		log.Printf("Bailed here. %v", err)
		return nil, err
	}

	aad := append([]byte{byte(QueryType)}, privateKey.PublicKey.KeyID()...)

	dnsMessage, err := ctxR.Open(aad, ct)
	if err != nil {
		return nil, err
	}

	return UnmarshalQueryBody(dnsMessage)
}

type QueryContext struct {
	key       []byte
	publicKey ObliviousDNSPublicKey
}

func lookupAeadKeySizeByAeadID(id hpke.AEADID) int {
	switch id {
	case hpke.AEAD_AESGCM128:
		return 16
	case hpke.AEAD_AESGCM256:
		return 32
	case hpke.AEAD_CHACHA20POLY1305:
		return 32
	default:
		return 0
	}
}

func createQueryContext(publicKey ObliviousDNSPublicKey) QueryContext {
	keySize := lookupAeadKeySizeByAeadID(publicKey.AeadID)
	if keySize == 0 {
		return QueryContext{
			key:       nil,
			publicKey: publicKey,
		}
	}
	responseKey := make([]byte, keySize)
	_, err := rand.Read(responseKey)
	if err != nil {
		return QueryContext{
			key:       nil,
			publicKey: publicKey,
		}
	}
	return QueryContext{
		key:       responseKey,
		publicKey: publicKey,
	}
}

func SealQuery(dnsQuery []byte, publicKey ObliviousDNSPublicKey) ([]byte, QueryContext, error) {
	queryContext := createQueryContext(publicKey)
	odohQuery := ObliviousDNSQuery{
		ResponseKey: queryContext.key,
		DnsMessage:  dnsQuery,
	}

	odnsMessage, err := queryContext.publicKey.EncryptQuery(odohQuery)
	if err != nil {
		log.Fatalf("Unable to Encrypt oDoH Question with provided Public Key of Resolver")
		return nil, queryContext, err
	}

	return odnsMessage.Marshal(), queryContext, nil
}

func (c QueryContext) OpenAnswer(encryptedDnsAnswer []byte) ([]byte, error) {
	message := CreateObliviousDNSMessage(ResponseType, []byte{}, encryptedDnsAnswer)
	odohResponse := ObliviousDNSResponse{ResponseKey: c.key}
	responseMessageType := message.MessageType
	if responseMessageType != ResponseType {
		return nil, errors.New("answer is not a valid response type")
	}
	encryptedResponse := message.EncryptedMessage

	responseKeyId := []byte{0x00, 0x00}
	aad := append([]byte{0x02}, responseKeyId...) // message_type = 0x02, with an empty keyID

	suite, err := hpke.AssembleCipherSuite(c.publicKey.KemID, c.publicKey.KdfID, c.publicKey.AeadID)

	decryptedResponse, err := odohResponse.DecryptResponse(suite, aad, encryptedResponse)
	if err != nil {
		return nil, errors.New("unable to decrypt the obtained response using the symmetric key sent")
	}
	return decryptedResponse, nil
}
