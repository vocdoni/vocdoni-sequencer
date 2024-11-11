package secies

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/vocdoni/vocdoni-z-sandbox/ecc/curves"
)

func TestKeyGeneration(t *testing.T) {
	curvePoint, err := curves.New(curves.CurveTypeBabyJubJub)
	if err != nil {
		t.Fatalf("Failed to create curve point: %v", err)
	}

	se, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	if se.privateKey == nil || se.publicKey == nil {
		t.Fatal("Private or public key is nil after key generation")
	}

	if se.privateKey.Sign() == 0 {
		t.Fatal("Private key is zero")
	}
	zero := se.curvePoint.New()
	zero.SetZero()
	if se.publicKey == nil || se.publicKey.Equal(zero) {
		t.Fatal("Public key is zero")
	}
}

func TestEncryptionDecryption(t *testing.T) {
	curvePoint, err := curves.New(curves.CurveTypeBabyJubJub)
	if err != nil {
		t.Fatalf("Failed to create curve point: %v", err)
	}

	// Generate recipient keys
	recipient, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Recipient key generation failed: %v", err)
	}

	recipientPublicKey := recipient.publicKey

	// Messages to test
	messages := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(-1),
		big.NewInt(42),
		new(big.Int).Sub(recipient.curvePoint.Order(), big.NewInt(1)), // Order - 1
		recipient.curvePoint.Order(),                                  // Exactly the order
		new(big.Int).Add(recipient.curvePoint.Order(), big.NewInt(1)), // Order + 1
	}

	for _, message := range messages {
		// Sender generates their own keys
		sender, err := New(nil, curvePoint, nil)
		if err != nil {
			t.Fatalf("Sender key generation failed: %v", err)
		}

		// Encrypt the message
		ciphertext, RBytes, err := sender.Encrypt(new(big.Int).Set(message), recipientPublicKey)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Decrypt the ciphertext
		plaintext, err := recipient.Decrypt(ciphertext, RBytes)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		// Messages should be congruent modulo the curve order
		expectedMessage := new(big.Int).Mod(message, recipient.curvePoint.Order())
		if plaintext.Cmp(expectedMessage) != 0 {
			t.Errorf("Decrypted message does not match original. Expected %s, got %s", expectedMessage.String(), plaintext.String())
		}
	}
}

func TestDecryptionWithWrongPrivateKey(t *testing.T) {
	curvePoint, err := curves.New(curves.CurveTypeBabyJubJub)
	if err != nil {
		t.Fatalf("Failed to create curve point: %v", err)
	}

	// Generate recipient keys
	recipient, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Recipient key generation failed: %v", err)
	}

	// Generate wrong recipient keys
	wrongRecipient, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Wrong recipient key generation failed: %v", err)
	}

	recipientPublicKey := recipient.publicKey

	// Message to encrypt
	message := big.NewInt(123456789)

	// Sender generates their own keys
	sender, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Sender key generation failed: %v", err)
	}

	// Encrypt the message
	ciphertext, RBytes, err := sender.Encrypt(message, recipientPublicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Attempt decryption with the wrong private key
	recoveredMessage, err := wrongRecipient.Decrypt(ciphertext, RBytes)
	if err != nil {
		t.Fatal("Decryption error with wrong private key")
	}
	if recoveredMessage.Cmp(message) == 0 {
		t.Fatal("Decryption should have failed with wrong private key, but it succeeded")
	}
}

func TestDecryptionWithMalformedCiphertext(t *testing.T) {
	curvePoint, err := curves.New(curves.CurveTypeBabyJubJub)
	if err != nil {
		t.Fatalf("Failed to create curve point: %v", err)
	}

	// Generate recipient keys
	recipient, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Recipient key generation failed: %v", err)
	}

	recipientPublicKey := recipient.publicKey

	// Message to encrypt
	message := big.NewInt(42)

	// Sender generates their own keys
	sender, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Sender key generation failed: %v", err)
	}

	// Encrypt the message
	ciphertext, RBytes, err := sender.Encrypt(message, recipientPublicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Tamper with the ciphertext
	corruptedCiphertext := new(big.Int).Add(ciphertext, big.NewInt(1))

	// Attempt decryption with corrupted ciphertext
	recoveredMessage, err := recipient.Decrypt(corruptedCiphertext, RBytes)
	if err != nil {
		t.Fatal("Decryption error with corrupted ciphertext")
	}
	if recoveredMessage.Cmp(message) == 0 {
		t.Fatal("Decryption should have failed with corrupted ciphertext, but it succeeded")
	}

	// Tamper with RBytes
	if len(RBytes) > 0 {
		RBytes[0] ^= 0xFF
	}

	// Attempt decryption with corrupted RBytes
	recoveredMessage, err = recipient.Decrypt(ciphertext, RBytes)
	if err != nil {
		t.Fatal("Decryption failed with corrupted RBytes")
	}
	if recoveredMessage.Cmp(message) == 0 {
		t.Fatal("Decryption should have failed with corrupted RBytes, but it succeeded")
	}

}

func TestEncryptDecryptWithMaxMessage(t *testing.T) {
	curvePoint, err := curves.New(curves.CurveTypeBabyJubJub)
	if err != nil {
		t.Fatalf("Failed to create curve point: %v", err)
	}

	// Generate recipient keys
	recipient, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Recipient key generation failed: %v", err)
	}

	recipientPublicKey := recipient.publicKey

	// Message equal to curve order - 1
	maxMessage := new(big.Int).Sub(curvePoint.Order(), big.NewInt(1))

	// Sender generates their own keys
	sender, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Sender key generation failed: %v", err)
	}

	// Encrypt the message
	ciphertext, RBytes, err := sender.Encrypt(maxMessage, recipientPublicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt the ciphertext
	plaintext, err := recipient.Decrypt(ciphertext, RBytes)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if plaintext.Cmp(maxMessage) != 0 {
		t.Errorf("Decrypted message does not match original. Expected %s, got %s", maxMessage.String(), plaintext.String())
	}
}

func TestEncryptDecryptRandomMessages(t *testing.T) {
	curvePoint, err := curves.New(curves.CurveTypeBabyJubJub)
	if err != nil {
		t.Fatalf("Failed to create curve point: %v", err)
	}

	// Generate recipient keys
	recipient, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Recipient key generation failed: %v", err)
	}

	recipientPublicKey := recipient.publicKey

	// Number of random messages to test
	numMessages := 100

	for i := 0; i < numMessages; i++ {
		// Generate a random message
		message, err := rand.Int(rand.Reader, curvePoint.Order())
		if err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}

		// Sender generates their own keys
		sender, err := New(nil, curvePoint, nil)
		if err != nil {
			t.Fatalf("Sender key generation failed: %v", err)
		}

		// Encrypt the message
		ciphertext, RBytes, err := sender.Encrypt(message, recipientPublicKey)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Decrypt the ciphertext
		plaintext, err := recipient.Decrypt(ciphertext, RBytes)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if plaintext.Cmp(message) != 0 {
			t.Errorf("Decrypted message does not match original. Expected %s, got %s", message.String(), plaintext.String())
		}
	}
}

func TestEncryptWithNilPrivateKey(t *testing.T) {
	curvePoint, err := curves.New(curves.CurveTypeBabyJubJub)
	if err != nil {
		t.Fatalf("Failed to create curve point: %v", err)
	}

	// Create a recipient with nil private key (should generate keys)
	se, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	if se.privateKey == nil || se.publicKey == nil {
		t.Fatal("Private or public key is nil after key generation")
	}
}

func TestPublicKeyMarshaling(t *testing.T) {
	curvePoint, err := curves.New(curves.CurveTypeBabyJubJub)
	if err != nil {
		t.Fatalf("Failed to create curve point: %v", err)
	}

	// Generate keys
	se, err := New(nil, curvePoint, nil)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	publicKeyBytes := se.GetPublicKey()

	// Unmarshal the public key
	publicKey := curvePoint.New()
	if err := publicKey.Unmarshal(publicKeyBytes); err != nil {
		t.Fatalf("Failed to unmarshal public key: %v", err)
	}

	// Check if the unmarshaled public key matches the original
	if !publicKey.Equal(se.publicKey) {
		t.Fatal("Unmarshaled public key does not match the original")
	}
}
