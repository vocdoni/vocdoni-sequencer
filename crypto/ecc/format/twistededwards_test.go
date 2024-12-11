package format

import (
	"math/big"
	"testing"
)

func TestTE2RTETransform(t *testing.T) {
	x, _ := new(big.Int).SetString("20284931487578954787250358776722960153090567235942462656834196519767860852891", 10)
	y, _ := new(big.Int).SetString("21185575020764391300398134415668786804224896114060668011215204645513129497221", 10)

	expectedRTE, _ := new(big.Int).SetString("5730906301301611931737915251485454905492689746504994962065413628158661689313", 10)
	xPrime, yPrime := FromTEtoRTE(x, y)
	if xPrime.Cmp(expectedRTE) != 0 {
		t.Errorf("Expected %v, got %v", expectedRTE, xPrime)
	} else if yPrime.Cmp(y) != 0 {
		t.Errorf("Expected %v, got %v", y, yPrime)
	}
	xPrimePrime, yPrimePrime := FromRTEtoTE(xPrime, yPrime)
	if xPrimePrime.Cmp(x) != 0 {
		t.Errorf("Expected %v, got %v", x, xPrimePrime)
	} else if yPrimePrime.Cmp(y) != 0 {
		t.Errorf("Expected %v, got %v", y, yPrimePrime)
	}
}
