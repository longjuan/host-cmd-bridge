package wecom

import "testing"

func TestPKCS7Unpad_Block32(t *testing.T) {
	plain := []byte("hello-wecom")
	pad := 20
	data := make([]byte, 0, len(plain)+pad)
	data = append(data, plain...)
	for i := 0; i < pad; i++ {
		data = append(data, byte(pad))
	}

	out, err := pkcs7Unpad(data)
	if err != nil {
		t.Fatalf("pkcs7Unpad failed: %v", err)
	}
	if string(out) != string(plain) {
		t.Fatalf("unexpected unpad result: %q", string(out))
	}
}
