package wecom

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const wxPKCS7BlockSize = 32

type CallbackVerifier struct {
	token  string
	corpID string
	aesKey []byte
	window time.Duration
}

func NewCallbackVerifier(token, encodingAESKey, corpID string, window time.Duration) (*CallbackVerifier, error) {
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return nil, fmt.Errorf("decode encoding aes key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid aes key length: %d", len(key))
	}
	return &CallbackVerifier{
		token:  token,
		corpID: corpID,
		aesKey: key,
		window: window,
	}, nil
}

func (v *CallbackVerifier) VerifyURL(msgSignature, timestamp, nonce, echoStr string) (string, error) {
	if err := v.validateTimestamp(timestamp); err != nil {
		return "", err
	}
	want := v.sign(timestamp, nonce, echoStr)
	if !secureEqual(want, msgSignature) {
		return "", errors.New("signature mismatch")
	}
	plaintext, err := v.decrypt(echoStr)
	if err != nil {
		return "", err
	}
	return plaintext, nil
}

type ApprovalEvent struct {
	ApprovalID string
	SpStatus   int
	EventTime  time.Time
}

func (v *CallbackVerifier) ParseApprovalEvent(msgSignature, timestamp, nonce string, body []byte) (ApprovalEvent, error) {
	if err := v.validateTimestamp(timestamp); err != nil {
		return ApprovalEvent{}, err
	}
	var envelope struct {
		XMLName xml.Name `xml:"xml"`
		Encrypt string   `xml:"Encrypt"`
	}
	if err := xml.Unmarshal(body, &envelope); err != nil {
		return ApprovalEvent{}, fmt.Errorf("parse callback xml: %w", err)
	}
	if envelope.Encrypt == "" {
		return ApprovalEvent{}, errors.New("callback encrypt field missing")
	}
	want := v.sign(timestamp, nonce, envelope.Encrypt)
	if !secureEqual(want, msgSignature) {
		return ApprovalEvent{}, errors.New("signature mismatch")
	}
	plain, err := v.decrypt(envelope.Encrypt)
	if err != nil {
		return ApprovalEvent{}, err
	}
	var evt struct {
		XMLName      xml.Name `xml:"xml"`
		Event        string   `xml:"Event"`
		CreateTime   int64    `xml:"CreateTime"`
		ApprovalInfo struct {
			SpNo     string `xml:"SpNo"`
			SpStatus int    `xml:"SpStatus"`
		} `xml:"ApprovalInfo"`
	}
	if err := xml.Unmarshal([]byte(plain), &evt); err != nil {
		return ApprovalEvent{}, fmt.Errorf("parse callback event xml: %w", err)
	}
	eventName := strings.TrimSpace(evt.Event)
	switch eventName {
	case "open_approval_change", "sys_approval_change":
	default:
		return ApprovalEvent{}, fmt.Errorf("unexpected event: %s", evt.Event)
	}
	if evt.ApprovalInfo.SpNo == "" {
		return ApprovalEvent{}, errors.New("approval id missing")
	}
	return ApprovalEvent{
		ApprovalID: evt.ApprovalInfo.SpNo,
		SpStatus:   evt.ApprovalInfo.SpStatus,
		EventTime:  time.Unix(evt.CreateTime, 0).UTC(),
	}, nil
}

func (v *CallbackVerifier) sign(timestamp, nonce, encrypted string) string {
	items := []string{v.token, timestamp, nonce, encrypted}
	sort.Strings(items)
	raw := strings.Join(items, "")
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (v *CallbackVerifier) validateTimestamp(ts string) error {
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	now := time.Now().UTC()
	t := time.Unix(sec, 0).UTC()
	if now.Sub(t) > v.window || t.Sub(now) > v.window {
		return errors.New("callback timestamp out of window")
	}
	return nil
}

func (v *CallbackVerifier) decrypt(encryptedBase64 string) (string, error) {
	cipherData, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", fmt.Errorf("decode encrypted payload: %w", err)
	}
	if len(cipherData)%aes.BlockSize != 0 {
		return "", errors.New("cipher data is not aligned to block size")
	}
	block, err := aes.NewCipher(v.aesKey)
	if err != nil {
		return "", err
	}
	iv := v.aesKey[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	plain := make([]byte, len(cipherData))
	mode.CryptBlocks(plain, cipherData)

	plain, err = pkcs7Unpad(plain)
	if err != nil {
		return "", err
	}
	if len(plain) < 20 {
		return "", errors.New("plaintext too short")
	}
	msgLen := binary.BigEndian.Uint32(plain[16:20])
	if int(20+msgLen) > len(plain) {
		return "", errors.New("invalid payload length")
	}
	msg := plain[20 : 20+msgLen]
	recvCorpID := string(plain[20+msgLen:])
	if recvCorpID != v.corpID {
		return "", errors.New("corp id mismatch")
	}
	return string(msg), nil
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty padding data")
	}
	pad := int(data[len(data)-1])
	if pad <= 0 || pad > wxPKCS7BlockSize || pad > len(data) {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-pad], nil
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := range a {
		out |= a[i] ^ b[i]
	}
	return out == 0
}

func BuildCallbackSuccessResponse(msg string) []byte {
	var buf bytes.Buffer
	buf.WriteString("<xml><Encrypt><![CDATA[")
	buf.WriteString(msg)
	buf.WriteString("]]></Encrypt></xml>")
	return buf.Bytes()
}
