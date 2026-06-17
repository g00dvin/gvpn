package provision

import (
	"os"

	qrcode "github.com/skip2/go-qrcode"
)

// WriteQRPNG renders content as a QR-code PNG of the given pixel size, written
// 0600 because enrollment links embed a secret PSK.
func WriteQRPNG(content, path string, size int) error {
	png, err := qrcode.Encode(content, qrcode.Medium, size)
	if err != nil {
		return err
	}
	return os.WriteFile(path, png, 0o600)
}

// TerminalQR renders content as a compact half-block QR for a terminal.
func TerminalQR(content string) (string, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	return q.ToSmallString(false), nil
}
