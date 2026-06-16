package provision

import (
	qrcode "github.com/skip2/go-qrcode"
)

// WriteQRPNG renders content as a QR-code PNG of the given pixel size.
func WriteQRPNG(content, path string, size int) error {
	return qrcode.WriteFile(content, qrcode.Medium, size, path)
}

// TerminalQR renders content as a compact half-block QR for a terminal.
func TerminalQR(content string) (string, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	return q.ToSmallString(false), nil
}
