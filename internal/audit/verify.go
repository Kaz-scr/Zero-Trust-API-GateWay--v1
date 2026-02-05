package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
)

/*
Verifylogintegrity reads an audit log and verifies the hash chain.
Any mismatch indicates tampering or corruption.
*/

func VerifyLogIntegrity(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var prevHash string

	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return errors.New("invalid log entry format")
		}

		if e.PrevHash != prevHash {
			return errors.New("hash chain broken (prev hash mismatch)")
		}

		expected := computeHash(e)
		if e.Hash != expected {
			return errors.New("hash mismatch (entry tampered)")
		}

		prevHash = e.Hash
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
