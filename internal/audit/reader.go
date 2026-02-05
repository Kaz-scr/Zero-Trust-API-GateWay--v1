package audit

import (
	"bufio"
	"encoding/json"
	"os"
)

// ReadLastEntries reads the audit log file and returns the last n entries,
// in chronological order (oldest first). Skips hash chain validation for performance.
// Returns an empty slice if the file is missing or empty.
func ReadLastEntries(path string, n int) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return []Entry{}, nil
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(entries) <= n {
		return entries, nil
	}
	return entries[len(entries)-n:], nil
}
