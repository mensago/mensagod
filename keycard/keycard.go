package keycard

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Keycard - class which houses a list of entries into a hash-linked chain
type Keycard struct {
	Type    string
	Entries []Entry
}

func (card *Keycard) Duplicate() *Keycard {
	var out Keycard
	out.Type = card.Type
	out.Entries = make([]Entry, len(card.Entries))
	for i, entry := range card.Entries {
		out.Entries[i] = *entry.Duplicate()
	}
	return &out
}

// Load writes the entire entry chain to one file with optional overwrite
func (card *Keycard) Load(path string, clobber bool) error {
	if len(path) < 1 {
		return errors.New("empty path")
	}

	fHandle, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fHandle.Close()

	fReader := bufio.NewReader(fHandle)

	var line string
	line, err = fReader.ReadString('\n')
	if err != nil {
		return err
	}

	accumulator := make([][2]string, 0, 16)
	cardType := ""
	lineIndex := 1
	for line != "" {
		line = strings.TrimSpace(line)
		if line == "" {
			lineIndex++
			continue
		}

		switch line {
		case "----- BEGIN ENTRY -----":
			accumulator = make([][2]string, 0, 16)

		case "----- END ENTRY -----":
			var currentEntry *Entry
			switch cardType {
			case "User":
				currentEntry = NewUserEntry()
			case "Organization":
				currentEntry = NewOrgEntry()
			default:
				return errors.New("unsupported entry type ")
			}

			for _, fieldData := range accumulator {
				err = currentEntry.SetField(fieldData[0], fieldData[1])
				if err != nil {
					return fmt.Errorf("bad field data in card line %d", lineIndex)
				}
			}

		default:
			parts := strings.SplitN(line, ":", 1)
			if len(parts) != 2 {
				return fmt.Errorf("bad line data in card line %d", lineIndex)
			}

			if parts[0] == "Type" {
				if cardType != "" {
					if cardType != parts[1] {
						return fmt.Errorf("keycard-entry type mismatch in line %d", lineIndex)
					}
				} else {
					cardType = parts[0]
				}
			}
			accumulator = append(accumulator, [2]string{parts[0], parts[1]})
		}

		line, err = fReader.ReadString('\n')
		if err != nil {
			return err
		}
		lineIndex++
	}

	return nil
}

// Save writes the entire entry chain to one file with optional overwrite
func (card Keycard) Save(path string, clobber bool) error {
	if len(path) < 1 {
		return errors.New("empty path")
	}

	_, err := os.Stat(path)
	if !os.IsNotExist(err) && !clobber {
		return errors.New("file exists")
	}

	fHandle, err := os.Create(path)
	if err != nil {
		return err
	}
	fHandle.Close()

	for _, entry := range card.Entries {
		_, err = fHandle.Write([]byte("----- BEGIN ENTRY -----\r\n"))
		if err != nil {
			return err
		}

		_, err = fHandle.Write(entry.MakeByteString(-1))
		if err != nil {
			return err
		}

		_, err = fHandle.Write([]byte("----- END ENTRY -----\r\n"))
		if err != nil {
			return err
		}
	}

	return nil
}

// VerifyChain verifies the entire chain of entries
func (card Keycard) VerifyChain(path string, clobber bool) (bool, error) {
	if len(card.Entries) < 1 {
		return false, errors.New("no entries in keycard")
	}

	if len(card.Entries) == 1 {
		return true, nil
	}

	for i := 0; i < len(card.Entries)-1; i++ {
		verifyStatus, err := card.Entries[i].VerifyChain(&card.Entries[i+1])
		if err != nil || !verifyStatus {
			return false, err
		}
	}
	return true, nil
}
