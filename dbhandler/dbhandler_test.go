package dbhandler

import (
	"errors"

	"github.com/darkwyrm/anselusd/config"
)

// setupTest initializes the global config and resets the database
func setupTest() error {

	// In this case we don't care about the diceware wordlist returned. Note that
	// resetDatabase depends on initialization of the server config, so this call must go
	// first
	config.SetupConfig()

	if err := resetDatabase(); err != nil {
		return err
	}

	Connect()
	return nil
}

// resetDatabase empties out the workspace directory to make sure it's ready for a filesystem
// test. Because the workspace directory may have special permissions set on it, we can't just
// delete the directory and recreate it--we have to actually empty the directory.
func resetDatabase() error {
	return errors.New("Unimplemented")
}

// TODO: Tests to write:

// AddDevice
// AddEntry
// AddWorkspace
// CheckDevice
// CheckLockout
// CheckPasscode
// CheckPassword
// CheckRegCode
// CheckUserID
// CheckWorkspace
// DeletePasscode
// DeleteRegCode
// GetAliases
// GetAnselusAddressType
// GetEncryptionPair
// GetLastEntry
// GetOrgEntries
// GetPrimarySigningKey
// GetQuota
// GetQuotaUsage
// GetUserEntries
// IsAlias
// LogFailure
// ModifyQuotaUsage
// PreregWorkspace
// RemoveDevice
// RemoveExpiredPasscodes
// RemoveWorkspace
// ResetPassword
// ResetQuotaUsage
// ResolveAddress
// SetPassword
// SetQuota
// SetQuotaUsage
// SetWorkspaceStatus
// UpdateDevice
