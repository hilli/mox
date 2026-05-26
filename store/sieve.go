package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mjl-/bstore"
)

// Sieve script-related errors. Tested for by managesieveserver to map to
// ManageSieve protocol response codes.
var (
	ErrSieveScriptNotFound       = errors.New("sieve: script not found")
	ErrSieveScriptExists         = errors.New("sieve: script already exists")
	ErrSieveScriptNameInvalid    = errors.New("sieve: script name invalid")
	ErrSieveScriptTooLarge       = errors.New("sieve: script too large")
	ErrSieveTooManyScripts       = errors.New("sieve: too many scripts")
	ErrSieveTotalTooLarge        = errors.New("sieve: total scripts too large")
	ErrSieveScriptActive         = errors.New("sieve: script is active")
)

// SieveScript is a per-account Sieve script stored by ManageSieve PUTSCRIPT.
// At most one script is active at a time, referenced by SieveSettings.ActiveScript.
type SieveScript struct {
	ID      int64
	Name    string `bstore:"nonzero,unique"`
	Content []byte
	Created time.Time `bstore:"default now"`
	Updated time.Time `bstore:"default now"`
}

// SieveSettings is the per-account Sieve singleton record holding which script is
// active. ID 1 is the only valid value.
type SieveSettings struct {
	ID           int // Singleton, always 1.
	ActiveScript string
}

// SieveVacationResponse records when a vacation auto-reply was sent for a
// given (handle, recipient) pair, to support RFC 5230 §4.6 suppression. The
// older the record, the more likely it was already cleaned up; callers use
// this to determine whether a response was sent within a recent window.
type SieveVacationResponse struct {
	ID        int64
	Handle    string    `bstore:"nonzero,index"`
	Recipient string    `bstore:"nonzero,index"`
	Sent      time.Time `bstore:"default now,index"`
}

// CheckSieveScriptName validates a Sieve script name per RFC 5804 §1.6.
// Returns ErrSieveScriptNameInvalid if invalid.
func CheckSieveScriptName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrSieveScriptNameInvalid)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: not valid UTF-8", ErrSieveScriptNameInvalid)
	}
	if utf8.RuneCountInString(name) > 128 {
		return fmt.Errorf("%w: longer than 128 unicode characters", ErrSieveScriptNameInvalid)
	}
	for _, r := range name {
		switch {
		case r >= 0x00 && r <= 0x1f:
			return fmt.Errorf("%w: contains control character", ErrSieveScriptNameInvalid)
		case r == 0x7f:
			return fmt.Errorf("%w: contains DELETE", ErrSieveScriptNameInvalid)
		case r >= 0x80 && r <= 0x9f:
			return fmt.Errorf("%w: contains control character", ErrSieveScriptNameInvalid)
		case r == 0x2028 || r == 0x2029:
			return fmt.Errorf("%w: contains line/paragraph separator", ErrSieveScriptNameInvalid)
		}
	}
	// Don't allow path-like names. Just defensive.
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("%w: contains path separator", ErrSieveScriptNameInvalid)
	}
	return nil
}

// SieveListScripts returns all Sieve scripts for the account, ordered by name.
// The active script name (if any) is also returned. Empty string means no active
// script.
func (a *Account) SieveListScripts() ([]SieveScript, string, error) {
	var scripts []SieveScript
	var active string
	err := a.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
		q := bstore.QueryTx[SieveScript](tx)
		q.SortAsc("Name")
		l, err := q.List()
		if err != nil {
			return fmt.Errorf("listing scripts: %w", err)
		}
		scripts = l
		settings := SieveSettings{ID: 1}
		err = tx.Get(&settings)
		if err == nil {
			active = settings.ActiveScript
		} else if err != bstore.ErrAbsent {
			return fmt.Errorf("get sieve settings: %w", err)
		}
		return nil
	})
	return scripts, active, err
}

// SieveGetScript returns the content of the named script.
func (a *Account) SieveGetScript(name string) ([]byte, error) {
	if err := CheckSieveScriptName(name); err != nil {
		return nil, err
	}
	var content []byte
	err := a.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
		s, err := bstore.QueryTx[SieveScript](tx).FilterNonzero(SieveScript{Name: name}).Get()
		if err == bstore.ErrAbsent {
			return ErrSieveScriptNotFound
		}
		if err != nil {
			return err
		}
		content = s.Content
		return nil
	})
	return content, err
}

// SieveActiveScript returns the active script name (empty if none) and its
// content. Returns ErrSieveScriptNotFound if no active script.
func (a *Account) SieveActiveScript() (string, []byte, error) {
	var name string
	var content []byte
	err := a.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
		settings := SieveSettings{ID: 1}
		err := tx.Get(&settings)
		if err == bstore.ErrAbsent {
			return ErrSieveScriptNotFound
		}
		if err != nil {
			return err
		}
		if settings.ActiveScript == "" {
			return ErrSieveScriptNotFound
		}
		s, err := bstore.QueryTx[SieveScript](tx).FilterNonzero(SieveScript{Name: settings.ActiveScript}).Get()
		if err == bstore.ErrAbsent {
			return ErrSieveScriptNotFound
		}
		if err != nil {
			return err
		}
		name = s.Name
		content = s.Content
		return nil
	})
	return name, content, err
}

// SieveCheckQuota checks if adding/replacing the named script with the given size
// would exceed quotas. If name refers to an existing script, its current size is
// subtracted before checking total size. Pass policy from effective config.
func (a *Account) SieveCheckQuota(name string, size int64, maxScripts int, maxScriptSize, maxTotalSize int64) error {
	if maxScriptSize > 0 && size > maxScriptSize {
		return fmt.Errorf("%w: max %d bytes", ErrSieveScriptTooLarge, maxScriptSize)
	}
	var total int64
	var count int
	var existingSize int64
	err := a.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
		return bstore.QueryTx[SieveScript](tx).ForEach(func(s SieveScript) error {
			count++
			total += int64(len(s.Content))
			if s.Name == name {
				existingSize = int64(len(s.Content))
			}
			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("check quota: %w", err)
	}
	// If name doesn't yet exist, this adds one more script.
	newCount := count
	if existingSize == 0 {
		newCount++
	}
	if maxScripts > 0 && newCount > maxScripts {
		return fmt.Errorf("%w: max %d scripts", ErrSieveTooManyScripts, maxScripts)
	}
	newTotal := total - existingSize + size
	if maxTotalSize > 0 && newTotal > maxTotalSize {
		return fmt.Errorf("%w: max %d bytes total", ErrSieveTotalTooLarge, maxTotalSize)
	}
	return nil
}

// SievePutScript inserts or replaces a script. The caller is responsible for
// having validated the script content (parsing, allowed extensions). Quota checks
// must also be done before calling.
func (a *Account) SievePutScript(name string, content []byte) error {
	if err := CheckSieveScriptName(name); err != nil {
		return err
	}
	now := time.Now()
	return a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		s, err := bstore.QueryTx[SieveScript](tx).FilterNonzero(SieveScript{Name: name}).Get()
		if err == bstore.ErrAbsent {
			return tx.Insert(&SieveScript{Name: name, Content: content, Created: now, Updated: now})
		}
		if err != nil {
			return err
		}
		s.Content = content
		s.Updated = now
		return tx.Update(&s)
	})
}

// SieveDeleteScript deletes the named script. Returns ErrSieveScriptActive if it
// is currently active.
func (a *Account) SieveDeleteScript(name string) error {
	if err := CheckSieveScriptName(name); err != nil {
		return err
	}
	return a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		settings := SieveSettings{ID: 1}
		err := tx.Get(&settings)
		if err != nil && err != bstore.ErrAbsent {
			return err
		}
		if settings.ActiveScript == name {
			return ErrSieveScriptActive
		}
		s, err := bstore.QueryTx[SieveScript](tx).FilterNonzero(SieveScript{Name: name}).Get()
		if err == bstore.ErrAbsent {
			return ErrSieveScriptNotFound
		}
		if err != nil {
			return err
		}
		return tx.Delete(&s)
	})
}

// SieveRenameScript renames a script. If the script is currently active, the
// active reference is also updated.
func (a *Account) SieveRenameScript(oldName, newName string) error {
	if err := CheckSieveScriptName(oldName); err != nil {
		return err
	}
	if err := CheckSieveScriptName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}
	return a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		// Verify new name not in use.
		if _, err := bstore.QueryTx[SieveScript](tx).FilterNonzero(SieveScript{Name: newName}).Get(); err == nil {
			return ErrSieveScriptExists
		} else if err != bstore.ErrAbsent {
			return err
		}
		s, err := bstore.QueryTx[SieveScript](tx).FilterNonzero(SieveScript{Name: oldName}).Get()
		if err == bstore.ErrAbsent {
			return ErrSieveScriptNotFound
		}
		if err != nil {
			return err
		}
		s.Name = newName
		s.Updated = time.Now()
		if err := tx.Update(&s); err != nil {
			return err
		}
		// Update active reference if applicable.
		settings := SieveSettings{ID: 1}
		err = tx.Get(&settings)
		if err == bstore.ErrAbsent {
			return nil
		}
		if err != nil {
			return err
		}
		if settings.ActiveScript == oldName {
			settings.ActiveScript = newName
			return tx.Update(&settings)
		}
		return nil
	})
}

// SieveSetActive sets the named script active. If name is the empty string, any
// active script is disabled. Returns ErrSieveScriptNotFound if the script does
// not exist.
func (a *Account) SieveSetActive(name string) error {
	if name != "" {
		if err := CheckSieveScriptName(name); err != nil {
			return err
		}
	}
	return a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		if name != "" {
			if _, err := bstore.QueryTx[SieveScript](tx).FilterNonzero(SieveScript{Name: name}).Get(); err == bstore.ErrAbsent {
				return ErrSieveScriptNotFound
			} else if err != nil {
				return err
			}
		}
		settings := SieveSettings{ID: 1}
		err := tx.Get(&settings)
		if err == bstore.ErrAbsent {
			settings.ActiveScript = name
			return tx.Insert(&settings)
		}
		if err != nil {
			return err
		}
		settings.ActiveScript = name
		return tx.Update(&settings)
	})
}

// SieveVacationRecentlySent reports whether a vacation response with the given
// handle was sent to the given recipient within the supplied window (per
// RFC 5230 §4.6). The handle is the explicit :handle of the vacation action
// or "default".
func (a *Account) SieveVacationRecentlySent(handle, recipient string, within time.Duration) (bool, error) {
	cutoff := time.Now().Add(-within)
	var found bool
	err := a.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
		q := bstore.QueryTx[SieveVacationResponse](tx)
		q.FilterNonzero(SieveVacationResponse{Handle: handle, Recipient: recipient})
		q.FilterGreater("Sent", cutoff)
		x, err := q.Exists()
		if err != nil {
			return err
		}
		found = x
		return nil
	})
	return found, err
}

// SieveVacationRecordSent records a vacation response sent for (handle,
// recipient) at the current time.
func (a *Account) SieveVacationRecordSent(handle, recipient string) error {
	return a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		return tx.Insert(&SieveVacationResponse{Handle: handle, Recipient: recipient, Sent: time.Now()})
	})
}

// SieveVacationCleanupOlder deletes vacation response records older than
// `keep`. Intended for periodic maintenance; safe to call without a recent
// migration.
func (a *Account) SieveVacationCleanupOlder(keep time.Duration) (int, error) {
	cutoff := time.Now().Add(-keep)
	n := 0
	err := a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		q := bstore.QueryTx[SieveVacationResponse](tx)
		q.FilterLess("Sent", cutoff)
		x, err := q.Delete()
		if err != nil {
			return err
		}
		n = int(x)
		return nil
	})
	return n, err
}
