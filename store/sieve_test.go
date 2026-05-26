package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

func TestSieveScripts(t *testing.T) {
	log := mlog.New("store", nil)
	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/store/mox.conf")
	mox.MustLoadConfig(true, false)
	err := Init(ctxbg)
	tcheck(t, err, "init")
	defer func() {
		err := Close()
		tcheck(t, err, "close")
	}()
	defer Switchboard()()

	acc, err := OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")
	defer func() {
		err = acc.Close()
		tcheck(t, err, "closing account")
		acc.WaitClosed()
	}()

	// Initially empty.
	scripts, active, err := acc.SieveListScripts()
	tcheck(t, err, "list scripts")
	if len(scripts) != 0 || active != "" {
		t.Fatalf("expected empty initial state, got %d scripts, active=%q", len(scripts), active)
	}

	// Bad name.
	if err := CheckSieveScriptName(""); err == nil {
		t.Fatalf("empty name should fail")
	}
	if err := CheckSieveScriptName("a/b"); err == nil {
		t.Fatalf("slash should fail")
	}
	if err := CheckSieveScriptName("ok-name"); err != nil {
		t.Fatalf("ok name failed: %v", err)
	}

	// Quota check.
	err = acc.SieveCheckQuota("one", 100, 5, 1000, 5000)
	tcheck(t, err, "quota ok")
	err = acc.SieveCheckQuota("one", 2000, 5, 1000, 5000)
	if !errors.Is(err, ErrSieveScriptTooLarge) {
		t.Fatalf("expected ErrSieveScriptTooLarge, got %v", err)
	}

	// Put two scripts.
	tcheck(t, acc.SievePutScript("first", []byte("keep;")), "put first")
	tcheck(t, acc.SievePutScript("second", []byte("discard;")), "put second")

	scripts, active, err = acc.SieveListScripts()
	tcheck(t, err, "list scripts")
	if len(scripts) != 2 || active != "" {
		t.Fatalf("got %d scripts active=%q", len(scripts), active)
	}

	// Get one.
	content, err := acc.SieveGetScript("first")
	tcheck(t, err, "get first")
	if !bytes.Equal(content, []byte("keep;")) {
		t.Fatalf("unexpected content %q", content)
	}

	// Activate.
	tcheck(t, acc.SieveSetActive("first"), "set active")
	_, active, err = acc.SieveListScripts()
	tcheck(t, err, "list after activate")
	if active != "first" {
		t.Fatalf("active=%q want first", active)
	}

	// Active script accessor.
	name, content, err := acc.SieveActiveScript()
	tcheck(t, err, "active script")
	if name != "first" || string(content) != "keep;" {
		t.Fatalf("unexpected active: %q %q", name, content)
	}

	// Cannot delete active.
	if err := acc.SieveDeleteScript("first"); !errors.Is(err, ErrSieveScriptActive) {
		t.Fatalf("expected ErrSieveScriptActive, got %v", err)
	}

	// Deactivate then delete.
	tcheck(t, acc.SieveSetActive(""), "deactivate")
	tcheck(t, acc.SieveDeleteScript("first"), "delete first")

	// Rename.
	tcheck(t, acc.SieveRenameScript("second", "renamed"), "rename")
	content, err = acc.SieveGetScript("renamed")
	tcheck(t, err, "get renamed")
	if string(content) != "discard;" {
		t.Fatalf("renamed content wrong")
	}

	// Replacing existing.
	tcheck(t, acc.SievePutScript("renamed", []byte("keep;\n")), "replace")
	content, err = acc.SieveGetScript("renamed")
	tcheck(t, err, "get replaced")
	if string(content) != "keep;\n" {
		t.Fatalf("replaced content wrong: %q", content)
	}

	// Nonexistent.
	_, err = acc.SieveGetScript("nope")
	if !errors.Is(err, ErrSieveScriptNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
	if err := acc.SieveSetActive("nope"); !errors.Is(err, ErrSieveScriptNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}
