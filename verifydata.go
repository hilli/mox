package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	bolt "go.etcd.io/bbolt"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrptdb"
)

func cmdVerifydata(c *cmd) {
	c.params = "data-dir"
	c.help = `Verify the contents of a data directory, typically of a backup.

Verifydata checks all database files to see if they are valid BoltDB/bstore
databases. It checks that all messages in the database have a corresponding
on-disk message file and there are no unrecognized files. If option -fix is
specified, unrecognized message files are moved away. This may be needed after
a restore, because messages enqueued or delivered in the future may get those
message sequence numbers assigned and writing the message file would fail.
Consistency of message/mailbox UID, UIDNEXT and UIDVALIDITY is verified as
well.

Because verifydata opens the database files, schema upgrades may automatically
be applied. This can happen if you use a new mox release. It is useful to run
"mox verifydata" with a new binary before attempting an upgrade, but only on a
copy of the database files, as made with "mox backup". Before upgrading, make a
new backup again since "mox verifydata" may have upgraded the database files,
possibly making them potentially no longer readable by the previous version.
`
	var fix bool
	c.flag.BoolVar(&fix, "fix", false, "fix fixable problems, such as moving away message files not referenced by their database")
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	dataDir := filepath.Clean(args[0])

	ctxbg := context.Background()

	// Check whether file exists, or rather, that it doesn't not exist. Other errors
	// will return true as well, so the triggered check can give the details.
	exists := func(path string) bool {
		_, err := os.Stat(path)
		return err == nil || !os.IsNotExist(err)
	}

	// Check for error. If so, write a log line, including the path, and set fail so we
	// can warn at the end.
	var fail bool
	checkf := func(err error, path, format string, args ...any) {
		if err == nil {
			return
		}
		fail = true
		log.Printf("error: %s: %s: %v", path, fmt.Sprintf(format, args...), err)
	}

	// When we fix problems, we may have to move files/dirs. We need to ensure the
	// directory of the destination path exists before we move. We keep track of
	// created dirs so we don't try to create the same directory all the time.
	createdDirs := map[string]struct{}{}
	ensureDir := func(path string) {
		dir := filepath.Dir(path)
		if _, ok := createdDirs[dir]; ok {
			return
		}
		err := os.MkdirAll(dir, 0770)
		checkf(err, dir, "creating directory")
		createdDirs[dir] = struct{}{}
	}

	// Check a database file by opening it with BoltDB and bstore and lightly checking
	// its contents.
	checkDB := func(path string, types []any) {
		_, err := os.Stat(path)
		checkf(err, path, "checking if file exists")
		if err != nil {
			return
		}
		bdb, err := bolt.Open(path, 0600, nil)
		checkf(err, path, "open database with bolt")
		if err != nil {
			return
		}
		// Check BoltDB consistency.
		err = bdb.View(func(tx *bolt.Tx) error {
			for err := range tx.Check() {
				checkf(err, path, "bolt database problem")
			}
			return nil
		})
		checkf(err, path, "reading bolt database")
		bdb.Close()

		db, err := bstore.Open(ctxbg, path, nil, types...)
		checkf(err, path, "open database with bstore")
		if err != nil {
			return
		}
		defer db.Close()

		err = db.Read(ctxbg, func(tx *bstore.Tx) error {
			// Check bstore consistency, if it can export all records for all types. This is a
			// quick way to get bstore to parse all records.
			types, err := tx.Types()
			checkf(err, path, "getting bstore types from database")
			if err != nil {
				return nil
			}
			for _, t := range types {
				var fields []string
				err := tx.Records(t, &fields, func(m map[string]any) error {
					return nil
				})
				checkf(err, path, "parsing record for type %q", t)
			}
			return nil
		})
		checkf(err, path, "checking database file")
	}

	checkFile := func(path string) {
		_, err := os.Stat(path)
		checkf(err, path, "checking if file exists")
	}

	checkQueue := func() {
		dbpath := filepath.Join(dataDir, "queue/index.db")
		checkDB(dbpath, queue.DBTypes)

		// Check that all messages present in the database also exist on disk.
		seen := map[string]struct{}{}
		db, err := bstore.Open(ctxbg, dbpath, &bstore.Options{MustExist: true}, queue.DBTypes...)
		checkf(err, dbpath, "opening queue database to check messages")
		if err == nil {
			err := bstore.QueryDB[queue.Msg](ctxbg, db).ForEach(func(m queue.Msg) error {
				mp := store.MessagePath(m.ID)
				seen[mp] = struct{}{}
				p := filepath.Join(dataDir, "queue", mp)
				checkFile(p)
				return nil
			})
			checkf(err, dbpath, "reading messages in queue database to check files")
		}

		// Check that there are no files that could be treated as a message.
		qdir := filepath.Join(dataDir, "queue")
		err = filepath.WalkDir(qdir, func(qpath string, d fs.DirEntry, err error) error {
			checkf(err, qpath, "walk")
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			p := qpath[len(qdir)+1:]
			if p == "index.db" {
				return nil
			}
			if _, ok := seen[p]; ok {
				return nil
			}
			l := strings.Split(p, string(filepath.Separator))
			if len(l) == 1 {
				log.Printf("warning: %s: unrecognized file in queue directory, ignoring", qpath)
				return nil
			}
			// If it doesn't look like a message number, there is no risk of it being the name
			// of a message enqueued in the future.
			if len(l) >= 3 {
				if _, err := strconv.ParseInt(l[1], 10, 64); err != nil {
					log.Printf("warning: %s: unrecognized file in queue directory, ignoring", qpath)
					return nil
				}
			}
			if !fix {
				checkf(errors.New("may interfere with messages enqueued in the future"), qpath, "unrecognized file in queue directory (use the -fix flag to move it away)")
				return nil
			}
			npath := filepath.Join(dataDir, "moved", "queue", p)
			ensureDir(npath)
			err = os.Rename(qpath, npath)
			checkf(err, qpath, "moving queue message file away")
			if err == nil {
				log.Printf("warning: moved %s to %s", qpath, npath)
			}
			return nil
		})
		checkf(err, qdir, "walking queue directory")
	}

	// Check an account, with its database file and messages.
	checkAccount := func(name string) {
		accdir := filepath.Join(dataDir, "accounts", name)
		checkDB(filepath.Join(accdir, "index.db"), store.DBTypes)

		jfdbpath := filepath.Join(accdir, "junkfilter.db")
		jfbloompath := filepath.Join(accdir, "junkfilter.bloom")
		if exists(jfdbpath) || exists(jfbloompath) {
			checkDB(jfdbpath, junk.DBTypes)
		}
		// todo: add some kind of check for the bloom filter?

		// Check that all messages in the database have a message file on disk.
		// And check consistency of UIDs with the mailbox UIDNext, and check UIDValidity.
		seen := map[string]struct{}{}
		dbpath := filepath.Join(accdir, "index.db")
		db, err := bstore.Open(ctxbg, dbpath, &bstore.Options{MustExist: true}, store.DBTypes...)
		checkf(err, dbpath, "opening account database to check messages")
		if err == nil {
			uidvalidity := store.NextUIDValidity{ID: 1}
			if err := db.Get(ctxbg, &uidvalidity); err != nil {
				checkf(err, dbpath, "missing nextuidvalidity")
			}

			mailboxUIDNexts := map[int64]store.UID{}
			err := bstore.QueryDB[store.Mailbox](ctxbg, db).ForEach(func(mb store.Mailbox) error {
				mailboxUIDNexts[mb.ID] = mb.UIDNext

				if mb.UIDValidity >= uidvalidity.Next {
					checkf(errors.New(`inconsistent uidvalidity for mailbox/account, see "mox fixuidmeta"`), dbpath, "mailbox id %d has uidvalidity %d >= account nextuidvalidity %d", mb.ID, mb.UIDValidity, uidvalidity.Next)
				}
				return nil
			})
			checkf(err, dbpath, "reading mailboxes to check uidnext consistency")

			err = bstore.QueryDB[store.Message](ctxbg, db).ForEach(func(m store.Message) error {
				if uidnext := mailboxUIDNexts[m.MailboxID]; m.UID >= uidnext {
					checkf(errors.New(`inconsistent uidnext for message/mailbox, see "mox fixuidmeta"`), dbpath, "message id %d in mailbox id %d has uid %d >= mailbox uidnext %d", m.ID, m.MailboxID, m.UID, uidnext)
				}
				mp := store.MessagePath(m.ID)
				seen[mp] = struct{}{}
				p := filepath.Join(accdir, "msg", mp)
				checkFile(p)
				return nil
			})
			checkf(err, dbpath, "reading messages in account database to check files")
		}

		// Walk through all files in the msg directory. Warn about files that weren't in
		// the database as message file. Possibly move away files that could cause trouble.
		msgdir := filepath.Join(accdir, "msg")
		if !exists(msgdir) {
			// New accounts with messages don't have a msg directory.
			return
		}
		err = filepath.WalkDir(msgdir, func(msgpath string, d fs.DirEntry, err error) error {
			checkf(err, msgpath, "walk")
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			p := msgpath[len(msgdir)+1:]
			if _, ok := seen[p]; ok {
				return nil
			}
			l := strings.Split(p, string(filepath.Separator))
			if len(l) == 1 {
				log.Printf("warning: %s: unrecognized file in message directory, ignoring", msgpath)
				return nil
			}
			if !fix {
				checkf(errors.New("may interfere with future account messages"), msgpath, "unrecognized file in account message directory (use the -fix flag to move it away)")
				return nil
			}
			npath := filepath.Join(dataDir, "moved", "accounts", name, "msg", p)
			ensureDir(npath)
			err = os.Rename(msgpath, npath)
			checkf(err, msgpath, "moving account message file away")
			if err == nil {
				log.Printf("warning: moved %s to %s", msgpath, npath)
			}
			return nil
		})
		checkf(err, msgdir, "walking account message directory")
	}

	// Check everything in the "accounts" directory.
	checkAccounts := func() {
		accountsDir := filepath.Join(dataDir, "accounts")
		entries, err := os.ReadDir(accountsDir)
		checkf(err, accountsDir, "reading accounts directory")
		for _, e := range entries {
			// We treat all directories as accounts. When we were backing up, we only verified
			// accounts from the config and made regular file copies of all other files
			// (perhaps an old account, but at least not with an open database file). It may
			// turn out that that account was/is not valid, generating warnings. Better safe
			// than sorry. It should hopefully get the admin to move away such an old account.
			if e.IsDir() {
				checkAccount(e.Name())
			} else {
				log.Printf("warning: %s: unrecognized file in accounts directory, ignoring", filepath.Join("accounts", e.Name()))
			}
		}
	}

	// Check all files, skipping the known files, queue and accounts directories. Warn
	// about unknown files. Skip a "tmp" directory. And a "moved" directory, we
	// probably created it ourselves.
	backupmoxversion := "(unknown)"
	checkOther := func() {
		err := filepath.WalkDir(dataDir, func(dpath string, d fs.DirEntry, err error) error {
			checkf(err, dpath, "walk")
			if err != nil {
				return nil
			}
			if dpath == dataDir {
				return nil
			}
			p := dpath
			if dataDir != "." {
				p = p[len(dataDir)+1:]
			}
			switch p {
			case "dmarcrpt.db", "mtasts.db", "tlsrpt.db", "receivedid.key", "lastknownversion":
				return nil
			case "acme", "queue", "accounts", "tmp", "moved":
				return fs.SkipDir
			case "moxversion":
				buf, err := os.ReadFile(dpath)
				checkf(err, dpath, "reading moxversion")
				if err == nil {
					backupmoxversion = string(buf)
				}
				return nil
			}
			log.Printf("warning: %s: unrecognized other file, ignoring", dpath)
			return nil
		})
		checkf(err, dataDir, "walking data directory")
	}

	checkDB(filepath.Join(dataDir, "dmarcrpt.db"), dmarcdb.DBTypes)
	checkDB(filepath.Join(dataDir, "mtasts.db"), mtastsdb.DBTypes)
	checkDB(filepath.Join(dataDir, "tlsrpt.db"), tlsrptdb.DBTypes)
	checkQueue()
	checkAccounts()
	checkOther()

	if backupmoxversion != moxvar.Version {
		log.Printf("NOTE: The backup was made with mox version %q, while verifydata was run with mox version %q. Database files have probably been modified by running mox verifydata. Make a fresh backup before upgrading.", backupmoxversion, moxvar.Version)
	}

	if fail {
		log.Fatalf("errors were found")
	} else {
		fmt.Printf("%s: OK\n", dataDir)
	}
}
