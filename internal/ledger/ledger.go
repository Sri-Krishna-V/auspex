// Package ledger records, per agent, the last time auspex's hook actually ran
// on this machine. It owns the "coverage" bucket of the shared state database
// (see internal/state, which owns the file) and stores exactly one RFC3339Nano
// timestamp per agent id — no command, path, or transcript content.
//
// The ledger answers one narrow question: did auspex execute here, for this
// agent? It is not a liveness or completeness claim. An absent entry means no
// hook execution was recorded on this machine — not that the agent never ran,
// and not that nothing happened. Agents observed only by at-rest scanning
// never appear here at all.
//
// Keys are agent ids from a closed enum, so the bucket is bounded by
// construction: no eviction, no LRU, no size cap.
package ledger

import (
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// bucketCoverage holds one timestamp per agent id. The handle is the shared
// auspex state database; this package owns only this bucket.
var bucketCoverage = []byte("coverage")

// Touch records at as the most recent hook execution for agent, creating the
// bucket on first use. Last write wins: the ledger holds a single "most
// recent" stamp, not a history. An empty agent id is a no-op rather than a
// blank key, so a malformed invocation cannot claim coverage for nothing.
func Touch(db *bolt.DB, agent string, at time.Time) error {
	if db == nil || agent == "" {
		return nil
	}
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketCoverage)
		if err != nil {
			return fmt.Errorf("ledger: init bucket: %w", err)
		}
		return b.Put([]byte(agent), []byte(at.UTC().Format(time.RFC3339Nano)))
	})
}

// Read returns every recorded agent stamp, in UTC. A missing bucket is not an
// error — it is the ordinary state of a machine where no hook has run yet, and
// yields a nil map. A value that will not parse fails the whole read instead of
// being skipped: a caller that silently dropped it would report "never" for an
// agent whose stamp exists but is unreadable, which is a lie in the unsafe
// direction.
func Read(db *bolt.DB) (map[string]time.Time, error) {
	if db == nil {
		return nil, nil
	}
	var out map[string]time.Time
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCoverage)
		if b == nil {
			return nil
		}
		out = map[string]time.Time{}
		return b.ForEach(func(k, v []byte) error {
			at, parseErr := time.Parse(time.RFC3339Nano, string(v))
			if parseErr != nil {
				return fmt.Errorf("ledger: agent %q: %w", k, parseErr)
			}
			out[string(k)] = at.UTC()
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
