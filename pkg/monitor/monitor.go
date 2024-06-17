package monitor

import (
	"context"
	"sync"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	DefaultBatchSize     = 512
	DefaultQueryInterval = 10 * time.Minute
)

// TODO: Figure out the proper interface to the monitor. Are callbacks
// the right way, or should we instead have one or more channels to
// pass new data items and alerts?
type Callbacks interface {
	// Called when a log (identified by key hash) has a new tree
	// head; application can use this to persist the tree head.
	// TODO: Also include cosignatures?
	NewTreeHead(logKeyHash crypto.Hash, signedTreeHead types.SignedTreeHead)
	// Called when there are new leaves with submit key of
	// interest. Includes only leaves with a known submit key, and
	// where signature and inclusion proof are valid.
	//
	// The numberOfProcessedLeaves reports the monitoring
	// progress; it is the number of leaves that have been
	// retrieved from the log and that have been checked for
	// proper inclusion; it may lag behind the tree size of the
	// latest seen tree. indices and leaves represents the subset
	// of new leaves that are of interest.
	NewLeaves(logKeyHash crypto.Hash, numberOfProcessedLeaves uint64, indices []uint64, leaves []types.Leaf)
	Alert(logKeyHash crypto.Hash, e error)
}

type MonitorState struct {
	TreeHead types.TreeHead
	// Index of next leaf to process.
	NextLeafIndex uint64
}

type Config struct {
	QueryInterval time.Duration
	// Maximum number of leaves to request at a time
	BatchSize uint64
	// Keys of interest. If nil, all keys are of interest (but no
	// signatures are verified).
	SubmitKeys map[crypto.Hash]crypto.PublicKey
	Callbacks  Callbacks
}

func (c *Config) applyDefaults() Config {
	r := *c
	if r.QueryInterval <= 0 {
		r.QueryInterval = DefaultQueryInterval
	}
	if r.BatchSize == 0 {
		r.BatchSize = DefaultBatchSize
	}
	return r
}

func (c *Config) filterLeaves(
	leaves []types.Leaf, startIndex uint64, alertCallback func(*Alert)) ([]uint64, []types.Leaf) {
	if c.SubmitKeys == nil {
		indices := make([]uint64, len(leaves))
		for i := range indices {
			indices[i] = startIndex + uint64(i)
		}
		return indices, leaves
	}
	indices := []uint64{}
	matchedLeaves := []types.Leaf{}
	for i, leaf := range leaves {
		index := startIndex + uint64(i)
		if key, ok := c.SubmitKeys[leaf.KeyHash]; ok {
			if !leaf.Verify(&key) {
				// Indicates log is misbehaving.
				// Generate alert and continue
				// processing remaining leaves. This
				// is an issue where inconsistent
				// verification conditions could
				// matter, see
				// https://hdevalence.ca/blog/2020-10-04-its-25519am
				alertCallback(newAlert(AlertLogError, "invalid signature on leaf %d, keyhash %x", index, leaf.KeyHash))
			} else {
				matchedLeaves = append(matchedLeaves, leaf)
				indices = append(indices, index)
			}
		}
	}
	return indices, matchedLeaves
}

// Monitor a single sigsum log. A monitor program is expected to call
// this function in one goroutine per log it monitors.
func MonitorLog(ctx context.Context, client *monitoringLogClient,
	state MonitorState, c *Config) {
	config := c.applyDefaults()
	keyHash := crypto.HashBytes(client.logKey[:])
	for ctx.Err() == nil {
		updateCtx, cancel := context.WithTimeout(ctx, config.QueryInterval)
		if state.TreeHead.Size == state.NextLeafIndex {
			cth, err := client.getTreeHead(updateCtx, &state.TreeHead)
			if err != nil {
				config.Callbacks.Alert(keyHash, err)
			} else if cth.Size > state.TreeHead.Size {
				config.Callbacks.NewTreeHead(keyHash, cth)
				state.TreeHead = cth.TreeHead
			}
		}
		for glState := (*getLeavesState)(nil); state.NextLeafIndex < state.TreeHead.Size; {
			end := state.TreeHead.Size
			if end-state.NextLeafIndex > config.BatchSize {
				end = state.NextLeafIndex + config.BatchSize
			}
			var allLeaves []types.Leaf
			var err error
			allLeaves, glState, err = client.getLeaves(updateCtx, glState, &state.TreeHead,
				requests.Leaves{StartIndex: state.NextLeafIndex, EndIndex: end})
			if err != nil {
				config.Callbacks.Alert(keyHash, err)
				break
			}
			indices, leaves := config.filterLeaves(allLeaves, state.NextLeafIndex, func(alert *Alert) {
				config.Callbacks.Alert(keyHash, err)
			})
			state.NextLeafIndex += uint64(len(allLeaves))
			config.Callbacks.NewLeaves(keyHash, state.NextLeafIndex, indices, leaves)
		}
		// Waits until end of interval
		<-updateCtx.Done()
		cancel()
	}
}

// Runs monitor in the background, until ctx is cancelled.
func StartMonitoring(
	ctx context.Context, p *policy.Policy,
	config *Config,
	state map[crypto.Hash]MonitorState) <-chan struct{} {
	var wg sync.WaitGroup
	for _, l := range p.GetLogsWithUrl() {
		keyHash := crypto.HashBytes(l.PublicKey[:])
		initialState, ok := state[keyHash]
		if !ok {
			initialState = MonitorState{
				TreeHead:      types.NewEmptyTreeHead(),
				NextLeafIndex: 0,
			}
		}

		wg.Add(1)
		go func(l policy.Entity) {
			MonitorLog(ctx, newMonitoringLogClient(&l.PublicKey, l.URL), initialState, config)
			wg.Done()
		}(l)
	}
	ch := make(chan struct{})
	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch
}
