package main

import (
	"fmt"
	"sort"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

// timelineSession is one reconstructed conversation. ProjectPath is display
// context and does not partition a session as it does for sequence detection.
type timelineSession struct {
	SourceAgent string        `json:"source_agent"`
	SessionID   string        `json:"session_id,omitempty"`
	ProjectPath string        `json:"project_path,omitempty"`
	Start       string        `json:"start,omitempty"`
	End         string        `json:"end,omitempty"`
	Events      []model.Event `json:"events"`

	sourceType string
	// boundary partitions events without a session id.
	boundary string
}

// groupSessions keys by source agent, source type, and session id. Empty session
// ids fall back to artifact path or event identity. Events and sessions use
// explicit timestamp and identity tiebreakers for deterministic output.
func groupSessions(events []model.Event) []timelineSession {
	type bucket struct {
		agent, sourceType, session, project string
		boundary                            string // the identity that keyed this session (empty-id partitioning)
		start, end                          string
		idx                                 []int // original indices, for the stable within-session order
	}
	order := []string{} // group keys in first-seen order, before final sort
	byKey := map[string]*bucket{}

	for i, ev := range events {
		sourceType := timelineSourceType(ev)
		key := ev.SourceAgent + "\x00" + sourceType + "\x00" + ev.SessionID
		boundary := ""
		if ev.SessionID == "" {
			boundary = timelineEmptySessionBoundary(ev, i)
			key = key + "\x00" + boundary
		}
		b := byKey[key]
		if b == nil {
			b = &bucket{agent: ev.SourceAgent, sourceType: sourceType, session: ev.SessionID, boundary: boundary}
			byKey[key] = b
			order = append(order, key)
		}
		b.idx = append(b.idx, i)
	}

	sessions := make([]timelineSession, 0, len(order))
	for _, key := range order {
		b := byKey[key]
		sort.SliceStable(b.idx, func(x, y int) bool {
			ix, iy := b.idx[x], b.idx[y]
			return timelineEventIndexLess(events[ix], ix, events[iy], iy)
		})
		evs := make([]model.Event, len(b.idx))
		for j, i := range b.idx {
			evs[j] = events[i]
			if b.project == "" && events[i].ProjectPath != "" {
				b.project = events[i].ProjectPath
			}
			if ts := events[i].Timestamp; ts != "" {
				if b.start == "" {
					b.start = ts
				}
				b.end = ts
			}
		}
		sessions = append(sessions, timelineSession{
			SourceAgent: b.agent,
			SessionID:   b.session,
			ProjectPath: b.project,
			Start:       b.start,
			End:         b.end,
			Events:      evs,
			sourceType:  b.sourceType,
			boundary:    b.boundary,
		})
	}

	sort.Slice(sessions, func(x, y int) bool {
		a, b := sessions[x], sessions[y]
		if cmp := model.CompareTimestamps(a.Start, b.Start); cmp != 0 {
			return cmp < 0
		}
		if a.SourceAgent != b.SourceAgent {
			return a.SourceAgent < b.SourceAgent
		}
		if a.sourceType != b.sourceType {
			return a.sourceType < b.sourceType
		}
		if a.SessionID != b.SessionID {
			return a.SessionID < b.SessionID
		}
		return a.boundary < b.boundary
	})
	return sessions
}

func timelineSourceType(ev model.Event) string {
	if ev.SourceType != "" {
		return ev.SourceType
	}
	// Sparse fixtures may omit source_type. Timeline is an at-rest command, so
	// artifact is the most useful default bucket.
	return model.SourceArtifact
}

func timelineEmptySessionBoundary(ev model.Event, idx int) string {
	if timelineSourceType(ev) == model.SourceArtifact && ev.Evidence.LocalPath != "" {
		return "artifact:" + ev.Evidence.LocalPath
	}
	if ev.EventID != "" {
		return "event:" + ev.EventID
	}
	return fmt.Sprintf("event-index:%d", idx)
}

func timelineEventIndexLess(a model.Event, ai int, b model.Event, bi int) bool {
	if cmp := model.CompareTimestamps(a.Timestamp, b.Timestamp); cmp != 0 {
		return cmp < 0
	}
	return ai < bi
}
