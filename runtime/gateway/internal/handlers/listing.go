package handlers

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Shared listing semantics for operator list endpoints (approvals,
// continuations, executions, and the execution queue).
//
// Historically these endpoints returned items in Go map-iteration order,
// which is deliberately randomized. Applying `limit` on top of that order
// returned an arbitrary, non-reproducible subset rather than a meaningful
// "most recent N" window. These helpers centralize limit parsing and define
// a single, deterministic ordering policy so the endpoints behave
// consistently.

const (
	defaultListLimit = 100
	maxListLimit     = 1000
)

func parseLimit(r *http.Request, def, max int) int {
	limit := def
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if l, err := strconv.Atoi(raw); err == nil && l > 0 {
			limit = l
		}
	}
	if max > 0 && limit > max {
		limit = max
	}
	return limit
}

func sortAscending(sortOrder string) bool {
	return sortOrder == "oldest"
}

// Cursor represents a position in a sorted, paginated list result.
// The cursor encodes the sort key (timestamp) and ID of the last item
// seen, allowing the next page to resume exactly where the previous left off.
type Cursor struct {
	Timestamp time.Time
	ID        string
}

// encodeCursor serializes a cursor to a base64 string suitable for use as
// a URL query parameter value.
func encodeCursor(c Cursor) string {
	raw := c.Timestamp.Format(time.RFC3339Nano) + "|" + c.ID
	return base64.URLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor parses a cursor string produced by encodeCursor.
// Returns false if the string is empty, malformed, or cannot be decoded.
func decodeCursor(raw string) (Cursor, bool) {
	if raw == "" {
		return Cursor{}, false
	}
	decoded, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return Cursor{}, false
	}
	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 {
		return Cursor{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return Cursor{}, false
	}
	return Cursor{Timestamp: t, ID: parts[1]}, true
}

// cursorFilter returns a new slice containing only items that come AFTER
// the cursor position (exclusive lower bound). For descending order
// (newest first, ascending=false), it skips items with timestamps >= cursor
// (or equal timestamp with ID <= cursor's ID). For ascending order
// (oldest first, ascending=true), it skips items with timestamps <= cursor.
func cursorFilter[T any](items []*T, cur Cursor, ascending bool, getTimestamp func(T) time.Time, getID func(T) string) []*T {
	if (cur.Timestamp.IsZero()) && cur.ID == "" {
		return items
	}

	result := make([]*T, 0, len(items))
	for _, item := range items {
		itemTS := getTimestamp(*item)
		itemID := getID(*item)

		var afterCursor bool
		if ascending {
			if itemTS.After(cur.Timestamp) {
				afterCursor = true
			} else if itemTS.Equal(cur.Timestamp) && itemID > cur.ID {
				afterCursor = true
			}
		} else {
			if itemTS.Before(cur.Timestamp) {
				afterCursor = true
			} else if itemTS.Equal(cur.Timestamp) && itemID > cur.ID {
				afterCursor = true
			}
		}

		if afterCursor {
			result = append(result, item)
		}
	}

	return result
}

// ListResult holds the output of the unified listing pipeline.
type ListResult[T any] struct {
	Items      []*T
	Count      int
	NextCursor string
}

// TimestampGetter and IDGetter extract the sort key fields from an item.
type TimestampGetter[T any] func(T) time.Time
type IDGetter[T any] func(T) string

// SortSpec defines the sort direction and tiebreaker for a list type.
type SortSpec[T any] struct {
	Ascending    bool
	GetTimestamp TimestampGetter[T]
	GetID        IDGetter[T]
}

// buildListedItems applies the full filter → sort → cursor → limit → next_cursor
// pipeline to a pre-filtered, pre-sorted slice of items. It returns a ListResult
// with all fields populated. The items slice should already be sorted by the
// caller (typically via buildFilteredList for continuations or equivalent
// logic for other types).
func buildListedItems[T any](items []*T, limit int, rawAfter string, spec SortSpec[T]) ListResult[T] {
	if items == nil {
		items = []*T{}
	}

	ascending := spec.Ascending
	getTimestamp := spec.GetTimestamp
	getID := spec.GetID

	// Apply cursor-based pagination after sorting, before limit.
	var nextCursor string
	if rawAfter != "" {
		if cur, ok := decodeCursor(rawAfter); ok {
			items = cursorFilter(items, cur, ascending, getTimestamp, getID)
		}
	}

	if items == nil {
		items = []*T{}
	}

	if limit > 0 && len(items) > limit {
		lastItem := items[limit-1]
		nextCursor = encodeCursor(Cursor{
			Timestamp: getTimestamp(*lastItem),
			ID:        getID(*lastItem),
		})
		items = items[:limit]
	}

	return ListResult[T]{
		Items:      items,
		Count:      len(items),
		NextCursor: nextCursor,
	}
}
