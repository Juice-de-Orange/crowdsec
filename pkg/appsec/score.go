package appsec

import (
	"slices"
	"strconv"
	"strings"
)

const (
	unspecifiedScoreReason = "unspecified"
	// An entry with no category is filed under the empty string rather than a
	// placeholder name: the category axis then reads as genuinely empty for
	// the rules that never use it, instead of inventing a bucket.
	noScoreCategory = ""
	// Labels given to the synthetic entries Set() leaves behind. Distinct
	// from any plausible operator-chosen label so the breakdown output stays
	// unambiguous about where the points came from.
	scoreSetLabel       = "set"
	scoreSetLabelPrefix = scoreSetLabel + ":"
)

// Entries are keyed by (label, category): re-adding a pair accumulates in
// place, so the reported order stays stable across a request.
type scoreEntry struct {
	label    string
	category string
	points   int
}

// RequestScore accumulates per-request suspicion points on two axes: a label
// (the signal that fired) and a category (the family it belongs to). The
// entry list is the only source of truth — every accessor derives from it, so
// there is no second index that can drift out of sync.
type RequestScore struct {
	total   int
	entries []scoreEntry
}

func normalizeScoreName(v, fallback string) string {
	if v = strings.TrimSpace(v); v == "" {
		return fallback
	}

	return v
}

// The expr prototypes already cap the category at one value, so extras are
// ignored rather than rejected: a Go-side caller must not be able to trip a
// runtime error no rule author wrote.
func scoreCategoryArg(category []string) string {
	if len(category) == 0 {
		return noScoreCategory
	}

	return normalizeScoreName(category[0], noScoreCategory)
}

func (s *RequestScore) indexOf(label, category string) int {
	return slices.IndexFunc(s.entries, func(e scoreEntry) bool {
		return e.label == label && e.category == category
	})
}

func (s *RequestScore) Add(points int, reason string, category ...string) int {
	label := normalizeScoreName(reason, unspecifiedScoreReason)
	cat := scoreCategoryArg(category)

	if i := s.indexOf(label, cat); i >= 0 {
		s.entries[i].points += points
	} else {
		s.entries = append(s.entries, scoreEntry{label: label, category: cat, points: points})
	}

	s.total += points

	return s.total
}

// Set replaces points instead of accumulating them. With no category the whole
// score is discarded and replaced by a single entry. With categories, each
// named category is dropped and re-seeded at points — so Set(50, "a", "b")
// contributes 100, not 50.
func (s *RequestScore) Set(points int, categories ...string) int {
	if len(categories) == 0 {
		s.entries = []scoreEntry{{
			label:    scoreSetLabel,
			category: noScoreCategory,
			points:   points,
		}}
		s.total = points

		return s.total
	}

	for _, raw := range categories {
		cat := normalizeScoreName(raw, noScoreCategory)

		s.dropCategory(cat)
		s.entries = append(s.entries, scoreEntry{
			label:    scoreSetLabelPrefix + cat,
			category: cat,
			points:   points,
		})
		s.total += points
	}

	return s.total
}

func (s *RequestScore) dropCategory(category string) {
	kept := s.entries[:0]

	for _, e := range s.entries {
		if e.category == category {
			s.total -= e.points
			continue
		}

		kept = append(kept, e)
	}

	s.entries = kept
}

func (s *RequestScore) Total() int {
	if s == nil {
		return 0
	}

	return s.total
}

func (s *RequestScore) For(reason string) int {
	if s == nil {
		return 0
	}

	label := strings.TrimSpace(reason)
	sum := 0

	for _, e := range s.entries {
		if e.label == label {
			sum += e.points
		}
	}

	return sum
}

// No argument means no filter, so RequestScore() keeps the meaning it
// shipped with.
func (s *RequestScore) ForCategories(categories ...string) int {
	if s == nil {
		return 0
	}

	if len(categories) == 0 {
		return s.total
	}

	// An empty name is not a category, so it matches nothing, exactly like
	// any name never used. Entries without a category are reached through
	// Uncategorized() instead — one meaning per spelling.
	wanted := make([]string, 0, len(categories))

	for _, c := range categories {
		if c = strings.TrimSpace(c); c != "" {
			wanted = append(wanted, c)
		}
	}

	sum := 0

	for _, e := range s.entries {
		if slices.Contains(wanted, e.category) {
			sum += e.points
		}
	}

	return sum
}

// These points count toward Total() but belong to no category, so
// ForCategories() can never reach them.
func (s *RequestScore) Uncategorized() int {
	if s == nil {
		return 0
	}

	sum := 0

	for _, e := range s.entries {
		if e.category == noScoreCategory {
			sum += e.points
		}
	}

	return sum
}

func (s *RequestScore) Reasons() []string {
	return s.distinct(func(e scoreEntry) string { return e.label })
}

// Uncategorized entries are not a category, so they are left out here while
// still counting toward Total().
func (s *RequestScore) Categories() []string {
	return s.distinct(func(e scoreEntry) string { return e.category })
}

func (s *RequestScore) distinct(key func(scoreEntry) string) []string {
	if s == nil || len(s.entries) == 0 {
		return nil
	}

	out := make([]string, 0, len(s.entries))

	for _, e := range s.entries {
		// An empty key is "not set", never a bucket of its own.
		if k := key(e); k != "" && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}

	return out
}

// Lets the category outputs stay absent for rules that never set one.
func (s *RequestScore) HasCategories() bool {
	if s == nil {
		return false
	}

	return slices.ContainsFunc(s.entries, func(e scoreEntry) bool {
		return e.category != noScoreCategory
	})
}

func (s *RequestScore) Empty() bool {
	return s == nil || len(s.entries) == 0
}

func (s *RequestScore) String() string {
	return s.detail(s.Reasons(), s.For)
}

func (s *RequestScore) CategoryDetail() string {
	return s.detail(s.Categories(), func(c string) int { return s.ForCategories(c) })
}

func (s *RequestScore) detail(keys []string, sum func(string) int) string {
	if s.Empty() {
		return ""
	}

	var b strings.Builder

	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}

		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(sum(k)))
	}

	return b.String()
}
