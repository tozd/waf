package waf

// pathranking_test.go tests Vue Router's path ranking algorithm as ported to Go.
// Test cases are derived from:
//   vue-router/packages/router/__tests__/matcher/pathRanking.spec.ts

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pathEntry represents a path with optional scoring options.
// It mirrors Array<string | [string, PathParserOptions]> from pathRanking.spec.ts.
type pathEntry struct {
	path    string
	opts    pathScoringOptions
	hasOpts bool // True when opts were explicitly specified.
}

// p creates a pathEntry with default options (mirrors a plain string in the TS tests).
func p(path string) pathEntry {
	return pathEntry{path: path}
}

// pOpts creates a pathEntry with explicit options (mirrors [path, options] in the TS tests).
func pOpts(path string, opts pathScoringOptions) pathEntry {
	return pathEntry{path: path, opts: opts, hasOpts: true}
}

// id returns the unique identifier for this entry.
// Mirrors: path + (options ? JSON.stringify(options) : ”) from pathRanking.spec.ts.
func (e pathEntry) id() string {
	if !e.hasOpts {
		return e.path
	}
	return fmt.Sprintf(`%s{"strict":%v,"sensitive":%v}`, e.path, e.opts.strict, e.opts.sensitive)
}

// joinScore formats a score for display, mirroring joinScore from pathRanking.spec.ts.
func joinScore(score [][]float64) string {
	segs := make([]string, len(score))
	for i, seg := range score {
		parts := make([]string, len(seg))
		for j, v := range seg {
			parts[j] = fmt.Sprintf("%g", v)
		}
		segs[i] = "[" + strings.Join(parts, ", ") + "]"
	}
	return strings.Join(segs, " ")
}

// scoresEqual reports whether two path scores are identical.
func scoresEqual(a, b [][]float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

// checkPathOrder verifies that entries, sorted by Vue Router's path scoring algorithm,
// produce the expected order (highest priority first).
// It mirrors checkPathOrder from pathRanking.spec.ts.
func checkPathOrder(t *testing.T, entries []pathEntry) {
	t.Helper()

	type scored struct {
		id    string
		score [][]float64
	}

	// Reverse to force reordering, same as the TypeScript test does.
	n := len(entries)
	items := make([]scored, n)
	for i, e := range entries {
		tokens, errE := tokenizePath(e.path)
		require.NoError(t, errE, "% -+#.1v", errE)
		items[n-1-i] = scored{
			id:    e.id(),
			score: computePathScore(tokens, e.opts),
		}
	}

	slices.SortStableFunc(items, func(a, b scored) int {
		comp := comparePathParserScore(a.score, b.score)
		switch {
		case comp < 0:
			return -1
		case comp > 0:
			return 1
		default:
			return 0
		}
	})

	// Check that adjacent parsers don't have equal scores (mirrors the TS warning).
	for i := range len(items) - 1 {
		if scoresEqual(items[i].score, items[i+1].score) {
			t.Errorf("Different routes should not have the same score:\n%s -> %s\n%s -> %s",
				items[i].id, joinScore(items[i].score),
				items[i+1].id, joinScore(items[i+1].score))
		}
	}

	expectedIDs := make([]string, n)
	for i, e := range entries {
		expectedIDs[i] = e.id()
	}
	gotIDs := make([]string, n)
	for i, item := range items {
		gotIDs[i] = item.id
	}
	if !assert.Equal(t, expectedIDs, gotIDs) {
		for _, item := range items {
			t.Logf("%s -> %s", item.id, joinScore(item.score))
		}
	}
}

// allOpts mirrors Vue Router's possibleOptions from pathRanking.spec.ts:
//
//	[undefined, { strict: true, sensitive: false }, { strict: false, sensitive: true }, { strict: true, sensitive: true }]
//
// The first element (zero value) corresponds to TypeScript's undefined.
var allOpts = []pathScoringOptions{
	{},
	{strict: true, sensitive: false},
	{strict: false, sensitive: true},
	{strict: true, sensitive: true},
}

func TestPathRankingCompareFunction(t *testing.T) {
	t.Parallel()

	// compare mirrors the compare() helper in pathRanking.spec.ts.
	compare := comparePathParserScore

	t.Run("same length", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, float64(1), compare([][]float64{{2}}, [][]float64{{3}}))  //nolint:testifylint
		assert.Equal(t, float64(0), compare([][]float64{{2}}, [][]float64{{2}}))  //nolint:testifylint
		assert.Equal(t, float64(-1), compare([][]float64{{4}}, [][]float64{{3}})) //nolint:testifylint
	})

	t.Run("longer", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, float64(1), compare([][]float64{{2}}, [][]float64{{3, 1}})) //nolint:testifylint
		// NOTE: we are assuming we never pass end: false.
		assert.Equal(t, float64(1), compare([][]float64{{3}}, [][]float64{{3, 1}})) //nolint:testifylint
		assert.Equal(t, float64(1), compare([][]float64{{1, 3}}, [][]float64{{2}})) //nolint:testifylint
		assert.Equal(t, float64(-1), compare([][]float64{{4}}, [][]float64{{3}}))   //nolint:testifylint
		assert.Equal(t, float64(1), compare([][]float64{}, [][]float64{{3}}))       //nolint:testifylint
	})
}

func TestPathRankingOrder(t *testing.T) {
	t.Parallel()

	t.Run("works", func(t *testing.T) {
		t.Parallel()
		checkPathOrder(t, []pathEntry{
			p("/a/b/c"),
			p("/a/b"),
			p("/a/:b/c"),
			p("/a/:b"),
			p("/a"),
			p("/a-:b-:c"),
			p("/a-:b"),
			p("/a-:w(.*)"),
			p("/:a-:b-:c"),
			p("/:a-:b"),
			p("/:a-:b(.*)"),
			p("/:a/-:b"),
			p("/:a/:b"),
			p("/:w"),
			p("/:w+"),
		})
	})

	t.Run("puts the slash before optional parameters", func(t *testing.T) {
		t.Parallel()
		for _, opts := range allOpts {
			checkPathOrder(t, []pathEntry{p("/"), pOpts("/:a?", opts)})
			checkPathOrder(t, []pathEntry{p("/"), pOpts("/:a*", opts)})
			checkPathOrder(t, []pathEntry{p("/"), pOpts("/:a(\\d+)?", opts)})
			checkPathOrder(t, []pathEntry{p("/"), pOpts("/:a(\\d+)*", opts)})
		}
	})

	t.Run("puts catchall param after same prefix", func(t *testing.T) {
		t.Parallel()
		for _, opts := range allOpts {
			checkPathOrder(t, []pathEntry{pOpts("/a", opts), pOpts("/a/:a(.*)*", opts)})
		}
	})

	t.Run("sensitive should go before non sensitive", func(t *testing.T) {
		t.Parallel()
		checkPathOrder(t, []pathEntry{
			pOpts("/Home", pathScoringOptions{sensitive: true}),
			pOpts("/home", pathScoringOptions{}),
		})
		checkPathOrder(t, []pathEntry{
			pOpts("/:w", pathScoringOptions{sensitive: true}),
			pOpts("/:w", pathScoringOptions{}),
		})
	})

	t.Run("strict should go before non strict", func(t *testing.T) {
		t.Parallel()
		checkPathOrder(t, []pathEntry{
			pOpts("/home", pathScoringOptions{strict: true}),
			p("/home"),
		})
	})

	t.Run("orders repeatable and optional", func(t *testing.T) {
		t.Parallel()
		for _, opts := range allOpts {
			checkPathOrder(t, []pathEntry{p("/:w"), pOpts("/:w?", opts)})
			checkPathOrder(t, []pathEntry{p("/:w?"), pOpts("/:w+", opts)})
			checkPathOrder(t, []pathEntry{p("/:w+"), pOpts("/:w*", opts)})
			checkPathOrder(t, []pathEntry{p("/:w+"), pOpts("/:w(.*)", opts)})
		}
	})

	t.Run("orders static before params", func(t *testing.T) {
		t.Parallel()
		for _, opts := range allOpts {
			checkPathOrder(t, []pathEntry{p("/a"), pOpts("/:id", opts)})
		}
	})

	t.Run("empty path before slash", func(t *testing.T) {
		t.Parallel()
		for _, opts := range allOpts {
			checkPathOrder(t, []pathEntry{p(""), pOpts("/", opts)})
		}
	})

	t.Run("works with long paths", func(t *testing.T) {
		t.Parallel()
		checkPathOrder(t, []pathEntry{
			p("/a/b/c/d/e"),
			p("/:k/b/c/d/e"),
			p("/:k/b/c/d/:j"),
		})
	})

	t.Run("prioritizes custom regex", func(t *testing.T) {
		t.Parallel()
		checkPathOrder(t, []pathEntry{p("/:a(\\d+)"), p("/:a"), p("/:a(.*)")})
		checkPathOrder(t, []pathEntry{p("/b-:a(\\d+)"), p("/b-:a"), p("/b-:a(.*)")})
	})

	t.Run("prioritizes ending slashes", func(t *testing.T) {
		t.Parallel()
		// No strict.
		checkPathOrder(t, []pathEntry{p("/a/"), p("/a")})
		checkPathOrder(t, []pathEntry{p("/a/b/"), p("/a/b")})

		checkPathOrder(t, []pathEntry{pOpts("/a/", pathScoringOptions{strict: true}), p("/a/")})
		checkPathOrder(t, []pathEntry{pOpts("/a", pathScoringOptions{strict: true}), p("/a")})
	})

	t.Run("puts the wildcard at the end", func(t *testing.T) {
		t.Parallel()
		for _, opts := range allOpts {
			checkPathOrder(t, []pathEntry{pOpts("", opts), p("/:rest(.*)")})
			checkPathOrder(t, []pathEntry{pOpts("/", opts), p("/:rest(.*)")})
			checkPathOrder(t, []pathEntry{pOpts("/ab", opts), p("/:rest(.*)")})
			checkPathOrder(t, []pathEntry{pOpts("/:a", opts), p("/:rest(.*)")})
			checkPathOrder(t, []pathEntry{pOpts("/:a?", opts), p("/:rest(.*)")})
			checkPathOrder(t, []pathEntry{pOpts("/:a+", opts), p("/:rest(.*)")})
			checkPathOrder(t, []pathEntry{pOpts("/:a*", opts), p("/:rest(.*)")})
			checkPathOrder(t, []pathEntry{pOpts("/:a(\\d+)", opts), p("/:rest(.*)")})
			checkPathOrder(t, []pathEntry{pOpts("/:a(\\d+)?", opts), p("/:rest(.*)")})
			checkPathOrder(t, []pathEntry{pOpts("/:a(\\d+)+", opts), p("/:rest(.*)")})
			checkPathOrder(t, []pathEntry{pOpts("/:a(\\d+)*", opts), p("/:rest(.*)")})
		}
	})

	t.Run("handles sub segments", func(t *testing.T) {
		t.Parallel()
		checkPathOrder(t, []pathEntry{
			p("/a/_2_"),
			// Something like /a/_23_.
			p("/a/_:b(\\d)other"),
			p("/a/_:b(\\d)?other"),
			// The _ is escaped but b can be also letters.
			p("/a/_:b-other"),
			p("/a/a_:b"),
		})
	})

	t.Run("handles repeatable and optional in sub segments", func(t *testing.T) {
		t.Parallel()
		checkPathOrder(t, []pathEntry{
			p("/a/_:b-other"),
			p("/a/_:b?-other"),
			p("/a/_:b+-other"),
			p("/a/_:b*-other"),
		})
		checkPathOrder(t, []pathEntry{
			p("/a/_:b(\\d)-other"),
			p("/a/_:b(\\d)?-other"),
			p("/a/_:b(\\d)+-other"),
			p("/a/_:b(\\d)*-other"),
		})
	})

	t.Run("ending slashes less than params", func(t *testing.T) {
		t.Parallel()
		checkPathOrder(t, []pathEntry{
			pOpts("/a/b", pathScoringOptions{strict: false}),
			pOpts("/a/:b", pathScoringOptions{strict: true}),
			pOpts("/a/:b/", pathScoringOptions{strict: true}),
		})
	})
}

func TestCompareScoreArrayEdgeCases(t *testing.T) {
	t.Parallel()

	const staticSegment = pathScoreStatic + pathScoreSegment // 80.

	// a is shorter, elements match up to a's length, and a[0]==staticSegment -> return -1.
	assert.Equal(t, float64(-1), compareScoreArray( //nolint:testifylint
		[]float64{staticSegment},
		[]float64{staticSegment, 40},
	))

	// b is shorter and b[0]==staticSegment -> return 1.
	assert.Equal(t, float64(1), compareScoreArray( //nolint:testifylint
		[]float64{staticSegment, 40},
		[]float64{staticSegment},
	))
}

func TestComparePathParserScoreEdgeCases(t *testing.T) {
	t.Parallel()

	// When a is longer than b (diff < 0 -> abs(diff)).
	a := [][]float64{{80}, {40}}
	b := [][]float64{{80}}
	result := comparePathParserScore(a, b)
	// a has 2 segments vs b's 1, diff=1-2=-1, abs=1, check isLastScoreNegative.
	assert.NotEqual(t, float64(0), result) // Just verify it runs.

	// isLastScoreNegative(a) true: a has a negative last score with diff==1.
	aNeg := [][]float64{{40}, {pathScoreBonusWildcard}}
	bShort := [][]float64{{40}}
	result2 := comparePathParserScore(aNeg, bShort)
	// A has negative last -> lower priority.
	assert.Equal(t, float64(1), result2) //nolint:testifylint
}

func TestScoreFromPathError(t *testing.T) {
	t.Parallel()

	// Path without a leading slash triggers tokenizePath error.
	_, errE := scoreFromPath("no-leading-slash")
	assert.EqualError(t, errE, "route path should start with a slash")
}

func TestTokenizePathErrors(t *testing.T) {
	t.Parallel()

	// Path without leading slash.
	_, errE := tokenizePath("no-slash")
	assert.EqualError(t, errE, "route path should start with a slash")
}

func TestTokenizePathEdgeCases(t *testing.T) {
	t.Parallel()

	// Param char followed by non-validParam, non-modifier: re-processes char in Static state.
	tokens, errE := tokenizePath("/:a/b")
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.NotNil(t, tokens)
}

func TestTokenizePathSpecialCases(t *testing.T) {
	t.Parallel()

	// Escape sequence in static segment (backslash before "/").
	tokens, errE := tokenizePath("/a\\/b")
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.NotNil(t, tokens)

	// Escaped ")" inside a regexp - the ")" is part of the regexp, not the closing delimiter.
	tokens, errE = tokenizePath("/:id(a\\)b)")
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.NotNil(t, tokens)

	// Unclosed regexp - "unfinished custom regexp for param".
	_, errE = tokenizePath("/:id(\\d")
	assert.EqualError(t, errE, "unfinished custom regexp for param")

	// Path ending with backslash - "invalid tokenizer state".
	_, errE = tokenizePath("/foo\\")
	assert.EqualError(t, errE, "invalid tokenizer state")

	// Repeatable param must be alone in its segment (segment already has other tokens).
	_, errE = tokenizePath("/:a-:b+")
	assert.EqualError(t, errE, "repeatable param must be alone in its segment")
}
