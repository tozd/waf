package waf

// pathranking.go implements Vue Router's path ranking algorithm.
// It is a direct port of:
//   - vue-router/packages/router/src/matcher/pathTokenizer.ts
//   - vue-router/packages/router/src/matcher/pathParserRanker.ts

import (
	"regexp"

	"gitlab.com/tozd/go/errors"
)

// pathTokenType mirrors Vue Router's TokenType enum (pathTokenizer.ts).
type pathTokenType int

const (
	pathTokenTypeStatic pathTokenType = iota // TokenType.Static = 0.
	pathTokenTypeParam                       // TokenType.Param  = 1.
)

// pathToken mirrors Vue Router's Token type (pathTokenizer.ts).
type pathToken struct {
	typ        pathTokenType
	value      string
	regexp     string // Custom regexp for param; empty means default [^/]+?.
	optional   bool
	repeatable bool
}

// pathScoringOptions mirrors Vue Router's _PathParserOptions (pathParserRanker.ts).
type pathScoringOptions struct {
	sensitive bool // Case-sensitive matching; default false.
	strict    bool // Disallow trailing slash; default false.
}

// Score constants mirror Vue Router's PathScore enum (pathParserRanker.ts).
const (
	pathScoreMultiplier        float64 = 10
	pathScoreRoot              float64 = 9 * pathScoreMultiplier // 90: just /.
	pathScoreSegment           float64 = 4 * pathScoreMultiplier // 40: /a-segment.
	pathScoreSubSegment        float64 = 3 * pathScoreMultiplier // 30: /multiple-:things-in-one-:segment.
	pathScoreStatic            float64 = 4 * pathScoreMultiplier // 40: /static.
	pathScoreDynamic           float64 = 2 * pathScoreMultiplier // 20: /:someId.
	pathScoreBonusCustomRegexp float64 = 1 * pathScoreMultiplier // 10: /:someId(\d+).
	// /:namedWildcard(.*) - we subtract the bonus added by the custom regexp.
	pathScoreBonusWildcard   float64 = -4*pathScoreMultiplier - pathScoreBonusCustomRegexp // -50.
	pathScoreBonusRepeatable float64 = -2 * pathScoreMultiplier                            // -20: /:w+ or /:w*.
	pathScoreBonusOptional   float64 = -0.8 * pathScoreMultiplier                          // -8: /:w? or /:w*.
	// These two must be under 0.1 so a strict /:page is still lower than /:a-:b.
	pathScoreBonusStrict        float64 = 0.07 * pathScoreMultiplier  // Applied when option strict: true is passed (value: 0.7).
	pathScoreBonusCaseSensitive float64 = 0.025 * pathScoreMultiplier // Applied when option sensitive: true is passed (value: 0.25).
)

// pathBaseParamPattern mirrors Vue Router's BASE_PARAM_PATTERN.
const pathBaseParamPattern = "[^/]+?"

// validParamRE mirrors Vue Router's VALID_PARAM_RE = /[a-zA-Z0-9_]/.
var validParamRE = regexp.MustCompile(`[a-zA-Z0-9_]`)

// pathTokenizerState mirrors Vue Router's TokenizerState enum (pathTokenizer.ts).
type pathTokenizerState int

const (
	pathTokenizerStateStatic pathTokenizerState = iota
	pathTokenizerStateParam
	pathTokenizerStateParamRegExp
	pathTokenizerStateParamRegExpEnd
	pathTokenizerStateEscapeNext
)

// tokenizePath converts a path string into an array of segments, each segment
// being an array of tokens. It is a port of tokenizePath from pathTokenizer.ts.
func tokenizePath(path string) ([][]pathToken, errors.E) {
	if path == "" {
		return [][]pathToken{{}}, nil
	}
	if path == "/" {
		// ROOT_TOKEN: static token with empty value.
		return [][]pathToken{{{typ: pathTokenTypeStatic, value: "", regexp: "", optional: false, repeatable: false}}}, nil
	}
	if path[0] != '/' {
		errE := errors.New("route path should start with a slash")
		errors.Details(errE)["path"] = path
		return nil, errE
	}

	state := pathTokenizerStateStatic
	var previousState pathTokenizerState
	var tokens [][]pathToken
	var segment []pathToken
	var buffer string
	var customRe string
	var char byte
	var tokenizeErrE errors.E

	finalizeSegment := func() {
		if segment != nil {
			tokens = append(tokens, segment)
		}
		segment = []pathToken{}
	}

	consumeBuffer := func() {
		if buffer == "" {
			return
		}
		switch state {
		case pathTokenizerStateStatic:
			segment = append(segment, pathToken{
				typ:        pathTokenTypeStatic,
				value:      buffer,
				regexp:     "",
				optional:   false,
				repeatable: false,
			})
		case pathTokenizerStateParam, pathTokenizerStateParamRegExp, pathTokenizerStateParamRegExpEnd:
			if len(segment) > 1 && (char == '*' || char == '+') {
				tokenizeErrE = errors.New("repeatable param must be alone in its segment")
				errors.Details(tokenizeErrE)["buffer"] = buffer
				buffer = ""
				return
			}
			segment = append(segment, pathToken{
				typ:        pathTokenTypeParam,
				value:      buffer,
				regexp:     customRe,
				repeatable: char == '*' || char == '+',
				optional:   char == '*' || char == '?',
			})
		case pathTokenizerStateEscapeNext:
			fallthrough
		default:
			tokenizeErrE = errors.New("invalid tokenizer state")
			errors.Details(tokenizeErrE)["state"] = int(state)
			errors.Details(tokenizeErrE)["buffer"] = buffer
			buffer = ""
			return
		}
		buffer = ""
	}

	for i := 0; i < len(path); {
		char = path[i]
		i++

		if char == '\\' && state != pathTokenizerStateParamRegExp {
			previousState = state
			state = pathTokenizerStateEscapeNext
			continue
		}

		switch state {
		case pathTokenizerStateStatic:
			switch char {
			case '/':
				if buffer != "" {
					consumeBuffer()
					if tokenizeErrE != nil {
						return nil, tokenizeErrE
					}
				}
				finalizeSegment()
			case ':':
				consumeBuffer()
				if tokenizeErrE != nil {
					return nil, tokenizeErrE
				}
				state = pathTokenizerStateParam
			default:
				buffer += string(char)
			}

		case pathTokenizerStateEscapeNext:
			buffer += string(char)
			state = previousState

		case pathTokenizerStateParam:
			if char == '(' {
				state = pathTokenizerStateParamRegExp
			} else if validParamRE.MatchString(string(char)) {
				buffer += string(char)
			} else {
				consumeBuffer()
				if tokenizeErrE != nil {
					return nil, tokenizeErrE
				}
				state = pathTokenizerStateStatic
				if char != '*' && char != '?' && char != '+' {
					// Go back one character to re-process in Static state.
					i--
				}
			}

		case pathTokenizerStateParamRegExp:
			if char == ')' {
				if len(customRe) > 0 && customRe[len(customRe)-1] == '\\' {
					customRe = customRe[:len(customRe)-1] + string(char)
				} else {
					state = pathTokenizerStateParamRegExpEnd
				}
			} else {
				customRe += string(char)
			}

		case pathTokenizerStateParamRegExpEnd:
			consumeBuffer()
			if tokenizeErrE != nil {
				return nil, tokenizeErrE
			}
			state = pathTokenizerStateStatic
			if char != '*' && char != '?' && char != '+' {
				// Go back one character.
				i--
			}
			customRe = ""
		}
	}

	if state == pathTokenizerStateParamRegExp {
		errE := errors.New("unfinished custom regexp for param")
		errors.Details(errE)["buffer"] = buffer
		return nil, errE
	}

	consumeBuffer()
	if tokenizeErrE != nil {
		return nil, tokenizeErrE
	}
	finalizeSegment()

	return tokens, nil
}

// computePathScore computes the path score for tokenized segments.
// It is a port of the score-computation part of tokensToParser from pathParserRanker.ts.
func computePathScore(segments [][]pathToken, opts pathScoringOptions) [][]float64 {
	score := make([][]float64, 0, len(segments))
	for _, segment := range segments {
		var segmentScores []float64
		if len(segment) == 0 {
			segmentScores = []float64{pathScoreRoot}
		} else {
			segmentScores = make([]float64, 0, len(segment))
		}

		for _, token := range segment {
			subSegmentScore := pathScoreSegment
			if opts.sensitive {
				subSegmentScore += pathScoreBonusCaseSensitive
			}
			switch token.typ {
			case pathTokenTypeStatic:
				subSegmentScore += pathScoreStatic
			case pathTokenTypeParam:
				re := token.regexp
				if re == "" {
					re = pathBaseParamPattern
				}
				if re != pathBaseParamPattern {
					subSegmentScore += pathScoreBonusCustomRegexp
				}
				subSegmentScore += pathScoreDynamic
				if token.optional {
					subSegmentScore += pathScoreBonusOptional
				}
				if token.repeatable {
					subSegmentScore += pathScoreBonusRepeatable
				}
				if re == ".*" {
					subSegmentScore += pathScoreBonusWildcard
				}
			}
			segmentScores = append(segmentScores, subSegmentScore)
		}

		score = append(score, segmentScores)
	}

	// Apply strict bonus to the last score entry.
	if opts.strict && len(score) > 0 {
		last := score[len(score)-1]
		if len(last) > 0 {
			score[len(score)-1][len(last)-1] += pathScoreBonusStrict
		}
	}

	return score
}

// compareScoreArray compares two sub-segment score arrays.
// Returns < 0 if a should be sorted first (higher priority),
// > 0 if b should be sorted first, 0 if equal.
// It is a port of compareScoreArray from pathParserRanker.ts.
func compareScoreArray(a, b []float64) float64 {
	i := 0
	for i < len(a) && i < len(b) {
		diff := b[i] - a[i]
		if diff != 0 {
			return diff
		}
		i++
	}

	const staticSegment = pathScoreStatic + pathScoreSegment // 80.
	if len(a) < len(b) {
		if len(a) == 1 && a[0] == staticSegment {
			return -1
		}
		return 1
	} else if len(a) > len(b) {
		if len(b) == 1 && b[0] == staticSegment {
			return 1
		}
		return -1
	}

	return 0
}

// comparePathParserScore compares two path scores.
// Returns < 0 if a should be sorted first (higher priority),
// > 0 if b should be sorted first, 0 if equal.
// It is a port of comparePathParserScore from pathParserRanker.ts.
func comparePathParserScore(a, b [][]float64) float64 {
	i := 0
	for i < len(a) && i < len(b) {
		comp := compareScoreArray(a[i], b[i])
		if comp != 0 {
			return comp
		}
		i++
	}

	diff := len(b) - len(a)
	if diff < 0 {
		diff = -diff
	}
	if diff == 1 {
		if isLastScoreNegative(a) {
			return 1
		}
		if isLastScoreNegative(b) {
			return -1
		}
	}

	return float64(len(b) - len(a))
}

// isLastScoreNegative reports whether the last score entry is negative.
// This is used to detect splat params at the end of a path: /home/:id(.*)*.
// It is a port of isLastScoreNegative from pathParserRanker.ts.
func isLastScoreNegative(score [][]float64) bool {
	if len(score) == 0 {
		return false
	}
	last := score[len(score)-1]
	return len(last) > 0 && last[len(last)-1] < 0
}

// scoreFromPath computes the Vue Router path score for a path string
// using default options (no strict, no sensitive).
func scoreFromPath(path string) ([][]float64, errors.E) {
	tokens, errE := tokenizePath(path)
	if errE != nil {
		return nil, errE
	}
	return computePathScore(tokens, pathScoringOptions{}), nil
}
