package waf

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"gitlab.com/tozd/go/errors"
)

func TestParsePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		inputPath      string
		expectedResult []pathSegment
		expectedError  error
	}{
		{
			inputPath: "/users/:id/posts",
			expectedResult: []pathSegment{
				{Value: "users", Parameter: false},
				{Value: "id", Parameter: true},
				{Value: "posts", Parameter: false},
			},
			expectedError: nil,
		},
		{
			inputPath: "/profile",
			expectedResult: []pathSegment{
				{Value: "profile", Parameter: false},
			},
			expectedError: nil,
		},
		{
			inputPath:      "users/posts",
			expectedResult: nil,
			expectedError:  errors.New(`path does not start with "/"`),
		},
		{
			inputPath:      "/users//posts",
			expectedResult: nil,
			expectedError:  errors.New("path has an empty part"),
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.inputPath, func(t *testing.T) {
			t.Parallel()

			segments, err := parsePath(tt.inputPath)
			assert.Equal(t, tt.expectedResult, segments)
			if tt.expectedError != nil {
				if assert.Error(t, err) {
					assert.Equal(t, tt.expectedError.Error(), err.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCompileRegexp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		inputSegments  []pathSegment
		expectedRegexp string
		inputMatch     []string
		expectedParams Params
		expectedError  error
	}{
		{
			inputSegments: []pathSegment{
				{Value: "users", Parameter: false},
				{Value: "id", Parameter: true},
				{Value: "posts", Parameter: false},
			},
			expectedRegexp: `^/users/([^/]+)/posts$`,
			inputMatch:     []string{"", "123"},
			expectedParams: Params{
				"id": "123",
			},
			expectedError: nil,
		},
		{
			inputSegments: []pathSegment{
				{Value: "profile", Parameter: false},
			},
			expectedRegexp: `^/profile$`,
			inputMatch:     []string{""},
			expectedParams: Params{},
			expectedError:  nil,
		},
	}

	for k, tt := range tests {
		tt := tt

		t.Run(fmt.Sprintf("case=#%d", k), func(t *testing.T) {
			t.Parallel()

			re, paramMapFunc, err := compileRegexp(tt.inputSegments)

			if tt.expectedError != nil {
				assert.Nil(t, re)
				assert.Nil(t, paramMapFunc)
				if assert.Error(t, err) {
					assert.Equal(t, tt.expectedError.Error(), err.Error())
				}
			} else {
				assert.NoError(t, err)
				if assert.NotNil(t, re) {
					assert.Equal(t, tt.expectedRegexp, re.String())
				}
				if assert.NotNil(t, paramMapFunc) {
					params := paramMapFunc(tt.inputMatch)
					assert.Equal(t, tt.expectedParams, params)
				}
			}
		})
	}
}
