package gopass

import (
	"strings"
	"testing"
)

func TestNewRandomPassword(t *testing.T) {
	tt := []struct {
		name           string
		length         int
		testIterations int
		opts           []PassOpt
		repeats        bool
		excludedChar   string
	}{
		{name: "16 characters no repeats", length: 16, testIterations: 2000, opts: []PassOpt{IncludeSpecial(), IncludeLowercase(), IncludeUppercase()}, repeats: false},
		{name: "32 characters no repeats", length: 32, testIterations: 2000, opts: []PassOpt{IncludeSpecial(), IncludeLowercase(), IncludeUppercase()}, repeats: false},
		{name: "16 characters with repeats", length: 16, testIterations: 2000, opts: []PassOpt{IncludeSpecial(), IncludeLowercase(), IncludeUppercase()}, repeats: true},
		{name: "32 characters with repeats", length: 32, testIterations: 2000, opts: []PassOpt{IncludeSpecial(), IncludeLowercase(), IncludeUppercase()}, repeats: true},
		{name: "16 characters with excluded $", length: 32, testIterations: 2000, opts: []PassOpt{IncludeSpecial(), IncludeLowercase(), IncludeUppercase()}, repeats: true, excludedChar: "$"},
	}

	for _, v := range tt {
		t.Run(v.name, func(t *testing.T) {
			for i := 0; i < v.testIterations; i++ {
				if !v.repeats {
					v.opts = append(v.opts, NoRepeatingCharacters())
				}
				if v.excludedChar != "" {
					v.opts = append(v.opts, CustomVerifier(func(s string) bool { return !strings.Contains(s, v.excludedChar) }))
				}

				pass, err := NewRandomPassword(v.length, v.opts...)
				if err != nil {
					t.Errorf("error: %v", err)
				}

				for i, k := range pass {
					if !v.repeats {
						if i > 0 && string(k) == string(pass[i-1]) {
							t.Errorf("password %v has repeating characters %v and %v", pass, string(k), string(pass[i-1]))
						}
					}

					if v.excludedChar != "" {
						if strings.Contains(pass, v.excludedChar) {
							t.Errorf("password is required to exclude %s but doesn't", v.excludedChar)
						}
					}
				}
			}
		})
	}
}
