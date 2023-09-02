package gopass

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"math/rand"
)

var (
	ErrIterationsExhausted = fmt.Errorf("password iterations exhausted")
)

type PassChars string

const (
	Numbers PassChars = "0123456789"
	Lower   PassChars = "abcdefghijklmnopqrstuvwxyz"
	Upper   PassChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Special PassChars = "!@#$%^&*()`=+-_"
)

// PassOpt sets options in the PassOptions struct
type PassOpt func(s *PassOptions)

// VerifyFunc takes a string and returns a bool.
type VerifyFunc func(string) bool

// PassOptions holds the options for password generation
type PassOptions struct {
	Chars       []PassChars
	Length      int
	Iterations  int
	VerifyFuncs []VerifyFunc
}

// NewRandomPassword returns a new random password from the PassOptions.
// If VerifyFuncs are added, it will loop and retry password generation
// until a string meeting those VerifyFuncs is created or the correctness
// iterations are met. This ensures rules and correctness are met instead of speed.
func NewRandomPassword(length int, secretOpts ...PassOpt) (string, error) {
	var opts PassOptions
	opts.Length = length
	opts.Iterations = 50

	for _, v := range secretOpts {
		v(&opts)
	}

outer:
	for i := 0; i < opts.Iterations; i++ {
		pass, err := newPassword(opts)
		if err != nil {
			return "", err
		}

		if opts.VerifyFuncs != nil {
			for _, v := range opts.VerifyFuncs {
				ok := v(pass)
				if !ok {
					continue outer
				}
			}
		}

		return pass, nil
	}

	return "", ErrIterationsExhausted

}

// newPassword generates a random password. It takes a random character from each PassChars group
// and shuffles the characters into a string from those characters. It loops through until the
// desired length is met. This ensures the password contains every type of character required.
// It finally runs a shuffle on the last string to ensure randomnes.
func newPassword(s PassOptions) (string, error) {
	var b []byte

outer:
	for i := 0; i < s.Length; i++ {
		var vals []byte
		for k := 0; k < len(s.Chars); k++ {
			chars := s.Chars[k]
			a, err := crand.Int(crand.Reader, big.NewInt(int64(len(chars))))
			if err != nil {
				return "", err
			}

			//a := rand.Intn(len(chars))

			rand.Shuffle(len(chars), func(i, j int) {
				[]byte(chars)[i], []byte(chars)[j] = chars[j], chars[i]
			})

			vals = append(vals, chars[a.Int64()])
		}

		for _, v := range vals {
			if len(b) == s.Length {
				break outer
			}
			b = append(b, v)
		}
	}

	rand.Shuffle(len(b), func(i, j int) {
		b[i], b[j] = b[j], b[i]
	})

	return string(b), nil
}

// norepeats is a Verifier function that returns false
// if the password has two consecutive characters
func noRepeats(pass string) bool {
	for i := range pass {
		if i > 0 {
			if pass[i] == pass[i-1] {
				return false
			}
		}
	}

	return true
}

// IncludeUppercase includes uppercase characters
func IncludeUppercase() PassOpt {
	return func(s *PassOptions) {
		s.Chars = append(s.Chars, Upper)
	}
}

// IncludeLowercase includes lowercase characters
func IncludeLowercase() PassOpt {
	return func(s *PassOptions) {
		s.Chars = append(s.Chars, Lower)
	}
}

// IncludeNumbers includes numbers
func IncludeNumbers() PassOpt {
	return func(s *PassOptions) {
		s.Chars = append(s.Chars, Numbers)
	}
}

// IncludeSpecial includes special characters
func IncludeSpecial() PassOpt {
	return func(s *PassOptions) {
		s.Chars = append(s.Chars, Special)
	}
}

// IncludeCustom includes custom characters for example
// if you need a limited set of special characters
func IncludeCustom(p PassChars) PassOpt {
	return func(s *PassOptions) {
		s.Chars = append(s.Chars, p)
	}
}

// NoRepeatingCharacters ensures no characters are repeating
func NoRepeatingCharacters() PassOpt {
	return func(s *PassOptions) {
		s.VerifyFuncs = append(s.VerifyFuncs, noRepeats)
	}
}

// CustomVerifier adds a CustomVerifier function
func CustomVerifier(v VerifyFunc) PassOpt {
	return func(s *PassOptions) {
		s.VerifyFuncs = append(s.VerifyFuncs, v)
	}
}

// CorrectnessIterations is the number of iterations if the password
// fails the Verifier functions
func CorrectnessIterations(i int) PassOpt {
	return func(s *PassOptions) {
		s.Iterations = i
	}
}
