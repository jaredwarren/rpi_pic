package form

import (
	"math/rand"
	"time"
)

var forms map[string]*Form

func init() {
	forms = make(map[string]*Form)
}

// Form ...
type Form struct {
	Hash string
	Date time.Time
}

// GetForm return stored form
func GetForm(key string) (f *Form, ok bool) {
	f, ok = forms[key]
	delete(forms, key)

	// form timout, 1 day max
	if f != nil {
		max := time.Now().AddDate(0, 0, -1)
		if max.Sub(f.Date).Seconds() > 0 {
			return nil, false
		}
	}

	return
}

// Check return stored form
func Check(key string) (f *Form, ok bool) {
	f, ok = forms[key]
	return
}

// New return new form
func New() string {
	hash := GetHash(32)
	forms[hash] = &Form{
		Hash: hash,
		Date: time.Now(),
	}
	return hash
}

const letterBytes = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
)

// GetHash ...
func GetHash(n int) string {
	b := make([]byte, n)
	for i := 0; i < n; {
		if idx := int(rand.Int63() & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i++
		}
	}
	return string(b)
}
