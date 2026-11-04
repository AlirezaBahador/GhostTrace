package main

import "testing"

func TestValidateAuth(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
		allow bool
		ok    bool
	}{
		{"empty-default-refused", "", false, false},
		{"explicit-local-dev", "", true, true},
		{"valid-token", "0123456789abcdef", false, true},
		{"too-short", "1234567", false, false},
		{"too-short-with-dev-flag", "1234567", true, false},
		{"too-long", string(make([]byte, 4097)), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAuth(tc.token, tc.allow)
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
