package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAccessKeyOwnedWipedOnSuccessAndFailure(t *testing.T) {
	guestOrSkip(t)
	ctx := context.Background()
	profile, err := OpenWithoutProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	for _, crn := range []string{"invalid", testCRN} {
		t.Run(crn, func(t *testing.T) {
			material := []byte("CSAKtestKeyId.testKeySecret")
			key := NewAccessKey(material)
			for _, verb := range []string{"%v", "%+v", "%#v", "%x", "%s", "%d"} {
				if fmt.Sprintf(verb, key) != "AccessKey(***)" || fmt.Sprintf(verb, *key) != "AccessKey(***)" {
					t.Fatal("key did not redact")
				}
			}
			strategy, err := profile.AccessKey(ctx, crn, key)
			if strategy != nil {
				defer strategy.Close()
			}
			if crn == "invalid" {
				if !errors.Is(err, ErrConfig) || strategy != nil {
					t.Fatalf("invalid CRN: strategy %v, error %v", strategy, err)
				}
			} else if err != nil || strategy == nil {
				t.Fatalf("valid CRN: strategy %v, error %v", strategy, err)
			}
			if !key.IsZero() || strings.Trim(string(material), "\x00") != "" {
				t.Fatal("AccessKey did not consume owned bytes")
			}
			key.Wipe()
		})
	}
}
