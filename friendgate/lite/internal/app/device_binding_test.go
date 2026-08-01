package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDeviceInvitationBindsKeyWithoutPublicIP(t *testing.T) {
	_, store := testApp(t)
	accountID := createTestAccount(t, store, "device-binding-account", "access-device", "acct-device")
	token := "device-invitation-token-long-enough"
	if _, err := store.CreateInvitationWithBinding(context.Background(), "device", token, "123456", accountID, 0, time.Now().Add(time.Hour).Unix(), "device"); err != nil {
		t.Fatal(err)
	}
	claim := "device-claim-token-long-enough"
	if _, err := store.VerifyInvitation(context.Background(), token, "123456", "198.51.100.20", claim, "device-probe-token-long-enough"); err != nil {
		t.Fatal(err)
	}
	deviceToken := "opaque-device-secret-long-enough"
	if err := store.SaveInviteDeviceWithCredential(context.Background(), token, claim, "198.51.100.20", "laptop", deviceToken); err != nil {
		t.Fatal(err)
	}
	key, _, err := store.GenerateInvitedKey(context.Background(), token, claim, "198.51.100.20", "sk-fg_device-flow", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthorizeKey(context.Background(), "sk-fg_device-flow", "203.0.113.2"); !errors.Is(err, ErrDeviceNotAllowed) {
		t.Fatalf("missing device credential error=%v", err)
	}
	if _, err := store.AuthorizeKeyWithDevice(context.Background(), "sk-fg_device-flow", "203.0.113.2", deviceToken); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeQuotaAuthorizedWithDevice(context.Background(), key.ID, "203.0.113.2", deviceToken); err != nil {
		t.Fatal(err)
	}
	// The one-time reveal endpoint must also work for device-only invitations
	// after a browser refresh, even though no IP row was copied to the key.
	if revealed, _, err := store.RevealInvitedKey(context.Background(), token, claim, "203.0.113.2"); err != nil || revealed != "sk-fg_device-flow" {
		t.Fatalf("device-only reveal failed: key=%q err=%v", revealed, err)
	}
}
