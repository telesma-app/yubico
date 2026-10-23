package ctaphid

import (
	"os"
	"testing"
)

func TestHardware(t *testing.T) {
	path := os.Getenv("YUBICO_CTAPHID_TEST_PATH")
	if path == "" {
		t.Skip("set YUBICO_CTAPHID_TEST_PATH to run the CTAPHID hardware test")
	}

	device, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Cleanup(func() {
		if err := device.Close(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	info, err := device.DeviceInfo(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Logf("reported information: %+v", info)
	t.Logf("firmware: %s", info.FirmwareVersion)
}
