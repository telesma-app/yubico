package ctaphid

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHardware(t *testing.T) {
	path := os.Getenv("YUBICO_CTAPHID_TEST_PATH")
	if path == "" {
		t.Skip("set YUBICO_CTAPHID_TEST_PATH to run the CTAPHID hardware test")
	}

	device, err := Open(t.Context(), path)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, device.Close())
	})

	info, err := device.DeviceInfo(t.Context())
	require.NoError(t, err)
	t.Logf("model: %s", info.ModelName(""))
	t.Logf("firmware: %s", info.FirmwareVersion)
}
