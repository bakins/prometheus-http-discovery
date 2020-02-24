package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscover(t *testing.T) {
	testDir, err := ioutil.TempDir("", t.Name())
	require.NoError(t, err)

	defer os.RemoveAll(testDir)

	testBody := `[ { "targets": [ "one:8080", "two:9090" ] } ]`

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(testBody))
	})

	svr := httptest.NewServer(handler)
	defer svr.Close()

	testOutputFile := filepath.Join(testDir, "out.json")

	testConfig := fmt.Sprintf(`---
discover_configs:
  - url: %s
    file: %s
`, svr.URL, testOutputFile)

	filename := filepath.Join(testDir, "discover.yaml")
	err = ioutil.WriteFile(filename, []byte(testConfig), 0644)
	require.NoError(t, err)

	d, err := newFromFile(filename, nil)
	require.NoError(t, err)

	require.Len(t, d.targets, 1)

	tgs, err := d.targets[0].refresh(context.Background())
	require.NoError(t, err)

	require.Len(t, tgs, 1)
	require.Len(t, tgs[0].Targets, 2)
}
