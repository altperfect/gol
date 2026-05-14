package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadObjectFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.o")
	want := []byte("object")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, source, err := loadObject(path, "", false)
	if err != nil {
		t.Fatalf("loadObject() error = %v", err)
	}
	if source != path {
		t.Fatalf("source = %q, want %q", source, path)
	}
	if string(got) != string(want) {
		t.Fatalf("object = %q, want %q", got, want)
	}
}

func TestFetchObjectHTTP(t *testing.T) {
	want := []byte("object")
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "http://stager/some-bof.o" {
			t.Fatalf("url = %q", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(bytes.NewReader(want)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	got, err := fetchObjectWithClient("http://stager/some-bof.o", client)
	if err != nil {
		t.Fatalf("fetchObject() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("object = %q, want %q", got, want)
	}
}

func TestHTTPSInsecureSkipVerifyConfig(t *testing.T) {
	client := newHTTPClient("https", true)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLSClientConfig.InsecureSkipVerify is not enabled")
	}

	client = newHTTPClient("https", false)
	if transport, ok := client.Transport.(*http.Transport); ok {
		if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify enabled without flag")
		}
	}
}

func TestLoadObjectRejectsFileAndURL(t *testing.T) {
	if _, _, err := loadObject("test.o", "http://example.test/test.o", false); err == nil {
		t.Fatal("loadObject() succeeded with both file and url, want error")
	}
}

func TestPackBOFArgs(t *testing.T) {
	got, err := packBOFArgs("zsiZb", []string{"host", "-2", "42", "Ж", "AQID"})
	if err != nil {
		t.Fatalf("packBOFArgs() error = %v", err)
	}

	var payload []byte
	payload = appendLengthPrefixed(payload, []byte("host\x00"))
	payload = binary.LittleEndian.AppendUint16(payload, uint16(0xfffe))
	payload = binary.LittleEndian.AppendUint32(payload, 42)
	payload = appendLengthPrefixed(payload, []byte{0x16, 0x04, 0x00, 0x00})
	payload = appendLengthPrefixed(payload, []byte{1, 2, 3})

	want := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)))
	want = append(want, payload...)

	if !bytes.Equal(got, want) {
		t.Fatalf("packed args = %x, want %x", got, want)
	}
}

func TestPackCLIArgsAutoPacksStringsAndInts(t *testing.T) {
	got, err := packCLIArgs([]string{"host", "443", "-1"}, "", nil)
	if err != nil {
		t.Fatalf("packCLIArgs() error = %v", err)
	}

	var payload []byte
	payload = appendLengthPrefixed(payload, []byte("host\x00"))
	payload = binary.LittleEndian.AppendUint32(payload, 443)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(0xffffffff))

	want := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)))
	want = append(want, payload...)

	if !bytes.Equal(got, want) {
		t.Fatalf("packed args = %x, want %x", got, want)
	}
}

func TestPackCLIArgsTreatsNonDecimalNumbersAsStrings(t *testing.T) {
	got, err := packCLIArgs([]string{"0x10"}, "", nil)
	if err != nil {
		t.Fatalf("packCLIArgs() error = %v", err)
	}

	var payload []byte
	payload = appendLengthPrefixed(payload, []byte("0x10\x00"))
	want := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)))
	want = append(want, payload...)

	if !bytes.Equal(got, want) {
		t.Fatalf("packed args = %x, want %x", got, want)
	}
}

func TestPackCLIArgsRejectsMixedSimpleAndTypedArgs(t *testing.T) {
	if _, err := packCLIArgs([]string{"host"}, "i", []string{"42"}); err == nil {
		t.Fatal("packCLIArgs() succeeded with mixed simple and typed args, want error")
	}
}

func TestPackBOFArgsValidatesFormatAndValues(t *testing.T) {
	tests := []struct {
		name   string
		format string
		values []string
	}{
		{name: "arg without format", values: []string{"value"}},
		{name: "count mismatch", format: "zi", values: []string{"value"}},
		{name: "bad int", format: "i", values: []string{"not-int"}},
		{name: "bad binary", format: "b", values: []string{"not-base64"}},
		{name: "unknown spec", format: "q", values: []string{"value"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := packBOFArgs(tt.format, tt.values); err == nil {
				t.Fatal("packBOFArgs() succeeded, want error")
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
