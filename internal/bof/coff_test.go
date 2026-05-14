package bof

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseIncludedX64Object(t *testing.T) {
	path := filepath.Join("..", "..", "..", "c-object-file-loading", "ObjectLdr", "ObjectLdr", "tests", "whoami.x64.o")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	obj, err := parseObject(data)
	if err != nil {
		t.Fatalf("parseObject() error = %v", err)
	}

	if obj.header.Machine != imageFileMachineAMD64 {
		t.Fatalf("Machine = 0x%x, want 0x%x", obj.header.Machine, imageFileMachineAMD64)
	}
	if len(obj.sections) == 0 {
		t.Fatal("expected at least one section")
	}
	if len(obj.symbols) == 0 {
		t.Fatal("expected at least one symbol")
	}
	if !hasSymbol(obj, "go") {
		t.Fatal("expected entry symbol go")
	}
}

func hasSymbol(obj *objectFile, name string) bool {
	for _, sym := range obj.symbols {
		if sym.Name == name {
			return true
		}
	}
	return false
}
