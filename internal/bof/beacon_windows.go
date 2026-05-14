//go:build windows

package bof

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	callbackOutput     = 0x00
	callbackOutputOEM  = 0x1e
	callbackOutputUTF8 = 0x20

	codePageACP  = 0
	codePageOEM  = 1
	codePageUTF8 = 65001

	mbErrInvalidChars = 0x00000008
)

type dataParser struct {
	original uintptr
	buffer   uintptr
	length   int32
	size     int32
}

var beaconCallbacks = map[string]uintptr{
	"BeaconDataParse":   syscall.NewCallback(beaconDataParse),
	"BeaconDataInt":     syscall.NewCallback(beaconDataInt),
	"BeaconDataShort":   syscall.NewCallback(beaconDataShort),
	"BeaconDataLength":  syscall.NewCallback(beaconDataLength),
	"BeaconDataExtract": syscall.NewCallback(beaconDataExtract),
	"BeaconOutput":      syscall.NewCallback(beaconOutput),
	"BeaconPrintf":      syscall.NewCallback(beaconPrintf),
}

var procMultiByteToWideChar = kernel32.NewProc("MultiByteToWideChar")

func resolveSymbol(symbol string, verbose bool) (uintptr, error) {
	name := strings.TrimPrefix(symbol, "__imp_")
	if addr, ok := beaconCallbacks[name]; ok {
		if verbose {
			fmt.Printf(" -> %s @ 0x%x\n", name, addr)
		}
		return addr, nil
	}

	library, function, ok := strings.Cut(name, "$")
	if !ok || library == "" || function == "" {
		return 0, fmt.Errorf("unsupported import symbol %q", symbol)
	}

	dll := syscall.NewLazyDLL(library)
	proc := dll.NewProc(function)
	if err := proc.Find(); err != nil {
		return 0, fmt.Errorf("resolve %s!%s: %w", library, function, err)
	}

	if verbose {
		fmt.Printf(" -> %s @ 0x%x\n", name, proc.Addr())
	}
	return proc.Addr(), nil
}

func beaconDataParse(parserPtr, buffer uintptr, size uint32) uintptr {
	if parserPtr == 0 {
		return 0
	}
	parser := (*dataParser)(unsafe.Pointer(parserPtr))
	parser.original = buffer
	parser.buffer = buffer
	if size < 4 {
		parser.length = 0
		parser.size = 0
		return 0
	}
	parser.length = int32(size - 4)
	parser.size = int32(size - 4)
	parser.buffer += 4
	return 0
}

func beaconDataInt(parserPtr uintptr) uintptr {
	parser := (*dataParser)(unsafe.Pointer(parserPtr))
	if parser.length < 4 {
		return 0
	}
	value := binary.LittleEndian.Uint32(unsafe.Slice((*byte)(unsafe.Pointer(parser.buffer)), 4))
	parser.buffer += 4
	parser.length -= 4
	return uintptr(value)
}

func beaconDataShort(parserPtr uintptr) uintptr {
	parser := (*dataParser)(unsafe.Pointer(parserPtr))
	if parser.length < 2 {
		return 0
	}
	value := binary.LittleEndian.Uint16(unsafe.Slice((*byte)(unsafe.Pointer(parser.buffer)), 2))
	parser.buffer += 2
	parser.length -= 2
	return uintptr(value)
}

func beaconDataLength(parserPtr uintptr) uintptr {
	parser := (*dataParser)(unsafe.Pointer(parserPtr))
	return uintptr(parser.length)
}

func beaconDataExtract(parserPtr, sizePtr uintptr) uintptr {
	parser := (*dataParser)(unsafe.Pointer(parserPtr))
	if parser.length < 4 {
		return 0
	}

	length := int32(binary.LittleEndian.Uint32(unsafe.Slice((*byte)(unsafe.Pointer(parser.buffer)), 4)))
	parser.buffer += 4
	parser.length -= 4
	if length < 0 || parser.length < length {
		return 0
	}

	out := parser.buffer
	parser.buffer += uintptr(length)
	parser.length -= length

	if sizePtr != 0 {
		*(*int32)(unsafe.Pointer(sizePtr)) = length
	}
	return out
}

func beaconOutput(outputType uintptr, data uintptr, length int32) uintptr {
	if data == 0 || length <= 0 {
		fmt.Println()
		return 0
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(data)), length)
	fmt.Println(decodeBeaconBytes(bytes.TrimRight(out, "\x00"), int(outputType)))
	return 0
}

func beaconPrintf(_ uintptr, formatPtr uintptr, a1 uintptr, a2 uintptr, a3 uintptr, a4 uintptr, a5 uintptr, a6 uintptr, a7 uintptr, a8 uintptr) uintptr {
	if formatPtr == 0 {
		return 0
	}

	format := decodeCString(formatPtr, callbackOutput)
	args := []uintptr{a1, a2, a3, a4, a5, a6, a7, a8}
	fmt.Print(formatBeaconString(format, args))
	return 0
}

func cBytes(ptr uintptr) []byte {
	var data []byte
	for p := ptr; ; p++ {
		b := *(*byte)(unsafe.Pointer(p))
		if b == 0 {
			return data
		}
		data = append(data, b)
	}
}

func decodeCString(ptr uintptr, outputType int) string {
	if ptr == 0 {
		return ""
	}
	return decodeBeaconBytes(cBytes(ptr), outputType)
}

func decodeBeaconBytes(data []byte, outputType int) string {
	switch outputType {
	case callbackOutputUTF8:
		return string(data)
	case callbackOutputOEM:
		return decodeWindowsCodePage(data, codePageOEM)
	case callbackOutput:
		return decodeWindowsCodePage(data, codePageACP)
	default:
		return decodeWindowsCodePage(data, codePageACP)
	}
}

func decodeWindowsCodePage(data []byte, codePage uint32) string {
	if len(data) == 0 {
		return ""
	}

	flags := uint32(0)
	if codePage == codePageUTF8 {
		flags = mbErrInvalidChars
	}

	chars, _, _ := procMultiByteToWideChar.Call(
		uintptr(codePage),
		uintptr(flags),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0,
		0,
	)
	if chars == 0 {
		return string(data)
	}

	wide := make([]uint16, chars)
	written, _, _ := procMultiByteToWideChar.Call(
		uintptr(codePage),
		uintptr(flags),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&wide[0])),
		uintptr(len(wide)),
	)
	if written == 0 {
		return string(data)
	}

	return string(utf16.Decode(wide[:written]))
}

func formatBeaconString(format string, rawArgs []uintptr) string {
	var b strings.Builder
	argIndex := 0

	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 == len(format) {
			b.WriteByte(format[i])
			continue
		}
		i++
		if format[i] == '%' {
			b.WriteByte('%')
			continue
		}

		for i < len(format) && strings.ContainsRune("-+ #0", rune(format[i])) {
			i++
		}
		for i < len(format) && format[i] >= '0' && format[i] <= '9' {
			i++
		}
		if i < len(format) && format[i] == '.' {
			i++
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
		}
		for i < len(format) && strings.ContainsRune("hljztL", rune(format[i])) {
			i++
		}
		if i >= len(format) {
			break
		}

		verb := format[i]
		var arg uintptr
		if argIndex < len(rawArgs) {
			arg = rawArgs[argIndex]
			argIndex++
		}

		switch verb {
		case 's':
			if arg == 0 {
				b.WriteString("(null)")
			} else {
				b.WriteString(decodeCString(arg, callbackOutput))
			}
		case 'c':
			b.WriteByte(byte(arg))
		case 'd', 'i':
			b.WriteString(fmt.Sprintf("%d", int64(arg)))
		case 'u':
			b.WriteString(fmt.Sprintf("%d", uint64(arg)))
		case 'x':
			b.WriteString(fmt.Sprintf("%x", uint64(arg)))
		case 'X':
			b.WriteString(fmt.Sprintf("%X", uint64(arg)))
		case 'p':
			b.WriteString(fmt.Sprintf("0x%x", arg))
		default:
			b.WriteByte('%')
			b.WriteByte(verb)
		}
	}

	return b.String()
}
