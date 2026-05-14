//go:build windows

package bof

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const (
	pageSize = 0x1000

	memCommit  = 0x00001000
	memReserve = 0x00002000
	memRelease = 0x00008000

	pageReadWrite   = 0x04
	pageExecuteRead = 0x20
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procVirtualAlloc   = kernel32.NewProc("VirtualAlloc")
	procVirtualFree    = kernel32.NewProc("VirtualFree")
	procVirtualProtect = kernel32.NewProc("VirtualProtect")
)

type sectionMap struct {
	base uintptr
	size uint32
}

type executionContext struct {
	obj        *objectFile
	sections   []sectionMap
	symbolMap  []uintptr
	symbolBase uintptr
	memory     uintptr
	size       uintptr
	verbose    bool
}

type Options struct {
	Verbose bool
}

func Execute(object []byte, entry string, args []byte) error {
	return ExecuteWithOptions(object, entry, args, Options{})
}

func ExecuteWithOptions(object []byte, entry string, args []byte, options Options) error {
	obj, err := parseObject(object)
	if err != nil {
		return err
	}

	ctx := &executionContext{obj: obj, verbose: options.Verbose}
	if err := ctx.allocateAndMap(); err != nil {
		return err
	}
	defer ctx.free()

	ctx.printf("[*] Virtual Size [%d bytes]\n", ctx.size)
	ctx.printf("[*] Allocated object file @ 0x%x [%d bytes]\n", ctx.memory, ctx.size)

	for i, section := range obj.sections {
		dst := unsafe.Slice((*byte)(unsafe.Pointer(ctx.sections[i].base)), section.SizeOfRawData)
		src := object[section.PointerToRawData : section.PointerToRawData+section.SizeOfRawData]
		copy(dst, src)
		ctx.printf(" -> %-8s @ 0x%x [%d bytes]\n", section.Name, ctx.sections[i].base, section.SizeOfRawData)
	}

	ctx.println("\n=== Process Sections ===")
	if err := ctx.processRelocations(); err != nil {
		return err
	}

	ctx.println("\n=== Symbol Execution ===")
	return ctx.execute(entry, args)
}

func (ctx *executionContext) allocateAndMap() error {
	size, imports, err := ctx.virtualSize()
	if err != nil {
		return err
	}

	addr, _, err := procVirtualAlloc.Call(0, size, memReserve|memCommit, pageReadWrite)
	if addr == 0 {
		return fmt.Errorf("VirtualAlloc: %w", err)
	}

	ctx.memory = addr
	ctx.size = size
	ctx.sections = make([]sectionMap, len(ctx.obj.sections))
	if imports > 0 {
		ctx.symbolMap = unsafe.Slice((*uintptr)(unsafe.Pointer(addr+size-uintptr(imports)*unsafe.Sizeof(uintptr(0)))), imports)
		ctx.symbolBase = uintptr(unsafe.Pointer(&ctx.symbolMap[0]))
	}

	next := addr
	for i, section := range ctx.obj.sections {
		ctx.sections[i] = sectionMap{base: next, size: section.SizeOfRawData}
		next = pageAlign(next + uintptr(section.SizeOfRawData))
	}

	return nil
}

func (ctx *executionContext) virtualSize() (uintptr, int, error) {
	var length uintptr
	imports := 0

	for _, section := range ctx.obj.sections {
		length += pageAlign(uintptr(section.SizeOfRawData))
		for _, reloc := range ctx.obj.relocations(section) {
			if int(reloc.SymbolTableIndex) >= len(ctx.obj.symbols) {
				return 0, 0, fmt.Errorf("relocation references symbol index %d outside table", reloc.SymbolTableIndex)
			}
			if strings.HasPrefix(ctx.obj.symbols[reloc.SymbolTableIndex].Name, "__imp_") {
				imports++
				length += unsafe.Sizeof(uintptr(0))
			}
		}
	}

	return pageAlign(length), imports, nil
}

func (ctx *executionContext) processRelocations() error {
	fnIndex := 0
	for sectionIndex, section := range ctx.obj.sections {
		for _, reloc := range ctx.obj.relocations(section) {
			if int(reloc.SymbolTableIndex) >= len(ctx.obj.symbols) {
				return fmt.Errorf("relocation references symbol index %d outside table", reloc.SymbolTableIndex)
			}

			sym := ctx.obj.symbols[reloc.SymbolTableIndex]
			relocAddr := ctx.sections[sectionIndex].base + uintptr(reloc.VirtualAddress)
			var resolved uintptr

			if strings.HasPrefix(sym.Name, "__imp_") {
				var err error
				resolved, err = resolveSymbol(sym.Name, ctx.verbose)
				if err != nil {
					return err
				}
			}

			if reloc.Type == imageRelAMD64Rel32 && resolved != 0 {
				ctx.symbolMap[fnIndex] = resolved
				target := ctx.symbolBase + uintptr(fnIndex)*unsafe.Sizeof(uintptr(0))
				patchRel32(relocAddr, target)
				fnIndex++
				continue
			}

			if sym.SectionNumber <= 0 || int(sym.SectionNumber) > len(ctx.sections) {
				return fmt.Errorf("symbol %q has unsupported section number %d", sym.Name, sym.SectionNumber)
			}
			sectionBase := ctx.sections[sym.SectionNumber-1].base + uintptr(sym.Value)
			if err := ctx.applyRelocation(reloc.Type, relocAddr, sectionBase); err != nil {
				return fmt.Errorf("relocate %q: %w", sym.Name, err)
			}
		}
	}

	return nil
}

func (ctx *executionContext) execute(entry string, args []byte) error {
	for _, sym := range ctx.obj.symbols {
		if !sym.isFunction() || sym.Name != entry {
			continue
		}
		if sym.SectionNumber <= 0 || int(sym.SectionNumber) > len(ctx.sections) {
			return fmt.Errorf("entry %q has unsupported section number %d", entry, sym.SectionNumber)
		}

		section := ctx.sections[sym.SectionNumber-1]
		var oldProtect uint32
		ok, _, err := procVirtualProtect.Call(section.base, uintptr(section.size), pageExecuteRead, uintptr(unsafe.Pointer(&oldProtect)))
		if ok == 0 {
			return fmt.Errorf("VirtualProtect PAGE_EXECUTE_READ: %w", err)
		}

		entryAddr := section.base + uintptr(sym.Value)
		var argPtr uintptr
		if len(args) > 0 {
			argPtr = uintptr(unsafe.Pointer(&args[0]))
		}
		_, _, callErr := syscall.SyscallN(entryAddr, argPtr, uintptr(len(args)))

		ok, _, protectErr := procVirtualProtect.Call(section.base, uintptr(section.size), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
		if ok == 0 {
			return fmt.Errorf("VirtualProtect restore after call error %v: %w", callErr, protectErr)
		}

		return nil
	}

	return fmt.Errorf("entry function %q not found", entry)
}

func (ctx *executionContext) free() {
	if ctx.memory != 0 {
		procVirtualFree.Call(ctx.memory, 0, memRelease)
		ctx.memory = 0
	}
}

func (ctx *executionContext) printf(format string, args ...any) {
	if ctx.verbose {
		fmt.Printf(format, args...)
	}
}

func (ctx *executionContext) println(args ...any) {
	if ctx.verbose {
		fmt.Println(args...)
	}
}

func (ctx *executionContext) applyRelocation(relocType uint16, relocAddr, sectionBase uintptr) error {
	switch relocType {
	case imageRelAMD64Rel32:
		patchRel32(relocAddr, sectionBase)
	case imageRelAMD64Rel321:
		patchRel32N(relocAddr, sectionBase, 1)
	case imageRelAMD64Rel322:
		patchRel32N(relocAddr, sectionBase, 2)
	case imageRelAMD64Rel323:
		patchRel32N(relocAddr, sectionBase, 3)
	case imageRelAMD64Rel324:
		patchRel32N(relocAddr, sectionBase, 4)
	case imageRelAMD64Rel325:
		patchRel32N(relocAddr, sectionBase, 5)
	case imageRelAMD64Addr64:
		current := binary.LittleEndian.Uint64(unsafe.Slice((*byte)(unsafe.Pointer(relocAddr)), 8))
		binary.LittleEndian.PutUint64(unsafe.Slice((*byte)(unsafe.Pointer(relocAddr)), 8), current+uint64(sectionBase))
	case imageRelAMD64Addr32:
		current := binary.LittleEndian.Uint32(unsafe.Slice((*byte)(unsafe.Pointer(relocAddr)), 4))
		binary.LittleEndian.PutUint32(unsafe.Slice((*byte)(unsafe.Pointer(relocAddr)), 4), current+uint32(sectionBase))
	case imageRelAMD64Addr32NB:
		current := binary.LittleEndian.Uint32(unsafe.Slice((*byte)(unsafe.Pointer(relocAddr)), 4))
		binary.LittleEndian.PutUint32(unsafe.Slice((*byte)(unsafe.Pointer(relocAddr)), 4), current+uint32(sectionBase-ctx.memory))
	default:
		return fmt.Errorf("unsupported relocation type 0x%x", relocType)
	}
	return nil
}

func patchRel32(relocAddr, target uintptr) {
	patchRel32N(relocAddr, target, 0)
}

func patchRel32N(relocAddr, target uintptr, adjustment uintptr) {
	buf := unsafe.Slice((*byte)(unsafe.Pointer(relocAddr)), 4)
	current := binary.LittleEndian.Uint32(buf)
	delta := uint32(uintptr(current) + target - relocAddr - 4 - adjustment)
	binary.LittleEndian.PutUint32(buf, delta)
}

func pageAlign(value uintptr) uintptr {
	return value + ((pageSize - (value & (pageSize - 1))) % pageSize)
}
