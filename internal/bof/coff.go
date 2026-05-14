package bof

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	imageFileMachineAMD64 = 0x8664

	imageSymTypeNull      = 0x0000
	imageSymDTypeFunction = 0x0020

	imageRelAMD64Addr64   = 0x0001
	imageRelAMD64Addr32   = 0x0002
	imageRelAMD64Addr32NB = 0x0003
	imageRelAMD64Rel32    = 0x0004
	imageRelAMD64Rel321   = 0x0005
	imageRelAMD64Rel322   = 0x0006
	imageRelAMD64Rel323   = 0x0007
	imageRelAMD64Rel324   = 0x0008
	imageRelAMD64Rel325   = 0x0009

	coffFileHeaderSize    = 20
	coffSectionHeaderSize = 40
	coffSymbolSize        = 18
	coffRelocationSize    = 10
)

type fileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type sectionHeader struct {
	Name                 string
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

type symbol struct {
	Name               string
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

type relocation struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

type objectFile struct {
	data     []byte
	header   fileHeader
	sections []sectionHeader
	symbols  []symbol
}

func parseObject(data []byte) (*objectFile, error) {
	if len(data) < coffFileHeaderSize {
		return nil, fmt.Errorf("object is too small for COFF header")
	}

	obj := &objectFile{data: data}
	r := bytes.NewReader(data[:coffFileHeaderSize])
	if err := binary.Read(r, binary.LittleEndian, &obj.header); err != nil {
		return nil, fmt.Errorf("parse COFF header: %w", err)
	}
	if obj.header.Machine != imageFileMachineAMD64 {
		return nil, fmt.Errorf("object machine 0x%x is not x64 AMD64", obj.header.Machine)
	}
	if obj.header.SizeOfOptionalHeader != 0 {
		return nil, fmt.Errorf("unexpected optional header size %d in COFF object", obj.header.SizeOfOptionalHeader)
	}

	sectionTable := coffFileHeaderSize + int(obj.header.SizeOfOptionalHeader)
	sectionBytes := int(obj.header.NumberOfSections) * coffSectionHeaderSize
	if !hasRange(data, sectionTable, sectionBytes) {
		return nil, fmt.Errorf("section table extends beyond object")
	}

	obj.sections = make([]sectionHeader, obj.header.NumberOfSections)
	for i := range obj.sections {
		off := sectionTable + i*coffSectionHeaderSize
		obj.sections[i] = parseSectionHeader(data[off : off+coffSectionHeaderSize])
	}

	symbolTable := int(obj.header.PointerToSymbolTable)
	symbolBytes := int(obj.header.NumberOfSymbols) * coffSymbolSize
	if !hasRange(data, symbolTable, symbolBytes) {
		return nil, fmt.Errorf("symbol table extends beyond object")
	}

	stringTable := symbolTable + symbolBytes
	if !hasRange(data, stringTable, 4) {
		return nil, fmt.Errorf("missing COFF string table")
	}
	stringTableSize := int(binary.LittleEndian.Uint32(data[stringTable:]))
	if stringTableSize < 4 || !hasRange(data, stringTable, stringTableSize) {
		return nil, fmt.Errorf("invalid COFF string table size %d", stringTableSize)
	}

	obj.symbols = make([]symbol, obj.header.NumberOfSymbols)
	for i := range obj.symbols {
		off := symbolTable + i*coffSymbolSize
		sym, err := parseSymbol(data[off:off+coffSymbolSize], data[stringTable:stringTable+stringTableSize])
		if err != nil {
			return nil, fmt.Errorf("parse symbol %d: %w", i, err)
		}
		obj.symbols[i] = sym
	}

	for i, section := range obj.sections {
		if section.SizeOfRawData > 0 && !hasRange(data, int(section.PointerToRawData), int(section.SizeOfRawData)) {
			return nil, fmt.Errorf("section %q raw data extends beyond object", section.Name)
		}
		relocBytes := int(section.NumberOfRelocations) * coffRelocationSize
		if relocBytes > 0 && !hasRange(data, int(section.PointerToRelocations), relocBytes) {
			return nil, fmt.Errorf("section %d relocation table extends beyond object", i)
		}
	}

	return obj, nil
}

func parseSectionHeader(data []byte) sectionHeader {
	return sectionHeader{
		Name:                 coffName(data[:8]),
		VirtualSize:          binary.LittleEndian.Uint32(data[8:12]),
		VirtualAddress:       binary.LittleEndian.Uint32(data[12:16]),
		SizeOfRawData:        binary.LittleEndian.Uint32(data[16:20]),
		PointerToRawData:     binary.LittleEndian.Uint32(data[20:24]),
		PointerToRelocations: binary.LittleEndian.Uint32(data[24:28]),
		PointerToLineNumbers: binary.LittleEndian.Uint32(data[28:32]),
		NumberOfRelocations:  binary.LittleEndian.Uint16(data[32:34]),
		NumberOfLineNumbers:  binary.LittleEndian.Uint16(data[34:36]),
		Characteristics:      binary.LittleEndian.Uint32(data[36:40]),
	}
}

func parseSymbol(data, stringTable []byte) (symbol, error) {
	name, err := parseSymbolName(data[:8], stringTable)
	if err != nil {
		return symbol{}, err
	}
	return symbol{
		Name:               name,
		Value:              binary.LittleEndian.Uint32(data[8:12]),
		SectionNumber:      int16(binary.LittleEndian.Uint16(data[12:14])),
		Type:               binary.LittleEndian.Uint16(data[14:16]),
		StorageClass:       data[16],
		NumberOfAuxSymbols: data[17],
	}, nil
}

func parseSymbolName(name, stringTable []byte) (string, error) {
	if binary.LittleEndian.Uint32(name[:4]) != 0 {
		return coffName(name), nil
	}

	offset := int(binary.LittleEndian.Uint32(name[4:8]))
	if offset == 0 {
		return "", nil
	}
	if offset < 4 || offset >= len(stringTable) {
		return "", fmt.Errorf("invalid string table offset %d", offset)
	}

	end := offset
	for end < len(stringTable) && stringTable[end] != 0 {
		end++
	}
	return string(stringTable[offset:end]), nil
}

func coffName(data []byte) string {
	if idx := bytes.IndexByte(data, 0); idx >= 0 {
		data = data[:idx]
	}
	return string(data)
}

func (obj *objectFile) relocations(section sectionHeader) []relocation {
	rels := make([]relocation, section.NumberOfRelocations)
	base := int(section.PointerToRelocations)
	for i := range rels {
		off := base + i*coffRelocationSize
		rels[i] = relocation{
			VirtualAddress:   binary.LittleEndian.Uint32(obj.data[off : off+4]),
			SymbolTableIndex: binary.LittleEndian.Uint32(obj.data[off+4 : off+8]),
			Type:             binary.LittleEndian.Uint16(obj.data[off+8 : off+10]),
		}
	}
	return rels
}

func (s symbol) isFunction() bool {
	return s.Type != imageSymTypeNull && s.Type&imageSymDTypeFunction == imageSymDTypeFunction
}

func hasRange(data []byte, off, size int) bool {
	return off >= 0 && size >= 0 && off <= len(data) && size <= len(data)-off
}
