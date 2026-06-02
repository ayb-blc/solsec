package parser

import (
	"strconv"
	"strings"
)

type SourceMap struct {
	lineOffsets []int
}

func NewSourceMap(source string) *SourceMap {
	offsets := []int{0}
	for i, ch := range source {
		if ch == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return &SourceMap{lineOffsets: offsets}
}

func (sm *SourceMap) LineOf(src string) int {
	offset := parseSrcOffset(src)
	if offset < 0 {
		return 0
	}
	return sm.lineOfOffset(offset)
}

func (sm *SourceMap) lineOfOffset(offset int) int {
	lo, hi := 0, len(sm.lineOffsets)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		if sm.lineOffsets[mid] <= offset {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return hi + 1 // 1-indexed
}

func parseSrcOffset(src string) int {
	parts := strings.SplitN(src, ":", 3)
	if len(parts) < 1 {
		return -1
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return -1
	}
	return n
}
