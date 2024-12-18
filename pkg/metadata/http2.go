package metadata

import (
	"bytes"
	"fmt"
	"math"
)

// https://github.com/golang/net/blob/5a444b4f2fe893ea00f0376da46aa5376c3f3e28/http2/http2.go#L112-L119
type Setting struct {
	Id  uint16
	Val uint32
}

// https://github.com/golang/net/blob/5a444b4f2fe893ea00f0376da46aa5376c3f3e28/http2/frame.go#L1142-L1156
type Priority struct {
	StreamId  uint32
	StreamDep uint32
	Exclusive bool
	Weight    uint8
}

// https://github.com/golang/net/blob/5a444b4f2fe893ea00f0376da46aa5376c3f3e28/http2/hpack/hpack.go#L36-L42
type HeaderField struct {
	Name, Value string
	Sensitive   bool
}

type HTTP2FingerprintingFrames struct {
	// Data from SETTINGS frame
	Settings []Setting

	// Increment of WINDOW_UPDATE frame
	WindowUpdateIncrement uint32

	// PRIORITY frame(s)
	Priorities []Priority

	// HEADERS frame
	Headers []HeaderField
}

func (f *HTTP2FingerprintingFrames) String() string {
	return f.Marshal(math.MaxUint)
}

// TODO: add tests
func (f *HTTP2FingerprintingFrames) Marshal(maxPriorityFrames uint) string {
	var buf bytes.Buffer

	// SETTINGS frame
	for i, s := range f.Settings {
		if i != 0 {
			// Multiple settings are concatenated using a semicolon (;) according to the order of their appearance.
			buf.WriteString(";")
		}
		// S[...] stands for a SETTINGS parameter and its value in the form of Key:Value.
		buf.WriteString(fmt.Sprintf("%d:%d", s.Id, s.Val))
	}

	buf.WriteString("|")

	// WINDOW_UPDATE frame
	// ‘00’ if the frame is not present
	buf.WriteString(fmt.Sprintf("%02d|", f.WindowUpdateIncrement))

	// PRIORITY frame
	if l := len(f.Priorities); uint(l) < maxPriorityFrames {
		maxPriorityFrames = uint(l)
	}
	if maxPriorityFrames == 0 {
		// If this feature does not exist, the value should be ‘0’.
		buf.WriteString("0|")
	} else {
		for i, p := range f.Priorities[:maxPriorityFrames] {
			if i != 0 {
				// Multiple priority frames are concatenated by a comma (,).
				buf.WriteString(",")
			}
			// StreamID:Exclusivity_Bit:Dependant_StreamID:Weight
			buf.WriteString(fmt.Sprintf("%d:", p.StreamId))
			if p.Exclusive {
				buf.WriteString("1:")
			} else {
				buf.WriteString("0:")
			}
			// "Add one to the value to obtain a weight between 1 and 256."
			// Quoted from https://httpwg.org/specs/rfc7540.html#PRIORITY
			buf.WriteString(fmt.Sprintf("%d:%d", p.StreamDep, int(p.Weight)+1))
		}
		buf.WriteString("|")
	}

	// HEADERS frame
	wrotePseudoHeader := false
	for _, h := range f.Headers {
		// filter only pseudo headers which starts with a colon
		if len(h.Name) >= 2 && h.Name[0] == ':' {
			if wrotePseudoHeader {
				buf.WriteString(",")
			}
			wrotePseudoHeader = true
			buf.WriteByte(h.Name[1])
		}
	}

	return buf.String()
}
