package main

import (
	"encoding/json"
	"fmt"

	"github.com/dreadl0ck/tlsx"
	"github.com/refraction-networking/utls/dicttls"
	"github.com/wi1dcard/fingerproxy/pkg/ja4"
)

type ja3Detail tlsx.ClientHelloBasic

type ja4Detail ja4.JA4Fingerprint

func (j *ja3Detail) MarshalJSON() ([]byte, error) {
	data := struct {
		ja3Detail
		ReadableCipherSuites    []string
		ReadableAllExtensions   []string
		ReadableSupportedGroups []string
	}{
		ja3Detail:               *j,
		ReadableCipherSuites:    make([]string, len(j.CipherSuites)),
		ReadableAllExtensions:   make([]string, len(j.AllExtensions)),
		ReadableSupportedGroups: make([]string, len(j.SupportedGroups)),
	}

	for i, v := range j.CipherSuites {
		u := uint16(v)
		if name, ok := dicttls.DictCipherSuiteValueIndexed[u]; ok {
			data.ReadableCipherSuites[i] = fmt.Sprintf("%s (0x%x)", name, u)
		} else {
			data.ReadableCipherSuites[i] = fmt.Sprintf("UNKNOWN (0x%x)", u)
		}
	}

	for i, v := range j.AllExtensions {
		if name, ok := dicttls.DictExtTypeValueIndexed[v]; ok {
			data.ReadableAllExtensions[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			data.ReadableAllExtensions[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}

	for i, v := range j.SupportedGroups {
		if name, ok := dicttls.DictSupportedGroupsValueIndexed[v]; ok {
			data.ReadableSupportedGroups[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			data.ReadableSupportedGroups[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}

	return json.Marshal(data)
}

func (j *ja4Detail) MarshalJSON() ([]byte, error) {
	data := struct {
		ja4Detail
		ReadableCipherSuites        []string
		ReadableExtensions          []string
		ReadableSignatureAlgorithms []string
	}{
		ja4Detail:                   *j,
		ReadableCipherSuites:        make([]string, len(j.CipherSuites)),
		ReadableExtensions:          make([]string, len(j.Extensions)),
		ReadableSignatureAlgorithms: make([]string, len(j.SignatureAlgorithms)),
	}

	for i, v := range j.CipherSuites {
		if name, ok := dicttls.DictCipherSuiteValueIndexed[v]; ok {
			data.ReadableCipherSuites[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			data.ReadableCipherSuites[i] = fmt.Sprintf("UNKNOWN (0x%x)", v)
		}
	}

	for i, v := range j.Extensions {
		if name, ok := dicttls.DictExtTypeValueIndexed[v]; ok {
			data.ReadableExtensions[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			data.ReadableExtensions[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}

	for i, v := range j.SignatureAlgorithms {
		if name, ok := dicttls.DictSignatureAlgorithmValueIndexed[uint8(v)]; ok {
			data.ReadableSignatureAlgorithms[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			data.ReadableSignatureAlgorithms[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}

	return json.Marshal(data)
}
