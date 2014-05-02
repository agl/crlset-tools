// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file of the Chromium repository.

// This is a small program to download and parse CRLSets.
package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

// update and the related structures are used for parsing the XML response from Omaha. The response looks like:
// <?xml version="1.0" encoding="UTF-8"?>
// <gupdate xmlns="http://www.google.com/update2/response" protocol="2.0" server="prod">
//   <daystart elapsed_seconds="42913"/>
//   <app appid="hfnkpimlhhgieaddgfemjhofmfblmnib" status="ok">
//     <updatecheck codebase="http://www.gstatic.com/chrome/crlset/56/crl-set-14830555124393087472.crx.data" hash="" size="0" status="ok" version="56"/>
//   </app>
// </gupdate>
type update struct {
	XMLName xml.Name    `xml:"gupdate"`
	Apps    []updateApp `xml:"app"`
}

type updateApp struct {
	AppId       string `xml:"appid,attr"`
	UpdateCheck updateCheck
}

type updateCheck struct {
	XMLName xml.Name `xml:"updatecheck"`
	URL     string   `xml:"codebase,attr"`
	Version string   `xml:"version,attr"`
}

// crlSetAppId is the hex(ish) encoded public key hash of the key that signs
// the CRL sets.
const crlSetAppId = "hfnkpimlhhgieaddgfemjhofmfblmnib"

// buildVersionRequestURL returns a URL from which the current CRLSet version
// information can be fetched.
func buildVersionRequestURL() string {
	args := url.Values(make(map[string][]string))
	args.Add("x", "id="+crlSetAppId+"&v=&uc")

	return (&url.URL{
		Scheme:   "http",
		Host:     "clients2.google.com",
		Path:     "/service/update2/crx",
		RawQuery: args.Encode(),
	}).String()
}

// crxHeader reflects the binary header of a CRX file.
type crxHeader struct {
	Magic       [4]byte
	Version     uint32
	PubKeyBytes uint32
	SigBytes    uint32
}

// zipReader is a small wrapper around a []byte which implements ReaderAt.
type zipReader []byte

func (z zipReader) ReadAt(p []byte, pos int64) (int, error) {
	if int(pos) < 0 {
		return 0, nil
	}
	return copy(p, []byte(z)[int(pos):]), nil
}

func fetch() bool {
	resp, err := http.Get(buildVersionRequestURL())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current version: %s\n", err)
		return false
	}

	var reply update
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read version reply: %s\n", err)
		return false
	}
	if err := xml.Unmarshal(bodyBytes, &reply); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse version reply: %s\n", err)
		return false
	}

	var crxURL, version string
	for _, app := range reply.Apps {
		if app.AppId == crlSetAppId {
			crxURL = app.UpdateCheck.URL
			version = app.UpdateCheck.Version
			break
		}
	}
	fmt.Fprintf(os.Stderr, "Downloading CRLSet version %s\n", version)

	if len(crxURL) == 0 {
		fmt.Fprintf(os.Stderr, "Failed to parse Omaha response\n")
		return false
	}

	resp, err = http.Get(crxURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get CRX: %s\n", err)
		return false
	}
	defer resp.Body.Close()

	// zip needs to seek around, so we read the whole reply into memory.
	crxBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to download CRX: %s\n", err)
		return false
	}
	crx := bytes.NewBuffer(crxBytes)

	var header crxHeader
	if err := binary.Read(crx, binary.LittleEndian, &header); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse CRX header: %s\n", err)
		return false
	}

	if !bytes.Equal(header.Magic[:], []byte("Cr24")) ||
		int(header.PubKeyBytes) < 0 ||
		int(header.SigBytes) < 0 {
		fmt.Fprintf(os.Stderr, "Downloaded file doesn't look like a CRX\n")
		return false
	}

	pubKeyBytes := crx.Next(int(header.PubKeyBytes))
	sigBytes := crx.Next(int(header.SigBytes))

	if len(pubKeyBytes) != int(header.PubKeyBytes) ||
		len(sigBytes) != int(header.SigBytes) {
		fmt.Fprintf(os.Stderr, "Downloaded file doesn't look like a CRX\n")
		return false
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse public key: %s\n", err)
		return false
	}
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "Not signed with an RSA key\n")
		return false
	}

	h := sha256.New()
	h.Write(pubKeyBytes)
	pubKeyHash := fmt.Sprintf("%x", h.Sum(nil)[:16])
	tweakedPubKeyHash := make([]byte, len(pubKeyHash))

	// AppIds use a different hex character set so we convert our hash into
	// it.
	for i := range pubKeyHash {
		if pubKeyHash[i] < 97 {
			tweakedPubKeyHash[i] = pubKeyHash[i] + 49
		} else {
			tweakedPubKeyHash[i] = pubKeyHash[i] + 10
		}
	}

	if string(tweakedPubKeyHash) != crlSetAppId {
		fmt.Fprintf(os.Stderr, "Public key mismatch (%s)\n", tweakedPubKeyHash)
		return false
	}

	zipBytes := crx.Bytes()

	sha1Hash := sha1.New()
	sha1Hash.Write(zipBytes)

	if err := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA1, sha1Hash.Sum(nil), sigBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Signature verification failure: %s\n", err)
		return false
	}

	zipReader := zipReader(zipBytes)

	z, err := zip.NewReader(zipReader, int64(len(zipBytes)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse ZIP file: %s\n", err)
		return false
	}

	var crlFile *zip.File
	for _, file := range z.File {
		if file.Name == "crl-set" {
			crlFile = file
			break
		}
	}

	if crlFile == nil {
		fmt.Fprintf(os.Stderr, "Downloaded CRX didn't contain a CRLSet\n")
		return false
	}

	crlSetReader, err := crlFile.Open()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open crl-set in ZIP: %s\n", err)
		return false
	}
	defer crlSetReader.Close()

	io.Copy(os.Stdout, crlSetReader)

	return true
}

// crlSetHeader is used to parse the JSON header found in CRLSet files.
type crlSetHeader struct {
	Sequence   int
	NumParents int
}

func dump(filename string, certificateFilename string) bool {
	var spki []byte
	if len(certificateFilename) > 0 {
		certBytes, err := ioutil.ReadFile(certificateFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read certificate: %s\n", err)
			return false
		}

		var derBytes []byte
		if block, _ := pem.Decode(certBytes); block == nil {
			derBytes = certBytes
		} else {
			derBytes = block.Bytes
		}

		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse certificate: %s\n", err)
			return false
		}

		h := sha256.New()
		h.Write(cert.RawSubjectPublicKeyInfo)
		spki = h.Sum(nil)
	}

	c, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read CRLSet: %s\n", err)
		return false
	}

	if len(c) < 2 {
		fmt.Fprintf(os.Stderr, "CRLSet truncated at header length\n")
		return false
	}

	headerLen := int(c[0]) | int(c[1])<<8
	c = c[2:]

	if len(c) < headerLen {
		fmt.Fprintf(os.Stderr, "CRLSet truncated at header\n")
		return false
	}
	headerBytes := c[:headerLen]
	c = c[headerLen:]

	var header crlSetHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse header: %s", err)
		return false
	}

	if len(spki) == 0 {
		fmt.Printf("Sequence: %d\n", header.Sequence)
		fmt.Printf("Parents: %d\n", header.NumParents)
		fmt.Printf("\n")
	}

	const spkiHashLen = 32

	for len(c) > 0 {
		if len(c) < spkiHashLen {
			fmt.Fprintf(os.Stderr, "CRLSet truncated at SPKI hash\n")
			return false
		}
		spkiMatches := bytes.Equal(spki, c[:spkiHashLen])
		if len(spki) == 0 {
			fmt.Printf("%x\n", c[:spkiHashLen])
		}
		c = c[spkiHashLen:]

		if len(c) < 4 {
			fmt.Fprintf(os.Stderr, "CRLSet truncated at serial count\n")
			return false
		}
		numSerials := uint32(c[0]) | uint32(c[1])<<8 | uint32(c[2])<<16 | uint32(c[3])<<24
		c = c[4:]

		for i := uint32(0); i < numSerials; i++ {
			if len(c) < 1 {
				fmt.Fprintf(os.Stderr, "CRLSet truncated at serial length\n")
				return false
			}
			serialLen := int(c[0])
			c = c[1:]

			if len(c) < serialLen {
				fmt.Fprintf(os.Stderr, "CRLSet truncated at serial\n")
				return false
			}

			if len(spki) == 0 {
				fmt.Printf("  %x\n", c[:serialLen])
			} else if spkiMatches {
				fmt.Printf("%x\n", c[:serialLen])
			}
			c = c[serialLen:]
		}
	}

	return true
}

func usage() {
	fmt.Fprintf(os.Stderr, "%s: { fetch | dump <filename> [<cert filename>] }\n", os.Args[0])
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	result := false
	needUsage := true

	switch os.Args[1] {
	case "fetch":
		if len(os.Args) == 2 {
			result = fetch()
			needUsage = false
		}
	case "dump":
		if len(os.Args) == 3 {
			needUsage = false
			result = dump(os.Args[2], "")
		} else if len(os.Args) == 4 {
			needUsage = false
			result = dump(os.Args[2], os.Args[3])
		}
	}

	if needUsage {
		usage()
	}

	if !result {
		os.Exit(1)
	}
}
