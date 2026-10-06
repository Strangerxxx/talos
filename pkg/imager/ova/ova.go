// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package ova implements OVA creation.
package ova

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/siderolabs/go-cmd/pkg/cmd"

	"github.com/siderolabs/talos/pkg/imager/utils"
	"github.com/siderolabs/talos/pkg/imager/vmdkconvert"
)

const mfTpl = `SHA256({{ .VMDK }})= {{ .VMDKSHA }}
SHA256({{ .OVF }})= {{ .OVFSHA }}
`

// OVF format reference: https://www.dmtf.org/standards/ovf.
//
//go:embed disk.ovf.tmpl
var ovfTpl string

// Options describe the input for creating an OVA.
type Options struct {
	// OutPath is the RAW disk, replaced with the OVA.
	OutPath     string
	ScratchPath string
	Arch        string
	DiskSize    int64

	// OVFTemplate replaces the built-in OVF descriptor template if set.
	OVFTemplate string
	// SecureBootCertificate is the DER SecureBoot signing certificate, nil without SecureBoot.
	SecureBootCertificate []byte
}

// CreateOVAFromRAW creates an OVA from a RAW disk.
//
//nolint:gocyclo
func CreateOVAFromRAW(ctx context.Context, options Options, printf func(string, ...any)) error {
	if err := os.MkdirAll(options.ScratchPath, 0o755); err != nil {
		return err
	}

	vmdkPath := filepath.Join(options.ScratchPath, "disk.vmdk")

	if err := utils.CopyFiles(printf, utils.SourceDestination(options.OutPath, vmdkPath)); err != nil {
		return err
	}

	if err := vmdkconvert.ConvertToStreamOptimizedVMDK(ctx, vmdkPath, printf); err != nil {
		return err
	}

	f, err := os.Stat(vmdkPath)
	if err != nil {
		return err
	}

	imageSize := f.Size()

	ovf, err := renderOVF(imageSize, options)
	if err != nil {
		return err
	}

	input, err := os.Open(vmdkPath)
	if err != nil {
		return err
	}

	defer input.Close() //nolint:errcheck

	vmdkSHA25Sum, err := sha256sum(input)
	if err != nil {
		return err
	}

	ovfSHA25Sum, err := sha256sum(strings.NewReader(ovf))
	if err != nil {
		return err
	}

	mf, err := renderMF(vmdkSHA25Sum, ovfSHA25Sum)
	if err != nil {
		return err
	}

	if err = os.WriteFile(filepath.Join(options.ScratchPath, "disk.mf"), []byte(mf), 0o666); err != nil {
		return err
	}

	if err = os.WriteFile(filepath.Join(options.ScratchPath, "disk.ovf"), []byte(ovf), 0o666); err != nil {
		return err
	}

	if _, err = cmd.RunWithOptions(ctx, "tar", []string{"-cvf", options.OutPath, "-C", options.ScratchPath, "disk.ovf", "disk.mf", "disk.vmdk"}); err != nil {
		return err
	}

	return nil
}

func sha256sum(input io.Reader) (string, error) {
	hash := sha256.New()

	if _, err := io.Copy(hash, input); err != nil {
		return "", err
	}

	sum := hash.Sum(nil)

	return hex.EncodeToString(sum), nil
}

func renderMF(vmdkSHA25Sum, ovfSHA25Sum string) (string, error) {
	cfg := struct {
		VMDK    string
		VMDKSHA string
		OVF     string
		OVFSHA  string
	}{
		VMDK:    "disk.vmdk",
		VMDKSHA: vmdkSHA25Sum,
		OVF:     "disk.ovf",
		OVFSHA:  ovfSHA25Sum,
	}

	templ := template.Must(template.New("mf").Parse(mfTpl))

	var buf bytes.Buffer

	if err := templ.Execute(&buf, cfg); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func renderOVF(imageSize int64, options Options) (string, error) {
	cfg := struct {
		VMDK                     string
		Size                     int64
		Capacity                 int64
		Arch                     string
		SecureBootCertificateHex string
	}{
		VMDK:                     "disk.vmdk",
		Size:                     imageSize,
		Capacity:                 options.DiskSize / (1 << 20),
		Arch:                     options.Arch,
		SecureBootCertificateHex: hex.EncodeToString(options.SecureBootCertificate),
	}

	ovfTemplate := options.OVFTemplate
	if ovfTemplate == "" {
		ovfTemplate = ovfTpl
	}

	templ, err := template.New("ovf").Parse(ovfTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse OVF template: %w", err)
	}

	var buf bytes.Buffer

	if err := templ.Execute(&buf, cfg); err != nil {
		return "", err
	}

	return buf.String(), nil
}
