// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"testing"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"

	tu "github.com/hashicorp/terraform-provider-tls/internal/provider/testutils"
)

func TestPrivateKeyRSA(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`)),
				),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
						rsa_bits = 4096
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) < 1700 {
							return fmt.Errorf("private key PEM looks too short for a 4096-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccPrivateKeyRSA_UpgradeFromVersion3_4_0(t *testing.T) {
	r.Test(t, r.TestCase{
		Steps: []r.TestStep{
			{
				ExternalProviders: providerVersion340(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_pem_pkcs8"),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`)),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				PlanOnly: true,
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`)),
				),
			},
		},
	})
}

func TestAccPrivateKeyRSA_UpgradeFromVersion3_1_0(t *testing.T) {
	r.Test(t, r.TestCase{
		Steps: []r.TestStep{
			{
				ExternalProviders: providerVersion310(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_openssh"),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_pem_pkcs8"),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestCheckNoResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256"),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`)),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				PlanOnly: true,
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`)),
				),
			},
		},
	})
}

func TestPrivateKeyECDSA(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckResourceAttr("tls_private_key.test", "private_key_openssh", ""),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_openssh", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", ""),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`)),
				),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
						ecdsa_curve = "P256"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ecdsa-sha2-nistp256 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`)),
				),
			},
		},
	})
}

func TestAccPrivateKeyECDSA_UpgradeFromVersion3_4_0(t *testing.T) {
	r.Test(t, r.TestCase{
		Steps: []r.TestStep{
			{
				ExternalProviders: providerVersion340(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckResourceAttr("tls_private_key.test", "private_key_openssh", ""),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_pem_pkcs8"),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_openssh", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", ""),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`))),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
					}
				`,
				PlanOnly: true,
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckResourceAttr("tls_private_key.test", "private_key_openssh", ""),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_openssh", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", ""),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`))),
			},
		},
	})
}

func TestAccPrivateKeyECDSA_UpgradeFromVersion3_1_0(t *testing.T) {
	r.Test(t, r.TestCase{
		Steps: []r.TestStep{
			{
				ExternalProviders: providerVersion310(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
						ecdsa_curve = "P256"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_openssh"),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_pem_pkcs8"),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ecdsa-sha2-nistp256 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestCheckNoResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256"),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`))),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
						ecdsa_curve = "P256"
					}
				`,
				PlanOnly: true,
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
						ecdsa_curve = "P256"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ecdsa-sha2-nistp256 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`))),
			},
		},
	})
}

func TestPrivateKeyED25519(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-ed25519 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`))),
			},
		},
	})
}

func TestAccPrivateKeyED25519_UpgradeFromVersion3_4_0(t *testing.T) {
	r.Test(t, r.TestCase{
		Steps: []r.TestStep{
			{
				ExternalProviders: providerVersion340(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_pem_pkcs8"),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-ed25519 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`))),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				PlanOnly: true,
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-ed25519 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`))),
			},
		},
	})
}

func TestOpenSSHComment(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
						openssh_comment = "test@test"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-ed25519 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(` test@test\n$`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_x509_sha256", regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`))),
			},
		},
	})
}

// type keyLens struct {
// 	algorithm   string
// 	rsa_bits    int
// 	ecdsa_curve string
// }

// var testAccProviders map[string]*schema.Provider
// var testAccProvider *schema.Provider

// func init() {
// 	testAccProvider = New()
// 	testAccProviders = map[string]*schema.Provider{
// 		"tls": testAccProvider,
// 	}
// }

// func TestAccImportKey(t *testing.T) {
// 	r.UnitTest(t, r.TestCase{
// 		PreCheck:  func() {},
// 		Providers: testAccProviders,
// 		Steps: []r.TestStep{
// 			{
// 				Config: testAccResourceKeyConfig,
// 				Check: r.ComposeTestCheckFunc(
// 					testAccResourceKeyCheck("tls_private_key.rsa", &keyLens{
// 						algorithm:   "RSA",
// 						rsa_bits:    2048,
// 						ecdsa_curve: "P224",
// 					}),
// 					testAccResourceKeyCheck("tls_private_key.ecdsa", &keyLens{
// 						algorithm:   "ECDSA",
// 						rsa_bits:    2048,
// 						ecdsa_curve: "P224",
// 					}),
// 				),
// 			},
// 			{
// 				ResourceName:      "tls_private_key.rsa",
// 				ImportState:       true,
// 				ImportStateIdFunc: importStateIdFunc(t, fixtures.TestPrivateKeyPEM),
// 			},
// 			{
// 				ResourceName:      "tls_private_key.ecdsa",
// 				ImportState:       true,
// 				ImportStateIdFunc: importStateIdFunc(t, fixtures.TestPrivateKeyECDSA),
// 			},
// 		},
// 	})
// }
// func importStateIdFunc(t *testing.T, key string) func(*terraform.State) (string, error) {
// 	return func(state *terraform.State) (string, error) {
// 		file, err := os.CreateTemp(t.TempDir(), state.Lineage)
// 		file.Write([]byte(key))
// 		if err != nil {
// 			return "", fmt.Errorf("could not write file: %w", err)
// 		}
// 		return file.Name(), nil
// 	}
// }
// func testAccResourceKeyCheck(id string, want *keyLens) r.TestCheckFunc {
// 	return func(s *terraform.State) error {
// 		rs, ok := s.RootModule().Resources[id]
// 		if !ok {
// 			return fmt.Errorf("Not found: %s", id)
// 		}
// 		if rs.Primary.ID == "" {
// 			return fmt.Errorf("No ID is set")
// 		}

// 		algorithm := rs.Primary.Attributes["algorithm"]
// 		rsa_bits := rs.Primary.Attributes["rsa_bits"]
// 		ecdsa_curve := rs.Primary.Attributes["ecdsa_curve"]

// 		if got, want := algorithm, want.algorithm; got != want {
// 			return fmt.Errorf("algorithm is %s; want %s", got, want)
// 		}
// 		if got, want := rsa_bits, want.rsa_bits; got != fmt.Sprint(want) {
// 			return fmt.Errorf("rsa_bits is %v; want %v", got, want)
// 		}
// 		if got, want := ecdsa_curve, want.ecdsa_curve; got != want {
// 			return fmt.Errorf("ecdsa_curve is %s; want %s", got, want)
// 		}

// 		return nil
// 	}
// }

// const (
// 	testAccResourceKeyConfig = `
// resource "tls_private_key" "rsa" {
//   algorithm = "RSA"
// }

// resource "tls_private_key" "ecdsa" {
//   algorithm = "ECDSA"
// }
// `
// )
