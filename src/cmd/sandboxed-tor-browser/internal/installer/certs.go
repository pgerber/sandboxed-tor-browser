// certs.go - dist.torproject.org certificates.
// Copyright (C) 2016  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package installer

import (
	"crypto/x509"
	"encoding/pem"
)

const (
	// Certificate chain
	// 0 s:/C=US/ST=Massachusetts/L=Cambridge/O=The Tor Project, Inc./CN=*.torproject.org
	//   i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 High Assurance Server CA
	// 1 s:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 High Assurance Server CA
	//   i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
	distTpoCertChainPEM = `-----BEGIN CERTIFICATE-----
MIIFaTCCBFGgAwIBAgIQDGnVmapHXfa3m9oYQq3WQTANBgkqhkiG9w0BAQsFADBw
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNz
dXJhbmNlIFNlcnZlciBDQTAeFw0xNjA0MTUwMDAwMDBaFw0xOTA1MjkxMjAwMDBa
MHQxCzAJBgNVBAYTAlVTMRYwFAYDVQQIEw1NYXNzYWNodXNldHRzMRIwEAYDVQQH
EwlDYW1icmlkZ2UxHjAcBgNVBAoTFVRoZSBUb3IgUHJvamVjdCwgSW5jLjEZMBcG
A1UEAwwQKi50b3Jwcm9qZWN0Lm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBALcjOe3IaIUn5YEOnAAM+uIlKm0HyHUaR6rwU0m5YhdSV8DRGUB80Q67
zkIbutTMbEla8KpPSqsK/FShSXhLWB6Hv5UV2jR6/Pzxi8QaLMMAuLT5oHCkR6Jn
LFZrUtPq50RmhYfg15kwosmEzPqLa3NDcK5tpTX5F48DvBT+0aCZQLndKGzVhiJI
pEJdfTc69b1i4xGyhzp4ChUFDtmK9MRZFRvDFl4ZaVBe2haw/+1kemGwh5UuaD+P
DqTJl+xwQdUCrKWBgwnOVLJKqrp2/Yc0mkkTFXqdUD1BS+wgvCDi64f7ndyyTQgb
8IWoWEeF6KHbiFZLVR/puH64cbyRF8cCAwEAAaOCAfkwggH1MB8GA1UdIwQYMBaA
FFFo/5CvAgd1PMzZZWRiohK4WXI7MB0GA1UdDgQWBBSCJgjxEylVNBS0j4Adcbhg
2ktBzDArBgNVHREEJDAighAqLnRvcnByb2plY3Qub3Jngg50b3Jwcm9qZWN0Lm9y
ZzAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MHUGA1UdHwRuMGwwNKAyoDCGLmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEy
LWhhLXNlcnZlci1nNS5jcmwwNKAyoDCGLmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNv
bS9zaGEyLWhhLXNlcnZlci1nNS5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAQEw
KjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZn
gQwBAgIwgYMGCCsGAQUFBwEBBHcwdTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
ZGlnaWNlcnQuY29tME0GCCsGAQUFBzAChkFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
dC5jb20vRGlnaUNlcnRTSEEySGlnaEFzc3VyYW5jZVNlcnZlckNBLmNydDAMBgNV
HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCwURSDN25h03L4cN8+FFi6ZbzP
OxIh8GgLKljF2nO/qW8gjKIOUgNizf99lsnn7YaYPCr8W9IZQBp64aWsWwuWZ3w8
bRhklFCmgHhDFeLCqmScYwxYlCmSL2qRe8Dus4t8Axse7LEni6KcOFA3Dtssc3MA
jv30cEvGJru0mcogoMh8O04hmWZfC1EiyBLDDb5mBhijtMN+SbNQSr53mZWTgMXh
luVXp48Z8RTrOdLJ03ArAh2gfpOLUz3eGmynpTFPz+l3V3yRHyoeWFiZUbm0ePnx
1HyeNR3onMNJC/tbYIBNoz/tIEPpFqJ1P3AT8q+uy/OQR4DEoG3f3Syq1pBG
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcDEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
LmRpZ2ljZXJ0LmNvbTEvMC0GA1UEAxMmRGlnaUNlcnQgU0hBMiBIaWdoIEFzc3Vy
YW5jZSBTZXJ2ZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2
4C/CJAbIbQRf1+8KZAayfSImZRauQkCbztyfn3YHPsMwVYcZuU+UDlqUH1VWtMIC
Kq/QmO4LQNfE0DtyyBSe75CxEamu0si4QzrZCwvV1ZX1QK/IHe1NnF9Xt4ZQaJn1
itrSxwUfqJfJ3KSxgoQtxq2lnMcZgqaFD15EWCo3j/018QsIJzJa9buLnqS9UdAn
4t07QjOjBSjEuyjMmqwrIw14xnvmXnG3Sj4I+4G3FhahnSMSTeXXkgisdaScus0X
sh5ENWV/UyU50RwKmmMbGZJ0aAo3wsJSSMs5WqK24V3B3aAguCGikyZvFEohQcft
bZvySC/zA/WiaJJTL17jAgMBAAGjggFJMIIBRTASBgNVHRMBAf8ECDAGAQH/AgEA
MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
NAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
dC5jb20wSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29t
L0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDA9BgNVHSAENjA0MDIG
BFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQ
UzAdBgNVHQ4EFgQUUWj/kK8CB3U8zNllZGKiErhZcjswHwYDVR0jBBgwFoAUsT7D
aQP4v0cB1JgmGggC72NkK8MwDQYJKoZIhvcNAQELBQADggEBABiKlYkD5m3fXPwd
aOpKj4PWUS+Na0QWnqxj9dJubISZi6qBcYRb7TROsLd5kinMLYBq8I4g4Xmk/gNH
E+r1hspZcX30BJZr01lYPf7TMSVcGDiEo+afgv2MW5gxTs14nhr9hctJqvIni5ly
/D6q1UEL2tU2ob8cbkdJf17ZSHwD2f2LSaCYJkJA69aSEaRkCldUxPUd1gJea6zu
xICaEnL6VpPX/78whQYwvwt/Tv9XBZ0k7YXDK/umdaisLRbvfXknsuvCnQsH6qqF
0wGjIChBWUMo0oHjqvbsezt3tkBigAVBRQHvFwY+3sAzm2fTYS5yh+Rp/BIAV0Ae
cPUeybQ=
-----END CERTIFICATE-----`
)

var distTpoCertChain []*x509.Certificate

func init() {
	// Decode the hardcoded certificate chain.
	for data := []byte(distTpoCertChainPEM); data != nil; {
		// Decode the PEM, and ensure that it is a certificate.
		p, rest := pem.Decode(data)
		if p == nil {
			break
		}
		if p.Type != "CERTIFICATE" {
			panic("invalid PEM type when decoding certificate chain")
		}

		// Decode the ASN.1 into a parsed certificate, and append.
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			panic("failed to parse certificate:" + err.Error())
		}
		distTpoCertChain = append(distTpoCertChain, cert)

		data = rest
	}

	if distTpoCertChain == nil {
		panic("no hardcoded certificate chain for `dist.torproject.org`")
	}
}
