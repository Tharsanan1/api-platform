/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Command mock-mtls-strict is a minimal mutual-TLS backend for
// gateway/it/features/mtls-outbound.feature's tls-test scenario: unlike the
// nginx-based mock backends in ../ (which complete the handshake and answer
// with an HTTP-level rejection for an untrusted client certificate), this
// server sets tls.RequireAndVerifyClientCert, so a client certificate that
// doesn't chain to its configured ClientCAs is rejected inside the TLS
// handshake itself — the one way to produce the gateway's
// BACKEND_REJECTED_IDENTITY probe result.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

// requireEnv reads a required configuration value, failing startup
// immediately (rather than falling back to a default) when it is missing —
// this server has no safe default for any of its three inputs.
func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("missing required environment variable %s", name)
	}
	return v
}

func main() {
	certFile := requireEnv("MTLS_STRICT_SERVER_CERT")
	keyFile := requireEnv("MTLS_STRICT_SERVER_KEY")
	clientCAFile := requireEnv("MTLS_STRICT_CLIENT_CA")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load server certificate/key (%s, %s): %v", certFile, keyFile, err)
	}

	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		log.Fatalf("failed to read client CA file %s: %v", clientCAFile, err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		log.Fatalf("no certificates found in client CA file %s", clientCAFile)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var subject string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			subject = r.TLS.PeerCertificates[0].Subject.String()
		}
		w.Header().Set("X-Client-Subject", subject)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"backend": "strict",
			"client":  subject,
		})
	})

	// Explicit timeouts per go-network-service-hardening.md — never a bare
	// zero-value server, even for a test-only mock.
	server := &http.Server{
		Addr:         ":8443",
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("mock-mtls-strict listening on :8443 (client CA: %s)", clientCAFile)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
