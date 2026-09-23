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

// Package certmetrics keeps the certificate-related Prometheus series
// (CertificatesTotal, CertificateExpirySeconds) in lockstep with the
// certificates actually persisted in storage, and periodically re-emits an
// expiry warning to the log for any certificate approaching its NotAfter.
package certmetrics

import (
	"context"
	"log/slog"
	"time"

	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/clientca"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/metrics"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

// sweepInterval is the fixed cadence at which Sweep recomputes certificate
// metrics and re-emits expiry warnings, independent of certificate writes.
const sweepInterval = 24 * time.Hour

// Store is the subset of storage.Storage that Refresh and Sweep need.
type Store interface {
	ListCertificates() ([]*models.StoredCertificate, error)
}

// Refresh recomputes CertificatesTotal (a count per usage) and
// CertificateExpirySeconds (one series per certificate row) from every
// certificate currently in store, and returns that same list so a caller
// that also needs it (Sweep) doesn't have to read storage twice. Every
// series is replaced on each call, so a row that has since been deleted
// stops being reported rather than lingering at its last known value.
func Refresh(store Store) ([]*models.StoredCertificate, error) {
	certs, err := store.ListCertificates()
	if err != nil {
		return nil, err
	}

	metrics.CertificatesTotal.Reset()
	metrics.CertificateExpirySeconds.Reset()

	counts := make(map[string]int)
	for _, cert := range certs {
		usage := cert.Usage
		if usage == "" {
			usage = models.CertificateUsageUpstream
		}
		counts[usage]++
		metrics.CertificateExpirySeconds.WithLabelValues(cert.UUID, cert.Name).Set(float64(cert.NotAfter.Unix()))
	}
	for usage, count := range counts {
		metrics.CertificatesTotal.WithLabelValues(usage).Set(float64(count))
	}

	return certs, nil
}

// Sweep runs Refresh once immediately, then again every sweepInterval, until
// ctx is cancelled. On every run it also logs one WARN per certificate whose
// NotAfter falls within clientca.ExpiryWarningHorizon.
func Sweep(ctx context.Context, store Store, log *slog.Logger) {
	runSweep(store, log)

	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runSweep(store, log)
		}
	}
}

func runSweep(store Store, log *slog.Logger) {
	certs, err := Refresh(store)
	if err != nil {
		log.Error("Failed to refresh certificate metrics", slog.Any("error", err))
		return
	}

	now := time.Now()
	for _, cert := range certs {
		warning := clientca.ExpiryWarning(cert.NotAfter, now)
		if warning == nil {
			continue
		}
		usage := cert.Usage
		if usage == "" {
			usage = models.CertificateUsageUpstream
		}
		log.Warn("Certificate expiry warning",
			slog.String("code", warning.Code),
			slog.String("name", cert.Name),
			slog.String("usage", usage),
			slog.Time("notAfter", cert.NotAfter))
	}
}
