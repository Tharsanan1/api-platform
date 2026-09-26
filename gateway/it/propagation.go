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

package it

import (
	"net/http"
	"time"
)

// pendingPropagationContextKey holds the scenario's pendingPropagation. It
// lives in TestState.Context so TestState.Reset clears it per scenario.
const pendingPropagationContextKey = "pendingPropagation"

// clientAuthorityPoolChangedContextKey is set while this scenario has
// changed the client authority pool and no step has yet seen the gateway
// apply the change.
const clientAuthorityPoolChangedContextKey = "clientAuthorityPoolChanged"

// pendingPropagation records the API mutations the controller accepted that
// no step has yet seen reach the gateway.
type pendingPropagation struct {
	mutations    int
	lastAccepted time.Time
}

// markPropagationPending records one accepted API mutation.
func markPropagationPending(state *TestState) {
	pending, _ := currentPendingPropagation(state)
	pending.mutations++
	pending.lastAccepted = time.Now()
	state.SetContextValue(pendingPropagationContextKey, pending)
}

func currentPendingPropagation(state *TestState) (pendingPropagation, bool) {
	raw, ok := state.GetContextValue(pendingPropagationContextKey)
	if !ok {
		return pendingPropagation{}, false
	}
	pending, ok := raw.(pendingPropagation)
	return pending, ok
}

// settlePendingPropagation waits until policyPropagationDelay has passed
// since the last accepted API mutation, then forgets the pending mutations.
// With nothing pending it returns at once.
func settlePendingPropagation(state *TestState) {
	pending, ok := currentPendingPropagation(state)
	if !ok {
		return
	}
	if remaining := policyPropagationDelay - time.Since(pending.lastAccepted); remaining > 0 {
		time.Sleep(remaining)
	}
	state.DeleteContextValue(pendingPropagationContextKey)
}

// releaseObservedPropagation forgets the pending mutation once a step has
// polled its route and the policy snapshot into agreement. It releases only
// a single pending mutation: when several are pending, the route that was
// polled may belong to an earlier one, so the next gateway request still
// waits out the rest of policyPropagationDelay.
func releaseObservedPropagation(state *TestState) {
	if pending, ok := currentPendingPropagation(state); ok && pending.mutations == 1 {
		state.DeleteContextValue(pendingPropagationContextKey)
	}
}

// settlePendingPropagationBeforeGatewayRequest settles pending propagation
// before any request not addressed to the gateway controller's management
// API, which answers from the database a mutation has already committed to.
// The admin API is not exempt: its config dump reads the in-memory store,
// which converges after the mutation returns.
func settlePendingPropagationBeforeGatewayRequest(state *TestState, req *http.Request) {
	if req.URL.Hostname() == "localhost" && req.URL.Port() == GatewayControllerPort {
		return
	}
	settlePendingPropagation(state)
}

// markClientAuthorityPoolChanged records that this scenario changed the
// client authority pool.
func markClientAuthorityPoolChanged(state *TestState) {
	state.SetContextValue(clientAuthorityPoolChangedContextKey, true)
}

// clientAuthorityPoolChanged reports whether this scenario changed the client
// authority pool since the gateway was last seen to apply it.
func clientAuthorityPoolChanged(state *TestState) bool {
	changed, _ := state.GetContextValue(clientAuthorityPoolChangedContextKey)
	return changed == true
}
