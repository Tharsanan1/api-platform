/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package helm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDockerConfigJSON_Struct(t *testing.T) {
	config := DockerConfigJSON{
		Auths: map[string]DockerAuthConfig{
			"https://index.docker.io/v1/": {
				Username: "user",
				Password: "pass",
				Auth:     "dXNlcjpwYXNz",
			},
		},
	}

	assert.NotNil(t, config.Auths)
	assert.Len(t, config.Auths, 1)

	auth, ok := config.Auths["https://index.docker.io/v1/"]
	assert.True(t, ok)
	assert.Equal(t, "user", auth.Username)
	assert.Equal(t, "pass", auth.Password)
	assert.Equal(t, "dXNlcjpwYXNz", auth.Auth)
}

func TestDockerAuthConfig_Struct(t *testing.T) {
	auth := DockerAuthConfig{
		Username: "testuser",
		Password: "testpassword",
		Auth:     "dGVzdHVzZXI6dGVzdHBhc3N3b3Jk",
	}

	assert.Equal(t, "testuser", auth.Username)
	assert.Equal(t, "testpassword", auth.Password)
	assert.Equal(t, "dGVzdHVzZXI6dGVzdHBhc3N3b3Jk", auth.Auth)
}

func TestDockerConfigJSON_MultipleRegistries(t *testing.T) {
	config := DockerConfigJSON{
		Auths: map[string]DockerAuthConfig{
			"https://index.docker.io/v1/": {
				Username: "dockerhub-user",
				Password: "dockerhub-pass",
			},
			"ghcr.io": {
				Username: "github-user",
				Password: "github-token",
			},
			"registry.example.com": {
				Auth: "c29tZWF1dGh0b2tlbg==",
			},
		},
	}

	assert.Len(t, config.Auths, 3)

	// Check DockerHub auth
	dockerHub := config.Auths["https://index.docker.io/v1/"]
	assert.Equal(t, "dockerhub-user", dockerHub.Username)

	// Check GitHub Container Registry auth
	ghcr := config.Auths["ghcr.io"]
	assert.Equal(t, "github-user", ghcr.Username)

	// Check private registry auth
	private := config.Auths["registry.example.com"]
	assert.Equal(t, "c29tZWF1dGh0b2tlbg==", private.Auth)
}

func TestDockerAuthConfig_EmptyFields(t *testing.T) {
	auth := DockerAuthConfig{}

	assert.Empty(t, auth.Username)
	assert.Empty(t, auth.Password)
	assert.Empty(t, auth.Auth)
}
