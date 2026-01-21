package auth

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestAuthConfigParsing(t *testing.T) {
	yamlContent := `
gateway:
  config:
    gateway_controller:
      auth:
        basic:
          enabled: true
          users:
            - username: "admin"
              password: "password123"
              password_hashed: false
              roles: ["admin"]
`

	var authConfig DeploymentConfig
	err := yaml.Unmarshal([]byte(yamlContent), &authConfig)
	assert.NoError(t, err)

	// Verify structure traversal
	basicAuth := authConfig.Gateway.Config.GatewayController.Auth.Basic
	assert.True(t, basicAuth.Enabled)
	assert.Len(t, basicAuth.Users, 1)
	assert.Equal(t, "admin", basicAuth.Users[0].Username)
	assert.Equal(t, "password123", basicAuth.Users[0].Password)
}

func TestGetBasicAuthCredentials(t *testing.T) {
	yamlContent := `
gateway:
  config:
    gateway_controller:
      auth:
        basic:
          enabled: true
          users:
            - username: "testuser"
              password: "testpassword"
              password_hashed: false
              roles: ["admin"]
`
	var deploymentConfig DeploymentConfig
	_ = yaml.Unmarshal([]byte(yamlContent), &deploymentConfig)

	username, password, ok := GetBasicAuthCredentials(&deploymentConfig.Gateway.Config.GatewayController.Auth)
	assert.True(t, ok)
	assert.Equal(t, "testuser", username)
	assert.Equal(t, "testpassword", password)
}

func TestCalculateConfigHash(t *testing.T) {
	content1 := "some content"
	content2 := "some content"
	content3 := "different content"

	hash1 := CalculateConfigHash(content1)
	hash2 := CalculateConfigHash(content2)
	hash3 := CalculateConfigHash(content3)

	assert.Equal(t, hash1, hash2, "Same content should produce same hash")
	assert.NotEqual(t, hash1, hash3, "Different content should produce different hash")
	assert.NotEmpty(t, hash1)
}

func TestGetBasicAuthCredentials_NilConfig(t *testing.T) {
	username, password, ok := GetBasicAuthCredentials(nil)
	assert.False(t, ok)
	assert.Empty(t, username)
	assert.Empty(t, password)
}

func TestGetBasicAuthCredentials_Disabled(t *testing.T) {
	authConfig := &AuthSettings{
		Basic: BasicAuthConfig{
			Enabled: false,
			Users: []AuthUser{
				{Username: "user", Password: "pass"},
			},
		},
	}

	username, password, ok := GetBasicAuthCredentials(authConfig)
	assert.False(t, ok)
	assert.Empty(t, username)
	assert.Empty(t, password)
}

func TestGetBasicAuthCredentials_NoUsers(t *testing.T) {
	authConfig := &AuthSettings{
		Basic: BasicAuthConfig{
			Enabled: true,
			Users:   []AuthUser{},
		},
	}

	username, password, ok := GetBasicAuthCredentials(authConfig)
	assert.False(t, ok)
	assert.Empty(t, username)
	assert.Empty(t, password)
}

func TestGetBasicAuthCredentials_HashedPassword(t *testing.T) {
	authConfig := &AuthSettings{
		Basic: BasicAuthConfig{
			Enabled: true,
			Users: []AuthUser{
				{
					Username:       "user",
					Password:       "hashed_password",
					PasswordHashed: true,
				},
			},
		},
	}

	username, password, ok := GetBasicAuthCredentials(authConfig)
	assert.False(t, ok, "Should not return credentials for hashed passwords")
	assert.Empty(t, username)
	assert.Empty(t, password)
}

func TestGetDefaultBasicAuthCredentials(t *testing.T) {
	username, password := GetDefaultBasicAuthCredentials()
	assert.Equal(t, "admin", username)
	assert.Equal(t, "admin", password)
}

func TestEncodeBasicAuth(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "simple credentials",
			username: "admin",
			password: "password",
		},
		{
			name:     "credentials with special chars",
			username: "user@example.com",
			password: "p@ss:word!",
		},
		{
			name:     "empty credentials",
			username: "",
			password: "",
		},
		{
			name:     "long credentials",
			username: "verylongusernamethatexceedsnormallength",
			password: "verylongpasswordthatexceedsnormallength123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeBasicAuth(tt.username, tt.password)

			// Decode and verify
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			assert.NoError(t, err)
			expected := tt.username + ":" + tt.password
			assert.Equal(t, expected, string(decoded))
		})
	}
}

func TestEncodeBasicAuth_RoundTrip(t *testing.T) {
	username := "testuser"
	password := "testpass"

	encoded := EncodeBasicAuth(username, password)

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	assert.NoError(t, err)

	// Should be "username:password"
	assert.Equal(t, "testuser:testpass", string(decoded))
}

func TestCalculateConfigHash_EmptyString(t *testing.T) {
	hash := CalculateConfigHash("")
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64) // SHA256 produces 64 hex characters
}

func TestCalculateConfigHash_Deterministic(t *testing.T) {
	content := "test configuration content\nwith multiple lines\n"

	hash1 := CalculateConfigHash(content)
	hash2 := CalculateConfigHash(content)
	hash3 := CalculateConfigHash(content)

	assert.Equal(t, hash1, hash2)
	assert.Equal(t, hash2, hash3)
}

func TestCalculateConfigHash_SensitiveToChanges(t *testing.T) {
	content1 := "config: value1"
	content2 := "config: value2"
	content3 := "Config: value1" // Different case

	hash1 := CalculateConfigHash(content1)
	hash2 := CalculateConfigHash(content2)
	hash3 := CalculateConfigHash(content3)

	assert.NotEqual(t, hash1, hash2)
	assert.NotEqual(t, hash1, hash3)
	assert.NotEqual(t, hash2, hash3)
}

func TestDeploymentConfig_Struct(t *testing.T) {
	config := DeploymentConfig{
		Gateway: GatewayConfig{
			Config: Config{
				GatewayController: GatewayControllerConfig{
					Auth: AuthSettings{
						Basic: BasicAuthConfig{
							Enabled: true,
							Users: []AuthUser{
								{
									Username:       "admin",
									Password:       "secret",
									PasswordHashed: false,
									Roles:          []string{"admin", "user"},
								},
							},
						},
						IDP: IDPConfig{
							Enabled: true,
						},
					},
				},
			},
		},
	}

	assert.True(t, config.Gateway.Config.GatewayController.Auth.Basic.Enabled)
	assert.True(t, config.Gateway.Config.GatewayController.Auth.IDP.Enabled)
	assert.Len(t, config.Gateway.Config.GatewayController.Auth.Basic.Users, 1)
	assert.Equal(t, "admin", config.Gateway.Config.GatewayController.Auth.Basic.Users[0].Username)
	assert.Len(t, config.Gateway.Config.GatewayController.Auth.Basic.Users[0].Roles, 2)
}

func TestAuthUser_Struct(t *testing.T) {
	user := AuthUser{
		Username:       "testuser",
		Password:       "testpass",
		PasswordHashed: false,
		Roles:          []string{"admin", "operator"},
	}

	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "testpass", user.Password)
	assert.False(t, user.PasswordHashed)
	assert.Len(t, user.Roles, 2)
	assert.Contains(t, user.Roles, "admin")
	assert.Contains(t, user.Roles, "operator")
}
