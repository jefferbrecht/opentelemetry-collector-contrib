// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clientauth // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/googleclientauthextension/internal/clientauth"

import (
	"context"
	"testing"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials/idtoken"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension"
)

type mockIDTokenSource struct {
	token string
}

func (ts *mockIDTokenSource) Token(context.Context) (*auth.Token, error) {
	return &auth.Token{
		Value: ts.token,
	}, nil
}

func TestCreateDefaultConfig(t *testing.T) {
	cfg := CreateDefaultConfig()
	assert.NotNil(t, cfg, "failed to create default config")
	assert.NoError(t, componenttest.CheckConfigStruct(cfg))
}

func TestCreateExtension(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "testdata/fake_creds.json")
	ext, err := CreateExtension(t.Context(), extension.Settings{}, CreateDefaultConfig())
	assert.NotNil(t, ext)
	assert.NoError(t, err)
}

func TestStart(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "testdata/fake_creds.json")
	ext, err := CreateExtension(t.Context(), extension.Settings{}, CreateDefaultConfig())
	assert.NotNil(t, ext)
	assert.NoError(t, err)
	err = ext.Start(t.Context(), nil)
	assert.NoError(t, err)
}

func TestStart_WithError(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "testdata/foo.json")
	ext, err := CreateExtension(t.Context(), extension.Settings{}, CreateDefaultConfig())
	assert.NotNil(t, ext)
	assert.NoError(t, err)
	err = ext.Start(t.Context(), nil)
	assert.Error(t, err)
}

func TestStart_WithNoProjectError(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "testdata/fake_creds_no_project.json")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	ext, err := CreateExtension(t.Context(), extension.Settings{}, CreateDefaultConfig())
	assert.NotNil(t, ext)
	assert.NoError(t, err)
	err = ext.Start(t.Context(), nil)
	assert.Error(t, err)
}

func TestStart_WithProjectFromEnvVar(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "testdata/fake_creds_no_project.json")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "my-project")
	ext, err := CreateExtension(t.Context(), extension.Settings{}, CreateDefaultConfig())
	assert.NotNil(t, ext)
	assert.NoError(t, err)
	err = ext.Start(t.Context(), nil)
	assert.NoError(t, err)
}

func TestStart_WithProjectOverride(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "testdata/fake_creds.json")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "my-overridden-project")
	ext, err := CreateExtension(t.Context(), extension.Settings{}, CreateDefaultConfig())
	assert.NotNil(t, ext)
	assert.NoError(t, err)
	err = ext.Start(t.Context(), nil)
	assert.NoError(t, err)
	// verify the value of the overridden project id
	ca, ok := ext.(*clientAuthenticator)
	if !ok {
		t.Fatalf("Returned extension is not of type *clientAuthenticator. Got: %T", ext)
	}
	assert.Equal(t, "my-overridden-project", ca.config.Project)
}

func TestStart_idtoken(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "testdata/fake_creds.json")
	ca := &clientAuthenticator{
		config: &Config{
			Project: "my-project",
			Scopes: []string{
				"https://www.googleapis.com/auth/cloud-platform",
				"https://www.googleapis.com/auth/logging.write",
				"https://www.googleapis.com/auth/monitoring.write",
				"https://www.googleapis.com/auth/trace.append",
			},
			TokenType: idToken,
			Audience:  "my-audience",
		},
		newIDTokenCredentials: func(opts *idtoken.Options) (*auth.Credentials, error) {
			assert.Equal(t, "my-audience", opts.Audience)

			return auth.NewCredentials(&auth.CredentialsOptions{
				TokenProvider: &mockIDTokenSource{token: "dummy token"},
			}), nil
		},
	}
	err := ca.Start(t.Context(), nil)
	assert.NoError(t, err)

	token, err := ca.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, "dummy token", token.Value)
}
