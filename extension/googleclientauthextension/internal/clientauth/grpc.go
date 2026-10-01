// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clientauth // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/googleclientauthextension/internal/clientauth"

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/credentials"
)

// perRPCCredentials returns gRPC credentials using the auth.Credentials, and adds
// google metadata.
func (ca clientAuthenticator) PerRPCCredentials() (credentials.PerRPCCredentials, error) {
	if ca.Credentials == nil {
		return nil, errors.New("not started")
	}
	return ca, nil
}

// GetRequestMetadata gets the request metadata as a map from a clientAuthenticator.
// Based on metadata added by the google go client:
// https://github.com/googleapis/google-api-go-client/blob/113082d14d54f188d1b6c34c652e416592fc51b5/transport/grpc/dial.go#L224
func (ca clientAuthenticator) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	if ca.Credentials == nil {
		return nil, errors.New("not started")
	}

	ri, _ := credentials.RequestInfoFromContext(ctx)
	if err := credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
		return nil, fmt.Errorf("unable to transfer credentials PerRPCCredentials: %w", err)
	}

	token, err := ca.Token(ctx)
	if err != nil {
		return nil, err
	}

	tokenType := token.Type
	if tokenType == "" {
		tokenType = "Bearer"
	}
	metadata := map[string]string{
		"authorization": fmt.Sprintf("%s %s", tokenType, token.Value),
	}

	// Attach system parameters
	if ca.config.QuotaProject != "" {
		metadata["X-goog-user-project"] = ca.config.QuotaProject
	}
	if ca.config.Project != "" {
		metadata["X-goog-project-id"] = ca.config.Project
	}
	return metadata, nil
}

func (clientAuthenticator) RequireTransportSecurity() bool {
	return true
}
