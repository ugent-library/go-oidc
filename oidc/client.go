package oidc

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	URL          string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type Client struct {
	oauthClient   *oauth2.Config
	tokenVerifier *oidc.IDTokenVerifier
}

// TODO make scopes configurable
func New(c Config) (*Client, error) {
	oidcProvider, err := oidc.NewProvider(context.Background(), c.URL)
	if err != nil {
		return nil, err
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauthClient := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Endpoint:     oidcProvider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "phone", "address"},
	}

	tokenVerifier := oidcProvider.Verifier(&oidc.Config{ClientID: c.ClientID})

	client := &Client{
		oauthClient:   oauthClient,
		tokenVerifier: tokenVerifier,
	}

	return client, nil
}

// TODO add state param for CSRF protection https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
func (c *Client) AuthorizationURL() string {
	return c.oauthClient.AuthCodeURL("")
}

func (c *Client) Exchange(code string, profile interface{}) error {
	ctx := context.Background()
	oauthToken, err := c.oauthClient.Exchange(ctx, code)
	if err != nil {
		return err
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		// handle missing token
		return errors.New("id token missing")
	}

	// Parse and verify ID Token payload.
	idToken, err := c.tokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return err
	}

	return idToken.Claims(&profile)
}
