package oidc

type Profile struct {
	Email                    string `json:"email"`
	EmailVerified            bool   `json:"email_verified"`
	Name                     string `json:"name"`
	FamilyName               string `json:"family_name"`
	GivenName                string `json:"given_name"`
	PreferredUsername        string `json:"preferred_username"`
	IdentityProvider         string `json:"identity_provider"`
	IdentityProviderIdentity string `json:"identity_provider_identity"`
}
