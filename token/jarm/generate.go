package jarm

import (
	"context"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/ory/fosite/token/jwt"
)

type Configurator interface {
	GetJWTSecuredAuthorizeResponseModeLifespan(ctx context.Context) time.Duration
	GetJWTSecuredAuthorizeResponseModeSigner(ctx context.Context) jwt.Signer
	GetJWTSecuredAuthorizeResponseModeIssuer(ctx context.Context) string
}

type IDTokenSession interface {
	IDTokenHeaders() *jwt.Headers
	IDTokenClaims() *jwt.IDTokenClaims
}

type JWTSessionContainer interface {
	GetJWTHeader() *jwt.Headers
	GetJWTClaims() jwt.JWTClaimsContainer
}

type Client interface {
	GetID() string
}

// GenerateParameters is a helper function to call GenerateTokenFromParameters wrapped in GenerateTokenToResponseParameters for token responses.
func GenerateParameters(ctx context.Context, config Configurator, client Client, session any, params url.Values) (parameters url.Values, err error) {
	return GenerateTokenToResponseParameters(GenerateTokenFromParameters(ctx, config, client, session, params))
}

// GenerateTokenToResponseParameters takes the result from GenerateTokenFromParameters and turns it into parameters in the form of url.Values.
func GenerateTokenToResponseParameters(token, signature string, tErr error) (parameters url.Values, err error) {
	if tErr != nil {
		return nil, tErr
	}

	return url.Values{"response": []string{token}}, nil
}

func GenerateTokenFromParameters(ctx context.Context, config Configurator, client Client, session any, params url.Values) (token, signature string, err error) {
	var (
		headers jwt.Mapper
		src     jwt.MapClaims
	)

	switch s := session.(type) {
	case IDTokenSession:
		headers = s.IDTokenHeaders()
		src = s.IDTokenClaims().ToMapClaims()
	case JWTSessionContainer:
		headers = s.GetJWTHeader()
		src = s.GetJWTClaims().ToMapClaims()
	case nil:
		return "", "", errors.New("The JARM response modes require the Authorize Requester session to be set but it wasn't.")
	default:
		return "", "", errors.New("The JARM response modes require the Authorize Requester session to implement either the openid.Session or oauth2.JWTSessionContainer interfaces but it doesn't.")
	}

	var (
		issuer string
		ok     bool
		value  any
	)

	if value, ok = src["iss"]; ok {
		issuer, _ = value.(string)
	}

	if len(issuer) <= 0 {
		issuer = config.GetJWTSecuredAuthorizeResponseModeIssuer(ctx)
	}

	claims := &jwt.JARMClaims{
		JTI:       uuid.New().String(),
		Issuer:    issuer,
		Audience:  []string{client.GetID()},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(config.GetJWTSecuredAuthorizeResponseModeLifespan(ctx)),
	}

	for param := range params {
		claims.Extra[param] = params.Get(param)
	}

	var signer jwt.Signer

	if signer = config.GetJWTSecuredAuthorizeResponseModeSigner(ctx); signer == nil {
		return "", "", errors.New("The JARM response modes require the JWTSecuredAuthorizeResponseModeSignerProvider to return a jwt.Signer but it didn't.")
	}

	return signer.Generate(ctx, claims.ToMapClaims(), headers)
}
