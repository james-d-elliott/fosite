package jwt

import (
	"github.com/google/uuid"
	"time"
)

// JARMClaims represent a token's claims.
type JARMClaims struct {
	Issuer    string
	Audience  []string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Extra     map[string]interface{}
}

// ToMap will transform the headers to a map structure
func (c *JARMClaims) ToMap() map[string]interface{} {
	var ret = Copy(c.Extra)

	if c.Issuer != "" {
		ret["iss"] = c.Issuer
	} else {
		delete(ret, "iss")
	}

	if c.JTI != "" {
		ret["jti"] = c.JTI
	} else {
		ret["jti"] = uuid.New().String()
	}

	if len(c.Audience) > 0 {
		ret["aud"] = c.Audience
	} else {
		ret["aud"] = []string{}
	}

	if !c.IssuedAt.IsZero() {
		ret["iat"] = c.IssuedAt.Unix()
	} else {
		delete(ret, "iat")
	}

	if !c.ExpiresAt.IsZero() {
		ret["exp"] = c.ExpiresAt.Unix()
	} else {
		delete(ret, "exp")
	}

	return ret
}

// FromMap will set the claims based on a mapping
func (c *JARMClaims) FromMap(m map[string]interface{}) {
	c.Extra = make(map[string]interface{})
	for k, v := range m {
		switch k {
		case "jti":
			if s, ok := v.(string); ok {
				c.JTI = s
			}
		case "iss":
			if s, ok := v.(string); ok {
				c.Issuer = s
			}
		case "aud":
			if s, ok := v.(string); ok {
				c.Audience = []string{s}
			} else if s, ok := v.([]string); ok {
				c.Audience = s
			}
		case "iat":
			c.IssuedAt = toTime(v, c.IssuedAt)
		case "exp":
			c.ExpiresAt = toTime(v, c.ExpiresAt)
		default:
			c.Extra[k] = v
		}
	}
}

// Add will add a key-value pair to the extra field
func (c *JARMClaims) Add(key string, value interface{}) {
	if c.Extra == nil {
		c.Extra = make(map[string]interface{})
	}
	c.Extra[key] = value
}

// Get will get a value from the extra field based on a given key
func (c JARMClaims) Get(key string) interface{} {
	return c.ToMap()[key]
}

// ToMapClaims will return a jwt-go MapClaims representation
func (c JARMClaims) ToMapClaims() MapClaims {
	return c.ToMap()
}

// FromMapClaims will populate claims from a jwt-go MapClaims representation
func (c *JARMClaims) FromMapClaims(mc MapClaims) {
	c.FromMap(mc)
}
