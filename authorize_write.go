// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"github.com/ory/fosite/token/jarm"
	"net/http"
	"net/url"
)

func (f *Fosite) WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, ar AuthorizeRequester, resp AuthorizeResponder) {
	// Set custom headers, e.g. "X-MySuperCoolCustomHeader" or "X-DONT-CACHE-ME"...
	wh := rw.Header()
	rh := resp.GetHeader()
	for k := range rh {
		wh.Set(k, rh.Get(k))
	}

	wh.Set("Cache-Control", "no-store")
	wh.Set("Pragma", "no-cache")

	redir := ar.GetRedirectURI()

	rm := ar.GetResponseMode()

	var getParameters getAuthorizeResponseParams

	switch rm {
	case ResponseModeJWT:
		if ar.GetResponseTypes().ExactOne("code") {
			rm = ResponseModeJWTQuery
		} else {
			rm = ResponseModeJWTFragment
		}

		fallthrough
	case ResponseModeJWTFormPost, ResponseModeJWTQuery, ResponseModeJWTFragment:
		getParameters = jarm.GenerateParameters
	default:
		getParameters = func(_ context.Context, _ jarm.Configurator, _ jarm.Client, _ any, params url.Values) (parameters url.Values, err error) {
			return params, nil
		}
	}

	var (
		parameters url.Values
		err        error
	)

	switch rm {
	case ResponseModeFormPost, ResponseModeJWTFormPost:
		//form_post
		if parameters, err = getParameters(ctx, f.Config, ar.GetClient(), ar.GetSession(), resp.GetParameters()); err != nil {
			f.handleWriteAuthorizeErrorJSON(ctx, rw, ErrServerError.WithWrap(err).WithDebug(err.Error()))

			return
		}

		rw.Header().Add("Content-Type", "text/html;charset=UTF-8")

		WriteAuthorizeFormPostResponse(redir.String(), parameters, GetPostFormHTMLTemplate(ctx, f), rw)
	case ResponseModeQuery, ResponseModeJWTQuery, ResponseModeDefault:
		// Explicit grants
		if parameters, err = getParameters(ctx, f.Config, ar.GetClient(), ar.GetSession(), resp.GetParameters()); err != nil {
			f.handleWriteAuthorizeErrorJSON(ctx, rw, ErrServerError.WithWrap(err).WithDebug(err.Error()))

			return
		}

		q := redir.Query()

		for k := range parameters {
			q.Set(k, parameters.Get(k))
		}

		redir.RawQuery = q.Encode()

		sendRedirect(redir.String(), rw)
	case ResponseModeFragment, ResponseModeJWTFragment:
		// Implicit grants
		// The endpoint URI MUST NOT include a fragment component.
		if parameters, err = getParameters(ctx, f.Config, ar.GetClient(), ar.GetSession(), resp.GetParameters()); err != nil {
			f.handleWriteAuthorizeErrorJSON(ctx, rw, ErrServerError.WithWrap(err).WithDebug(err.Error()))

			return
		}

		redir.Fragment = ""

		u := redir.String()

		if len(parameters) > 0 {
			u = u + "#" + parameters.Encode()
		}

		sendRedirect(u, rw)
	default:
		if f.ResponseModeHandler(ctx).ResponseModes().Has(rm) {
			f.ResponseModeHandler(ctx).WriteAuthorizeResponse(ctx, rw, ar, resp)
		}
	}
}

type getAuthorizeResponseParams func(ctx context.Context, config jarm.Configurator, client jarm.Client, session any, params url.Values) (parameters url.Values, err error)

// https://tools.ietf.org/html/rfc6749#section-4.1.1
// When a decision is established, the authorization server directs the
// user-agent to the provided client redirection URI using an HTTP
// redirection response, or by other means available to it via the
// user-agent.
func sendRedirect(url string, rw http.ResponseWriter) {
	rw.Header().Set("Location", url)
	rw.WriteHeader(http.StatusSeeOther)
}
