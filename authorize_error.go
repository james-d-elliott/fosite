// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ory/fosite/token/jarm"
)

func (f *Fosite) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, ar AuthorizeRequester, err error) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	rfcerr := ErrorToRFC6749Error(err).WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx)).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(ar))
	if !ar.IsRedirectURIValid() {
		f.handleWriteAuthorizeErrorJSON(ctx, rw, rfcerr)

		return
	}

	errors := rfcerr.ToValues()
	errors.Set("state", ar.GetState())

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
	)

	switch rm {
	case ResponseModeFormPost, ResponseModeJWTFormPost:
		//form_post
		if parameters, err = getParameters(ctx, f.Config, ar.GetClient(), ar.GetSession(), errors); err != nil {
			f.handleWriteAuthorizeErrorJSON(ctx, rw, ErrorToRFC6749Error(err))

			return
		}

		rw.Header().Add("Content-Type", "text/html;charset=UTF-8")

		WriteAuthorizeFormPostResponse(redir.String(), parameters, GetPostFormHTMLTemplate(ctx, f), rw)
	case ResponseModeQuery, ResponseModeJWTQuery, ResponseModeDefault:
		// Explicit grants
		if parameters, err = getParameters(ctx, f.Config, ar.GetClient(), ar.GetSession(), errors); err != nil {
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
		if parameters, err = getParameters(ctx, f.Config, ar.GetClient(), ar.GetSession(), errors); err != nil {
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
		if f.ResponseModeHandler(ctx).ResponseModes().Has(ar.GetResponseMode()) {
			f.ResponseModeHandler(ctx).WriteAuthorizeError(ctx, rw, ar, err)
			return
		}
	}
}

func (f *Fosite) handleWriteAuthorizeErrorJSON(ctx context.Context, rw http.ResponseWriter, rfcerr *RFC6749Error) {
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

	js, err := json.Marshal(rfcerr)
	if err != nil {
		if f.Config.GetSendDebugMessagesToClients(ctx) {
			errorMessage := EscapeJSONString(err.Error())
			http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
		} else {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
		}
		return
	}

	rw.WriteHeader(rfcerr.CodeField)
	_, _ = rw.Write(js)
	return
}
