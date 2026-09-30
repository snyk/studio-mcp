/*
 * © 2023-2024 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package authentication

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/errorcodes"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
)

type ActiveUser struct {
	Id       string `json:"id"`
	UserName string `json:"username,omitempty"`
	Name     string `json:"name,omitempty"`
	Orgs     []struct {
		Name  string `json:"name,omitempty"`
		Id    string `json:"id,omitempty"`
		Group struct {
			Name string `json:"name,omitempty"`
			Id   string `json:"id,omitempty"`
		} `json:"group,omitempty"`
	} `json:"orgs,omitempty"`
}

func CallWhoAmI(logger *zerolog.Logger, engine workflow.Engine) (*ActiveUser, error) {
	globalConf := engine.GetConfiguration()
	conf := globalConf.Clone()
	logger.Trace().Str("method", "CallWhoAmI").
		Str("configInstance", fmt.Sprintf("%p", globalConf)).
		Str("configClone", fmt.Sprintf("%p", conf)).
		Msg("invoking whoami workflow")
	conf.Set(configuration.FLAG_EXPERIMENTAL, true)
	conf.Set("json", true)
	result, err := engine.InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, conf)

	if err != nil {
		return nil, errors.Wrap(err, "failed to invoke whoami workflow")
	}
	if len(result) == 0 {
		return nil, errors.New("no user data found")
	}

	payload := result[0].GetPayload()

	if payload == nil {
		return nil, errors.New("no payload found")
	}

	payloadBytes, ok := payload.([]byte)
	if !ok {
		return nil, errors.New("payload is not a byte array")
	}

	var user ActiveUser
	err = json.Unmarshal(payloadBytes, &user)
	if err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal user data")
	}

	return &user, nil
}

// IsAuthError reports whether err means Snyk refused the credentials (or there
// were none), as opposed to giving no verdict at all: a network failure, a
// timeout, a 5xx. GAF's response middleware turns a 401 into the error
// catalog's Unauthorised error, so this checks that type, not the message.
//
// It does not match on "auth" in the message: every failed OAuth refresh,
// network failures included, carries GAF's "authentication failed".
func IsAuthError(err error) bool {
	var snykErr snyk_errors.Error
	if !errors.As(err, &snykErr) {
		return false
	}
	if snykErr.ErrorCode == errorcodes.Snyk.UnauthorisedError || snykErr.StatusCode == http.StatusUnauthorized {
		return true
	}
	// An expired or revoked OAuth refresh token: Snyk's token endpoint answers
	// 400 invalid_grant, which reaches here as a BadRequest joined with GAF's
	// ErrAuthenticationFailed rather than as Unauthorised.
	return snykErr.StatusCode == http.StatusBadRequest && errors.Is(err, middleware.ErrAuthenticationFailed)
}
