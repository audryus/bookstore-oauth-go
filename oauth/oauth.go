package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/federicoleon/golang-restclient/rest"
	"gitlab.com/aubayaml/aubayaml-go/bookstore/utils-go/errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-User-Id"

	paramAccessToke = "token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8081",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Token    string `json:"access_token"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

type client struct{}

type cilentInterface interface {
}

//IsPublic header
func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

//GetCallerID return caller ID, 0 if absent/error
func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	id, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

//GetClientID return client ID, 0 if absent/error
func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	id, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

//AuthenticateRequest for token
func AuthenticateRequest(request *http.Request) errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenID := strings.TrimSpace(request.URL.Query().Get(paramAccessToke))
	if accessTokenID == "" {
		return errors.UnautorizedError()
	}
	at, err := getAccessToken(accessTokenID)

	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))
	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXCallerID)
	request.Header.Del(headerXClientID)
}

//URL oauth/access/:token_id
func getAccessToken(at string) (*accessToken, errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access/%s", at))
	if response == nil || response.Response == nil {
		return nil, errors.InternalServerError("invalid rest client response when trying to get access token", errors.New("oAuth Out of Reach"))
	}
	if response.StatusCode > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, errors.InternalServerError("invalid error interface when trying to get access token", err)
		}
		return nil, restErr
	}
	var token accessToken
	if err := json.Unmarshal(response.Bytes(), &token); err != nil {
		fmt.Printf(fmt.Sprintf("%v", response))
		return nil, errors.InternalServerError("error when trying to unmarshal access token response", err)
	}
	return &token, nil
}
