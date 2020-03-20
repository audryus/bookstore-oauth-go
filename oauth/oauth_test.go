package oauth

import (
	"net/http"
	"os"
	"testing"

	"github.com/federicoleon/golang-restclient/rest"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	rest.StartMockupServer()
	os.Exit(m.Run())
}

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-Id", headerXClientID)
	assert.EqualValues(t, "X-User-Id", headerXCallerID)
	assert.EqualValues(t, "token", paramAccessToke)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil))
}

func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.False(t, IsPublic(&request))

	request.Header.Add("X-Public", "true")
	assert.True(t, IsPublic(&request))
}
func TestGetCallerIDNilRequest(t *testing.T) {
	assert.EqualValues(t, 0, GetCallerID(nil))
}
func TestGetCallerIDInvalid(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-User-Id", "true")
	assert.EqualValues(t, 0, GetCallerID(&request))
}
func TestGetCallerID(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-User-Id", "1")
	assert.EqualValues(t, 1, GetCallerID(&request))
}

func TestGetAccessTokenInvalidRestClientResponse(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8081/oauth/access/abc123",
		ReqBody:      ``,
		RespHTTPCode: -1,
		RespBody:     `{} `,
	})

	accessToken, err := getAccessToken("abc123")

	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status())
	assert.EqualValues(t, "invalid rest client response when trying to get access token", err.Message())
}
