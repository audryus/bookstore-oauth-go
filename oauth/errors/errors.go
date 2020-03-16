package errors

import "net/http"

//RestErr Struct
type RestErr struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
	Error   string `json:"error"`
}

//DefaultError Defautl error generator
func defaultError(message string, status int, errorDesc string) *RestErr {
	return &RestErr{
		Message: message,
		Status:  status,
		Error:   errorDesc,
	}
}

//BadRequestError error for bad request
func BadRequestError(message string) *RestErr {
	return defaultError(message, http.StatusBadRequest, "bad_request")
}

//NotFound Not found resourcer error
func NotFound(message string) *RestErr {
	return defaultError(message, http.StatusNotFound, "not_found")
}

//InternalServerError 500 error
func InternalServerError(message string) *RestErr {
	return defaultError(message, http.StatusInternalServerError, "internal_server_error")
}
