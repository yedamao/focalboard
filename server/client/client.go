package client

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/mattermost/focalboard/server/api"
	"github.com/mattermost/focalboard/server/model"
)

const (
	APIURLSuffix = "/api/v1"
)

type RequestReaderError struct {
	buf []byte
}

func (rre RequestReaderError) Error() string {
	return "payload: " + string(rre.buf)
}

type Response struct {
	StatusCode int
	Error      error
	Header     http.Header
}

func BuildResponse(r *http.Response) *Response {
	return &Response{
		StatusCode: r.StatusCode,
		Header:     r.Header,
	}
}

func BuildErrorResponse(r *http.Response, err error) *Response {
	statusCode := 0
	header := make(http.Header)
	if r != nil {
		statusCode = r.StatusCode
		header = r.Header
	}

	return &Response{
		StatusCode: statusCode,
		Error:      err,
		Header:     header,
	}
}

func closeBody(r *http.Response) {
	if r.Body != nil {
		_, _ = io.Copy(ioutil.Discard, r.Body)
		_ = r.Body.Close()
	}
}

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

type Client struct {
	URL        string
	APIURL     string
	HTTPClient *http.Client
	HTTPHeader map[string]string
	// Token if token is empty indicate client is not login yet
	Token string
}

func NewClient(url, sessionToken string) *Client {
	url = strings.TrimRight(url, "/")

	headers := map[string]string{
		"X-Requested-With": "XMLHttpRequest",
	}

	return &Client{url, url + APIURLSuffix, &http.Client{}, headers, sessionToken}
}

func (c *Client) DoAPIGet(url, etag string) (*http.Response, error) {
	return c.DoAPIRequest(http.MethodGet, c.APIURL+url, "", etag)
}

func (c *Client) DoAPIPost(url, data string) (*http.Response, error) {
	return c.DoAPIRequest(http.MethodPost, c.APIURL+url, data, "")
}

func (c *Client) DoAPIPut(url, data string) (*http.Response, error) {
	return c.DoAPIRequest(http.MethodPut, c.APIURL+url, data, "")
}

func (c *Client) DoAPIDelete(url string) (*http.Response, error) {
	return c.DoAPIRequest(http.MethodDelete, c.APIURL+url, "", "")
}

func (c *Client) DoAPIRequest(method, url, data, etag string) (*http.Response, error) {
	return c.doAPIRequestReader(method, url, strings.NewReader(data), etag)
}

func (c *Client) doAPIRequestReader(method, url string, data io.Reader, _ /* etag */ string) (*http.Response, error) {
	rq, err := http.NewRequest(method, url, data)
	if err != nil {
		return nil, err
	}

	if c.HTTPHeader != nil && len(c.HTTPHeader) > 0 {
		for k, v := range c.HTTPHeader {
			rq.Header.Set(k, v)
		}
	}

	if c.Token != "" {
		rq.Header.Set("Authorization", "Bearer "+c.Token)
	}

	rp, err := c.HTTPClient.Do(rq)
	if err != nil || rp == nil {
		return nil, err
	}

	if rp.StatusCode == http.StatusNotModified {
		return rp, nil
	}

	if rp.StatusCode >= http.StatusMultipleChoices {
		defer closeBody(rp)
		b, err := ioutil.ReadAll(rp.Body)
		if err != nil {
			return rp, fmt.Errorf("error when parsing response with code %d: %w", rp.StatusCode, err)
		}
		return rp, RequestReaderError{b}
	}

	return rp, nil
}

func (c *Client) GetBlocksRoute() string {
	return "/workspaces/0/blocks"
}

func (c *Client) GetBlockRoute(id string) string {
	return fmt.Sprintf("%s/%s", c.GetBlocksRoute(), id)
}

func (c *Client) GetSubtreeRoute(id string) string {
	return fmt.Sprintf("%s/subtree", c.GetBlockRoute(id))
}

func (c *Client) GetBlocks() ([]model.Block, *Response) {
	r, err := c.DoAPIGet(c.GetBlocksRoute(), "")
	if err != nil {
		return nil, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	return model.BlocksFromJSON(r.Body), BuildResponse(r)
}

func (c *Client) InsertBlocks(blocks []model.Block) (bool, *Response) {
	r, err := c.DoAPIPost(c.GetBlocksRoute(), toJSON(blocks))
	if err != nil {
		return false, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	return true, BuildResponse(r)
}

func (c *Client) DeleteBlock(blockID string) (bool, *Response) {
	r, err := c.DoAPIDelete(c.GetBlockRoute(blockID))
	if err != nil {
		return false, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	return true, BuildResponse(r)
}

func (c *Client) GetSubtree(blockID string) ([]model.Block, *Response) {
	r, err := c.DoAPIGet(c.GetSubtreeRoute(blockID), "")
	if err != nil {
		return nil, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	return model.BlocksFromJSON(r.Body), BuildResponse(r)
}

// Sharing

func (c *Client) GetSharingRoute(rootID string) string {
	return fmt.Sprintf("/workspaces/0/sharing/%s", rootID)
}

func (c *Client) GetSharing(rootID string) (*model.Sharing, *Response) {
	r, err := c.DoAPIGet(c.GetSharingRoute(rootID), "")
	if err != nil {
		return nil, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	sharing := model.SharingFromJSON(r.Body)
	return &sharing, BuildResponse(r)
}

func (c *Client) PostSharing(sharing model.Sharing) (bool, *Response) {
	r, err := c.DoAPIPost(c.GetSharingRoute(sharing.ID), toJSON(sharing))
	if err != nil {
		return false, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	return true, BuildResponse(r)
}

func (c *Client) GetRegisterRoute() string {
	return "/register"
}

func (c *Client) Register(request *api.RegisterRequest) (bool, *Response) {
	r, err := c.DoAPIPost(c.GetRegisterRoute(), toJSON(&request))
	if err != nil {
		return false, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	return true, BuildResponse(r)
}

func (c *Client) GetLoginRoute() string {
	return "/login"
}

func (c *Client) Login(request *api.LoginRequest) (*api.LoginResponse, *Response) {
	r, err := c.DoAPIPost(c.GetLoginRoute(), toJSON(&request))
	if err != nil {
		return nil, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	data, err := api.LoginResponseFromJson(r.Body)
	if err != nil {
		return nil, BuildErrorResponse(r, err)
	}

	if data.Token != "" {
		c.Token = data.Token
	}

	return data, BuildResponse(r)
}

func (c *Client) GetUserMeRoute() string {
	return fmt.Sprintf("/users/me")
}

func (c *Client) GetUserMe() (*model.User, *Response) {
	r, err := c.DoAPIGet(c.GetUserMeRoute(), "")
	if err != nil {
		return nil, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	me, err := model.UserFromJSON(r.Body)
	if err != nil {
		return nil, BuildErrorResponse(r, err)
	}
	return me, BuildResponse(r)
}

func (c *Client) GetUserRoute(id string) string {
	return fmt.Sprintf("/users/%s", id)
}

func (c *Client) GetUser(id string) (*model.User, *Response) {
	r, err := c.DoAPIGet(c.GetUserRoute(id), "")
	if err != nil {
		return nil, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	user, err := model.UserFromJSON(r.Body)
	if err != nil {
		return nil, BuildErrorResponse(r, err)
	}
	return user, BuildResponse(r)
}

func (c *Client) GetUserChangePasswordRoute(id string) string {
	return fmt.Sprintf("/users/%s/changepassword", id)
}

func (c *Client) UserChangePassword(id string, data *api.ChangePasswordRequest) (bool, *Response) {
	r, err := c.DoAPIPost(c.GetUserChangePasswordRoute(id), toJSON(&data))
	if err != nil {
		return false, BuildErrorResponse(r, err)
	}
	defer closeBody(r)

	return true, BuildResponse(r)
}
