package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"github.com/go-errors/errors"
	"net/http"
	"net"
	"encoding/json"
	"os"
	"github.com/AndrewSamokhvalov/go-spew/spew"
	application "github.com/bitlum/macaroon-application-auth"
)

type Config struct {
	Host  string
	Port  string
	Token string
}

func (c *Config) validate() error {
	if c.Host == "" {
		return errors.New("bitlum host should be specified")
	}

	if c.Port == "" {
		return errors.New("bitlum port should be specified")
	}

	if c.Token == "" {
		return errors.New("bitlum token should be specified")
	}

	return nil
}

type Client struct {
	cfg    *Config
	client *http.Client
	url    string
}

func NewClient(cfg *Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &Client{
		cfg:    cfg,
		client: &http.Client{},
		url:    "http://" + net.JoinHostPort(cfg.Host, cfg.Port) + "/query",
	}, nil
}

type GraphqlResponse struct {
	Data interface{} `json:"data"`
	Errors []struct {
		Message string
		Locations []struct {
			Line   int
			Column int
		}
	}
}

type MeResp struct {
	Data struct {
		ID string
	} `json:"me"`
}

func (c *Client) Me() (*MeResp, error) {
	query := `
		query Me {
			me {
			  id
			}
		}
	`

	resp := &MeResp{}
	if err := c.doRequest(query, nil, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) doRequest(query string, variables map[string]interface{},
	r interface{}) error {

	data, err := json.Marshal(map[string]interface{}{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	bearer := fmt.Sprintf("Macaroon %v", c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", bearer)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("status code: %v", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	qlResp := &GraphqlResponse{
		Data: r,
	}

	if err := json.Unmarshal(body, qlResp); err != nil {
		return err
	}

	if qlResp.Errors != nil {
		return errors.New(qlResp.Errors[0].Message)
	}

	return nil
}

func main() {
	m, err := application.DecodeMacaroon("0201066269746c756d0204811f79090002166469736f70732069737375655f6170695f746f6b656e00020f7573657220323136363332333436350000062023ffa8c3ba9fa8a8cda6171a313fcfdfc98b52410f03685c448583cf1be01d04")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	m, err = application.AddNonce(m, 100)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	m, err = application.AddCurrentTime(m)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	token, err := application.EncodeMacaroon(m)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cfg := &Config{
		Host:  "localhost",
		Port:  "5454",
		Token: token,
	}

	client, err := NewClient(cfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	resp, err := client.Me()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	spew.Dump(resp)
}
