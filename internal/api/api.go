package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Program struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Status            ProgramStatus     `json:"status"`
	Configuration     ProgramConfiguration `json:"configuration"`
	RulesOfEngagement RulesOfEngagement `json:"rulesOfEngagement"`
	Domains           DomainsWrapper    `json:"domains"`
}

type RulesOfEngagement struct {
	Content RulesOfEngagementContent `json:"content"`
}

type RulesOfEngagementContent struct {
	TestingRequirements TestingRequirements `json:"testingRequirements"`
}

type TestingRequirements struct {
	MaxRPS uint `json:"automatedTooling"`
}

type DomainsWrapper struct {
	Value   []Scope `json:"value"`
	Items   []Scope `json:"items"`
	Content []Scope `json:"content"`
}

func (dw DomainsWrapper) GetScopes() []Scope {
	if len(dw.Value) > 0 {
		return dw.Value
	}
	if len(dw.Items) > 0 {
		return dw.Items
	}
	return dw.Content
}

type ProgramStatus struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
}

type ProgramConfiguration struct {
	MaxRPS        uint           `json:"maxRequestsPerSecond"`
	CustomHeaders []CustomHeader `json:"customHeaders"`
}

type CustomHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type AssetType struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
}

type Tier struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
}

type Scope struct {
	ID          string    `json:"id"`
	Type        AssetType `json:"type"`
	Tier        Tier      `json:"tier"`
	Endpoint    string    `json:"endpoint"`
	Description *string   `json:"description"`
	IsInScope   bool      `json:"isInScope"`
}

type IntigritiClient struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

func NewIntigritiClient(token string, baseURL string) *IntigritiClient {
	if baseURL == "" {
		baseURL = "https://api.intigriti.com/external/researcher/v1"
	}
	return &IntigritiClient{
		httpClient: &http.Client{},
		baseURL:    baseURL,
		token:      token,
	}
}

func (c *IntigritiClient) get(path string, target interface{}) error {
	url := fmt.Sprintf("%s%s", c.baseURL, path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Puts it back for your app
	println(string(bodyBytes))

	return json.NewDecoder(resp.Body).Decode(target)
}

func (c *IntigritiClient) GetProgram(programID string) (*Program, error) {
	var program Program
	err := c.get(fmt.Sprintf("/programs/%s", programID), &program)
	return &program, err
}
