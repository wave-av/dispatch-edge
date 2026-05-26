// Package dispatch is the Go client for wave Dispatch — route each request to the cheapest capable
// model (local-first, escalate to your frontier model only when needed). Your keys + infra stay yours;
// the API returns a routing decision (and, if your plan enables it, the edge-local answer).
package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DefaultEndpoint is the hosted wave Dispatch edge.
const DefaultEndpoint = "https://dispatch.wave.online"

// Client calls the wave Dispatch edge API.
type Client struct {
	Endpoint string       // defaults to DefaultEndpoint
	License  string       // Bearer license key (wv_...); empty = x402 pay-per-use
	HTTP     *http.Client // defaults to a 30s client
}

// New returns a Client for the hosted edge with the given license key.
func New(license string) *Client {
	return &Client{Endpoint: DefaultEndpoint, License: license, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// Decision is the routing result.
type Decision struct {
	Route       string  `json:"route"`
	Probability float64 `json:"probability"`
	Margin      float64 `json:"margin"`
	DecidedAt   string  `json:"decided_at"`
	Forward     bool    `json:"forward"`              // true => escalate to your frontier model
	Answer      string  `json:"answer,omitempty"`     // present when Execute is requested + enabled
	ExecutedBy  string  `json:"executed_by,omitempty"`
	Tier        string  `json:"tier,omitempty"`
}

// Route classifies a prompt (no execution).
func (c *Client) Route(ctx context.Context, prompt string) (*Decision, error) {
	return c.post(ctx, map[string]any{"prompt": prompt})
}

// Execute classifies and runs the request on the edge if your plan allows it.
func (c *Client) Execute(ctx context.Context, prompt string) (*Decision, error) {
	return c.post(ctx, map[string]any{"prompt": prompt, "execute": true})
}

// RouteVector classifies a pre-computed 768-d embedding (matmul-only — cheapest + fastest path).
func (c *Client) RouteVector(ctx context.Context, vec []float64) (*Decision, error) {
	return c.post(ctx, map[string]any{"vector": vec})
}

func (c *Client) post(ctx context.Context, body map[string]any) (*Decision, error) {
	ep := c.Endpoint
	if ep == "" {
		ep = DefaultEndpoint
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep+"/", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	if c.License != "" {
		req.Header.Set("authorization", "Bearer "+c.License)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusPaymentRequired {
		return nil, fmt.Errorf("dispatch: 402 payment required (x402) — pay and retry, or set a license")
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return nil, fmt.Errorf("dispatch: status %d: %s", resp.StatusCode, e.Error)
	}
	var d Decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}
