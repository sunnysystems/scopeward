package ghclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// GraphQLError is one error entry returned by the GraphQL API.
type GraphQLError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// GraphQL executes a read-only GraphQL query, decoding the "data" field into
// out. Query-level errors (e.g. insufficient permissions) are returned so
// collectors can downgrade coverage instead of failing.
func (c *Client) GraphQL(ctx context.Context, query string, vars map[string]any, out any) error {
	reqBody, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/graphql", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token.Expose())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("calling GitHub GraphQL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Status: resp.Status, Message: decodeErrorMessage(resp.Body)}
	}

	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []GraphQLError  `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("decoding GraphQL response: %w", err)
	}
	if len(envelope.Errors) > 0 {
		return fmt.Errorf("graphql: %s", envelope.Errors[0].Message)
	}
	if out != nil && len(envelope.Data) > 0 {
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return fmt.Errorf("decoding GraphQL data: %w", err)
		}
	}
	return nil
}
