// Package antiscamai provides AI-powered request inspection middleware
// for any Go HTTP server (net/http, chi, gin, echo, fiber, etc.).
//
// Quick start:
//
//	import "github.com/nebulamatch/antiscamai-sdk-go"
//
//	mux := http.NewServeMux()
//	handler := antiscamai.NewMiddleware(antiscamai.Config{
//	    APIKey: "YOUR_KEY",
//	}).Handler(mux)
//	http.ListenAndServe(":8080", handler)
package antiscamai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ─── Config ───────────────────────────────────────────────────────────────────

// Config holds all SDK configuration.
type Config struct {
	// APIKey is your SDK API key (required).
	APIKey string

	// Endpoint is the base URL of your AntiScam AI instance.
	// Default: "http://localhost:5000"
	Endpoint string

	// Mode controls how threats are handled.
	//  "block"   – requests scoring ≥65 are blocked (default)
	//  "flag"    – requests scoring ≥40 are flagged but allowed
	//  "monitor" – all requests allowed; threats are only logged
	Mode string

	// TimeoutMs is the max milliseconds to wait for AI (default: 3000).
	TimeoutMs int

	// OnError controls what happens when the AI service is unreachable.
	//  "allow" – fail-open  (default)
	//  "block" – fail-closed
	OnError string

	// ExcludePaths are URL prefixes to skip entirely.
	// Default: ["/health", "/metrics", "/favicon.ico"]
	ExcludePaths []string

	// InspectMethods are HTTP methods to inspect.
	// Default: ["POST", "PUT", "PATCH"]
	InspectMethods []string

	// OnThreat is an optional callback invoked on every detected threat.
	OnThreat func(ThreatEvent)
}

func (c *Config) withDefaults() {
	if c.Endpoint == "" {
		c.Endpoint = "http://localhost:5000"
	}
	if c.Mode == "" {
		c.Mode = "block"
	}
	if c.TimeoutMs == 0 {
		c.TimeoutMs = 3000
	}
	if c.OnError == "" {
		c.OnError = "allow"
	}
	if len(c.ExcludePaths) == 0 {
		c.ExcludePaths = []string{"/health", "/metrics", "/favicon.ico"}
	}
	if len(c.InspectMethods) == 0 {
		c.InspectMethods = []string{"POST", "PUT", "PATCH"}
	}
}

// ─── Models ───────────────────────────────────────────────────────────────────

// InspectRequest is the payload sent to the AntiScam AI gateway.
type InspectRequest struct {
	BodyText      string            `json:"bodyText,omitempty"`
	BodyRaw       string            `json:"bodyRaw,omitempty"`
	ExtractedURLs []string          `json:"extractedUrls,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	SourceIP      string            `json:"sourceIp,omitempty"`
	Endpoint      string            `json:"endpoint,omitempty"`
	Method        string            `json:"method,omitempty"`
	UserID        string            `json:"userId,omitempty"`
	Mode          string            `json:"mode,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// ThreatDetail describes a single detected threat.
type ThreatDetail struct {
	Type        string  `json:"type"`
	Category    string  `json:"category"`
	Score       float64 `json:"score"`
	Confidence  float64 `json:"confidence"`
	Explanation string  `json:"explanation"`
}

// InspectResponse is the AI gateway's verdict.
type InspectResponse struct {
	RequestID   string         `json:"requestId"`
	ThreatScore float64        `json:"threatScore"`
	RiskLevel   string         `json:"riskLevel"`
	Decision    string         `json:"decision"` // allow | flag | block
	ShouldBlock bool           `json:"shouldBlock"`
	Threats     []ThreatDetail `json:"threats"`
	ProcessedAt string         `json:"processedAt"`
	ModelVersion string        `json:"modelVersion"`
}

// ThreatEvent is passed to the OnThreat callback.
type ThreatEvent struct {
	RequestID  string
	Score      float64
	RiskLevel  string
	Decision   string
	Threats    []ThreatDetail
	Endpoint   string
	SourceIP   string
}

// ─── Middleware ───────────────────────────────────────────────────────────────

// Middleware is the AntiScam AI HTTP middleware.
type Middleware struct {
	cfg    Config
	client *http.Client
	urlRe  *regexp.Regexp
}

// NewMiddleware creates a new middleware instance.
func NewMiddleware(cfg Config) *Middleware {
	cfg.withDefaults()
	if cfg.APIKey == "" {
		panic("[AntiScamAI] APIKey is required")
	}
	return &Middleware{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
		},
		urlRe: regexp.MustCompile(`(?i)https?://[^\s"'\]\)>]+`),
	}
}

// Handler wraps any http.Handler with AntiScam AI inspection.
//
//	handler := antiscamai.NewMiddleware(cfg).Handler(mux)
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := strings.ToUpper(r.Method)

		// Skip excluded paths or non-inspectable methods
		if m.shouldSkip(r.URL.Path, method) {
			next.ServeHTTP(w, r)
			return
		}

		// Read + restore body
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
		if err != nil {
			log.Printf("[AntiScamAI] body read error: %v", err)
			next.ServeHTTP(w, r)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		text, urls := m.extractContent(bodyBytes)

		safeHeaders := m.safeHeaders(r)

		result := m.call(InspectRequest{
			BodyText:      truncate(text, 4000),
			ExtractedURLs: urls[:min(len(urls), 10)],
			Headers:       safeHeaders,
			SourceIP:      realIP(r),
			Endpoint:      fmt.Sprintf("%s %s", method, r.URL.Path),
			Method:        method,
			UserID:        r.Header.Get("X-User-ID"),
			Mode:          m.cfg.Mode,
		})

		// Store result in request context
		ctx := context.WithValue(r.Context(), contextKey{}, result)
		r = r.WithContext(ctx)

		// Invoke callback
		if m.cfg.OnThreat != nil && len(result.Threats) > 0 {
			m.cfg.OnThreat(ThreatEvent{
				RequestID: result.RequestID,
				Score:     result.ThreatScore,
				RiskLevel: result.RiskLevel,
				Decision:  result.Decision,
				Threats:   result.Threats,
				Endpoint:  fmt.Sprintf("%s %s", method, r.URL.Path),
				SourceIP:  realIP(r),
			})
		}

		if result.ShouldBlock {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			reason := "Suspicious content detected"
			if len(result.Threats) > 0 {
				reason = result.Threats[0].Explanation
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":     "Request blocked by AntiScam AI",
				"requestId": result.RequestID,
				"riskLevel": result.RiskLevel,
				"reason":    reason,
			})
			return
		}

		if result.Decision == "flag" {
			w.Header().Set("X-AntiScam-Flag", "true")
			w.Header().Set("X-AntiScam-Score", fmt.Sprintf("%.2f", result.ThreatScore))
		}

		next.ServeHTTP(w, r)
	})
}

// FromContext retrieves the InspectResponse stored by the middleware.
func FromContext(ctx context.Context) (InspectResponse, bool) {
	v, ok := ctx.Value(contextKey{}).(InspectResponse)
	return v, ok
}

// ─── Internal ─────────────────────────────────────────────────────────────────

type contextKey struct{}

func (m *Middleware) shouldSkip(path, method string) bool {
	for _, p := range m.cfg.ExcludePaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	for _, meth := range m.cfg.InspectMethods {
		if strings.EqualFold(meth, method) {
			return false
		}
	}
	return true
}

func (m *Middleware) extractContent(body []byte) (string, []string) {
	text := ""
	// Try JSON flatten
	var obj any
	if json.Unmarshal(body, &obj) == nil {
		text = flattenJSON(obj, 0)
	} else {
		text = string(body)
	}
	urls := m.urlRe.FindAllString(text, -1)
	return text, uniqueStrings(urls)
}

func flattenJSON(v any, depth int) string {
	if depth > 5 {
		return ""
	}
	switch val := v.(type) {
	case string:
		if len(val) > 2 {
			return val
		}
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, flattenJSON(item, depth+1))
		}
		return strings.Join(parts, " ")
	case map[string]any:
		parts := make([]string, 0, len(val))
		for _, v2 := range val {
			parts = append(parts, flattenJSON(v2, depth+1))
		}
		return strings.Join(parts, " ")
	}
	return ""
}

var headerAllowList = []string{"User-Agent", "Referer", "X-Forwarded-For", "Origin"}

func (m *Middleware) safeHeaders(r *http.Request) map[string]string {
	out := make(map[string]string, len(headerAllowList))
	for _, h := range headerAllowList {
		if v := r.Header.Get(h); v != "" {
			out[strings.ToLower(h)] = v
		}
	}
	return out
}

func (m *Middleware) call(req InspectRequest) InspectResponse {
	b, _ := json.Marshal(req)
	httpReq, err := http.NewRequest(
		"POST",
		strings.TrimRight(m.cfg.Endpoint, "/")+"/sdk/v1/inspect",
		bytes.NewBuffer(b),
	)
	if err != nil {
		log.Printf("[AntiScamAI] failed to create request: %v", err)
		return m.fallback()
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-AntiScam-Key", m.cfg.APIKey)

	resp, err := m.client.Do(httpReq)
	if err != nil {
		log.Printf("[AntiScamAI] request failed: %v – falling back to: %s", err, m.cfg.OnError)
		return m.fallback()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[AntiScamAI] unexpected status %d – falling back", resp.StatusCode)
		return m.fallback()
	}

	var result InspectResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[AntiScamAI] decode error: %v", err)
		return m.fallback()
	}
	return result
}

func (m *Middleware) fallback() InspectResponse {
	blocked := m.cfg.OnError == "block"
	return InspectResponse{
		RequestID:   "error-fallback",
		ThreatScore: 0,
		RiskLevel:   "MINIMAL",
		Decision:    func() string { if blocked { return "block" }; return "allow" }(),
		ShouldBlock: blocked,
	}
}

// ─── Utilities ────────────────────────────────────────────────────────────────

func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.TrimSpace(strings.Split(ip, ",")[0])
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func uniqueStrings(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
