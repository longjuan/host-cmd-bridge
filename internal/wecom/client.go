package wecom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"host-cmd-bridge/internal/config"
)

type Client struct {
	cfg    config.WeComConfig
	client *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time

	templateMu       sync.Mutex
	templateBindings map[string]controlBinding
}

type ApprovalPayload struct {
	RequestID        string
	Command          string
	Args             []string
	Reason           string
	TimeoutSec       int
	Digest           string
	RequestAt        time.Time
	ApprovalDeadline time.Time
	AutoApproved     bool
}

type controlBinding struct {
	Control string
	ID      string
}

func NewClient(cfg config.WeComConfig) *Client {
	return &Client{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) WarmupTemplate(ctx context.Context) error {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return err
	}
	_, err = c.getTemplateBindings(ctx, token)
	return err
}

func (c *Client) CreateApproval(ctx context.Context, p ApprovalPayload) (string, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return "", err
	}
	bindings, err := c.getTemplateBindings(ctx, token)
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/cgi-bin/oa/applyevent?access_token=%s", strings.TrimRight(c.cfg.APIBaseURL, "/"), url.QueryEscape(token))
	body, err := c.buildApprovalRequest(p, bindings)
	if err != nil {
		return "", err
	}
	respBody, err := c.doJSON(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return "", err
	}
	var resp struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
		SpNo    string `json:"sp_no"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("decode create approval response: %w", err)
	}
	if resp.ErrCode != 0 {
		return "", fmt.Errorf("wecom create approval failed: errcode=%d errmsg=%s", resp.ErrCode, resp.ErrMsg)
	}
	if resp.SpNo == "" {
		return "", fmt.Errorf("wecom create approval returned empty sp_no")
	}
	return resp.SpNo, nil
}

func (c *Client) buildApprovalRequest(p ApprovalPayload, bindings map[string]controlBinding) (map[string]any, error) {
	fieldValues := []struct {
		Key   string
		Value string
	}{
		{Key: "request_id", Value: p.RequestID},
		{Key: "command", Value: p.Command},
		{Key: "args", Value: strings.Join(p.Args, " ")},
		{Key: "reason", Value: p.Reason},
		{Key: "timeout_sec", Value: fmt.Sprintf("%d", p.TimeoutSec)},
		{Key: "digest", Value: p.Digest},
	}

	contents := make([]map[string]any, 0, len(fieldValues))
	for _, field := range fieldValues {
		binding, ok := bindings[field.Key]
		if !ok {
			return nil, fmt.Errorf("template binding missing for field %q", field.Key)
		}
		controlItem, err := makeControlValue(binding, field.Value)
		if err != nil {
			return nil, fmt.Errorf("field %q invalid template control: %w", field.Key, err)
		}
		contents = append(contents, controlItem)
	}

	req := map[string]any{
		"creator_userid":        c.cfg.CreatorUserID,
		"template_id":           c.cfg.TemplateID,
		"use_template_approver": 1,
		"notify_type":           1,
		"apply_data":            map[string]any{"contents": contents},
		"summary_list": []map[string]any{
			textSummary(joinCommandAndArgs(p.Command, p.Args)),
			textSummary(p.Reason),
			textSummary(thirdSummaryLine(p)),
		},
	}
	if len(c.cfg.ApproverUserIDs) > 0 {
		req["use_template_approver"] = 0
		req["process"] = map[string]any{
			"node_list": []map[string]any{
				{
					"type":    1,
					"apv_rel": 2,
					"userid":  c.cfg.ApproverUserIDs,
				},
			},
		}
	}
	return req, nil
}

func makeControlValue(binding controlBinding, v string) (map[string]any, error) {
	item := map[string]any{
		"control": binding.Control,
		"id":      binding.ID,
	}
	switch binding.Control {
	case "Text", "Textarea":
		item["value"] = map[string]any{"text": v}
	case "Number":
		item["value"] = map[string]any{"new_number": v}
	case "Money":
		item["value"] = map[string]any{"new_money": v}
	default:
		return nil, fmt.Errorf("unsupported control type %q, only Text/Textarea/Number/Money are supported", binding.Control)
	}
	return item, nil
}

func textSummary(v string) map[string]any {
	summary := strings.TrimSpace(v)
	if summary == "" {
		summary = "-"
	}
	summary = trimRunes(summary, 20)
	return map[string]any{
		"summary_info": []map[string]any{
			{
				"text": summary,
				"lang": "zh_CN",
			},
		},
	}
}

func joinCommandAndArgs(command string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	if strings.TrimSpace(command) != "" {
		parts = append(parts, strings.TrimSpace(command))
	}
	for _, a := range args {
		if strings.TrimSpace(a) == "" {
			continue
		}
		parts = append(parts, strings.TrimSpace(a))
	}
	return strings.Join(parts, " ")
}

func formatWindowSummary(requestAt, deadline time.Time) string {
	reqText := "-"
	deadlineText := "-"
	if !requestAt.IsZero() {
		reqText = requestAt.Local().Format("15:04:05")
	}
	if !deadline.IsZero() {
		deadlineText = deadline.Local().Format("15:04:05")
	}
	return fmt.Sprintf("起%s 截%s", reqText, deadlineText)
}

func thirdSummaryLine(p ApprovalPayload) string {
	if p.AutoApproved {
		return "已自动通过，无需审批"
	}
	return formatWindowSummary(p.RequestAt, p.ApprovalDeadline)
}

func trimRunes(s string, max int) string {
	rs := []rune(s)
	if len(rs) <= max {
		return s
	}
	return string(rs[:max])
}

func (c *Client) getTemplateBindings(ctx context.Context, token string) (map[string]controlBinding, error) {
	c.templateMu.Lock()
	if c.templateBindings != nil {
		out := copyBindings(c.templateBindings)
		c.templateMu.Unlock()
		return out, nil
	}
	c.templateMu.Unlock()

	resolved, err := c.fetchTemplateBindings(ctx, token)
	if err != nil {
		return nil, err
	}

	c.templateMu.Lock()
	c.templateBindings = resolved
	out := copyBindings(c.templateBindings)
	c.templateMu.Unlock()
	return out, nil
}

func copyBindings(in map[string]controlBinding) map[string]controlBinding {
	out := make(map[string]controlBinding, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (c *Client) fetchTemplateBindings(ctx context.Context, token string) (map[string]controlBinding, error) {
	endpoint := fmt.Sprintf("%s/cgi-bin/oa/gettemplatedetail?access_token=%s", strings.TrimRight(c.cfg.APIBaseURL, "/"), url.QueryEscape(token))
	reqBody := map[string]any{"template_id": c.cfg.TemplateID}
	respBody, err := c.doJSON(ctx, http.MethodPost, endpoint, reqBody)
	if err != nil {
		return nil, err
	}

	var resp struct {
		ErrCode         int    `json:"errcode"`
		ErrMsg          string `json:"errmsg"`
		TemplateContent struct {
			Controls []struct {
				Property struct {
					Control string `json:"control"`
					ID      string `json:"id"`
					Title   []struct {
						Text string `json:"text"`
						Lang string `json:"lang"`
					} `json:"title"`
				} `json:"property"`
			} `json:"controls"`
		} `json:"template_content"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("decode template detail response: %w", err)
	}
	if resp.ErrCode != 0 {
		return nil, fmt.Errorf("wecom gettemplatedetail failed: errcode=%d errmsg=%s", resp.ErrCode, resp.ErrMsg)
	}

	titleMap := make(map[string]controlBinding)
	idMap := make(map[string]controlBinding)
	availableTitles := make([]string, 0, len(resp.TemplateContent.Controls))
	for _, ctrl := range resp.TemplateContent.Controls {
		binding := controlBinding{Control: ctrl.Property.Control, ID: ctrl.Property.ID}
		idMap[ctrl.Property.ID] = binding
		title := pickPreferredTitle(ctrl.Property.Title)
		if title != "" {
			titleMap[title] = binding
			availableTitles = append(availableTitles, title)
		}
	}
	sort.Strings(availableTitles)

	required := map[string]string{
		"request_id":  strings.TrimSpace(c.cfg.FieldTitles.RequestID),
		"command":     strings.TrimSpace(c.cfg.FieldTitles.Command),
		"args":        strings.TrimSpace(c.cfg.FieldTitles.Args),
		"reason":      strings.TrimSpace(c.cfg.FieldTitles.Reason),
		"timeout_sec": strings.TrimSpace(c.cfg.FieldTitles.TimeoutSec),
		"digest":      strings.TrimSpace(c.cfg.FieldTitles.Digest),
	}

	resolved := make(map[string]controlBinding, len(required))
	for key, title := range required {
		if title == "" {
			return nil, fmt.Errorf("wecom.field_titles.%s cannot be empty", key)
		}
		if binding, ok := titleMap[title]; ok {
			resolved[key] = binding
			continue
		}
		if binding, ok := idMap[title]; ok {
			resolved[key] = binding
			continue
		}
		return nil, fmt.Errorf("template field %q not found by title/id %q, available titles: %s", key, title, strings.Join(availableTitles, ", "))
	}
	return resolved, nil
}

func pickPreferredTitle(titles []struct {
	Text string `json:"text"`
	Lang string `json:"lang"`
}) string {
	for _, t := range titles {
		if t.Lang == "zh_CN" && strings.TrimSpace(t.Text) != "" {
			return strings.TrimSpace(t.Text)
		}
	}
	for _, t := range titles {
		if strings.TrimSpace(t.Text) != "" {
			return strings.TrimSpace(t.Text)
		}
	}
	return ""
}

func (c *Client) getAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		token := c.token
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	endpoint := fmt.Sprintf("%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s",
		strings.TrimRight(c.cfg.APIBaseURL, "/"), url.QueryEscape(c.cfg.CorpID), url.QueryEscape(c.cfg.CorpSecret))
	respBody, err := c.doJSON(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("decode gettoken response: %w", err)
	}
	if resp.ErrCode != 0 {
		return "", fmt.Errorf("wecom gettoken failed: errcode=%d errmsg=%s", resp.ErrCode, resp.ErrMsg)
	}
	if resp.AccessToken == "" {
		return "", fmt.Errorf("wecom gettoken returned empty access_token")
	}

	exp := time.Now().Add(time.Duration(resp.ExpiresIn-120) * time.Second)
	c.mu.Lock()
	c.token = resp.AccessToken
	c.tokenExpiry = exp
	c.mu.Unlock()
	return resp.AccessToken, nil
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, body any) ([]byte, error) {
	var reader io.Reader
	var reqBody []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = b
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}

	if len(reqBody) > 0 {
		log.Printf("[wecom] request method=%s url=%s body=%s", method, sanitizeURL(endpoint), string(reqBody))
	} else {
		log.Printf("[wecom] request method=%s url=%s", method, sanitizeURL(endpoint))
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request wecom: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read wecom response: %w", err)
	}
	log.Printf("[wecom] response url=%s status=%d body=%s", sanitizeURL(endpoint), resp.StatusCode, string(b))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wecom http status %d: %s", resp.StatusCode, string(b))
	}
	return b, nil
}

func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for _, k := range []string{"access_token", "corpsecret"} {
		if q.Has(k) {
			q.Set(k, "***")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
