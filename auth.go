package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	loginPath     = "/prx/000/http/localhost/login"
	challengePath = "/prx/000/http/localhost/challenge"
	welcomeMark   = "/welcome"
)

type AuthClient struct {
	hc   *http.Client
	base string
	jar  *cookiejar.Jar
	role string
	// Prompt asks the user for a secondary credential; question is the
	// server-provided prompt text.
	Prompt func(question string) (string, error)
}

type aaaMethod struct {
	Name       string `json:"name"`
	MethodDisp string `json:"method_disp"`
}

func NewAuthClient(server, caFile string, insecure bool) (*AuthClient, error) {
	tlsCfg, err := makeTLSConfig(server, caFile, insecure)
	if err != nil {
		return nil, fmt.Errorf("TLS config: %w", err)
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Jar:       jar,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &AuthClient{hc: hc, base: "https://" + server, jar: jar}, nil
}

func (c *AuthClient) Role() string { return c.role }

// Logout ends the server-side session (mirrors array_bye).
func (c *AuthClient) Logout() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.base+"/prx/000/http/localhost/logout", nil)
	if err != nil {
		return
	}
	resp, err := c.hc.Do(req)
	if err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
	}
}

func (c *AuthClient) baseURL() *url.URL {
	u, _ := url.Parse(c.base)
	return u
}

func (c *AuthClient) get(ctx context.Context, rawurl string) (*http.Response, []byte, error) {
	if strings.HasPrefix(rawurl, "/") {
		rawurl = c.base + rawurl
	}
	req, err := http.NewRequestWithContext(ctx, "GET", rawurl, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, body, nil
}

func (c *AuthClient) postForm(ctx context.Context, rawurl string, vals url.Values) (*http.Response, []byte, error) {
	if strings.HasPrefix(rawurl, "/") {
		rawurl = c.base + rawurl
	}
	req, err := http.NewRequestWithContext(ctx, "POST", rawurl, strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, body, nil
}

// Login performs the full authentication dialogue and returns the Cookie
// header value usable for the raw /vpntunnel connection.
func (c *AuthClient) Login(ctx context.Context, user, pass string) (string, error) {
	// Prime the session: sets the ANsession...=VPN cookie.
	_, _, err := c.get(ctx, loginPath)
	if err != nil {
		return "", err
	}

	method, err := c.fetchAAAMethod(ctx)
	if err != nil {
		return "", fmt.Errorf("fetch AAA method: %w", err)
	}

	resp, body, err := c.postForm(ctx, loginPath, url.Values{
		"method":      {method},
		"uname":       {user},
		"pwd":         {pass},
		"pwd1":        {},
		"pwd2":        {},
		"deviceid":    {},
		"device_name": {},
		"hardwareid":  {},
		"customer1":   {},
	})
	if err != nil {
		return "", err
	}

	for round := 0; round < 6; round++ {
		if msg := c.msgCookie(); msg != "" {
			return "", fmt.Errorf("server: %s", msg)
		}
		loc := resp.Header.Get("Location")
		bodyStr := string(body)

		if strings.Contains(loc, welcomeMark) || c.hasSession() {
			c.role = c.cookieValue("role_names")
			return c.cookieHeader(), nil
		}
		// PKU-style secondary verification (id-card tail / phone digits):
		// 302 to the challenge endpoint, one "pwd" field.
		if strings.Contains(loc, "/challenge") {
			resp, body, err = c.doChallenge(ctx)
			if err != nil {
				return "", err
			}
			continue
		}
		// Any other challenge-like page: follow and answer the form.
		if loc != "" {
			resp, body, err = c.get(ctx, loc)
			if err != nil {
				return "", err
			}
			continue
		}
		if strings.Contains(bodyStr, "<form") || strings.Contains(bodyStr, "<input") {
			resp, body, err = c.answerForm(ctx, bodyStr)
			if err != nil {
				return "", err
			}
			continue
		}
		return "", fmt.Errorf("unexpected login response (HTTP %s, no redirect, no form)", resp.Status)
	}
	return "", fmt.Errorf("too many verification rounds")
}

// doChallenge handles the secondary-verification dialogue like the
// official client's do_challenge: GET the challenge endpoint, parse
// _AN_str_info_chal/_AN_str_errmsg_chal, POST the answer back as "pwd".
func (c *AuthClient) doChallenge(ctx context.Context) (*http.Response, []byte, error) {
	js := c.fetchChallengeJS(ctx)
	question := jsString(js, "_AN_str_info_chal")
	errMsg := jsString(js, "_AN_str_errmsg_chal")
	if question == "" {
		question = "verification code"
	}
	if errMsg != "" {
		fmt.Fprintf(os.Stderr, "server message: %s\n", errMsg)
	}

	prompt := c.Prompt
	if prompt == nil {
		prompt = func(q string) (string, error) {
			fmt.Fprintf(os.Stderr, "%s\nanswer: ", q)
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			return strings.TrimSpace(line), err
		}
	}
	answer, err := waitForInput(ctx, func() (string, error) { return prompt(question) })
	if err != nil {
		return nil, nil, err
	}
	if answer == "" {
		return nil, nil, fmt.Errorf("empty verification answer")
	}

	return c.postForm(ctx, challengePath, url.Values{"pwd": {answer}})
}

// A terminal read cannot be cancelled directly. Let shutdown finish even
// while the input goroutine is waiting for a verification answer.
func waitForInput(ctx context.Context, read func() (string, error)) (string, error) {
	type result struct {
		text string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		text, err := read()
		ch <- result{text, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-ch:
		return r.text, r.err
	}
}

// fetchChallengeJS retrieves the text holding the challenge variables:
// first the official way (GET the challenge page and inspect it, following
// the one-level redirect), then the an_chal.js script the page references,
// then PKU's known an_chal.js location as a last resort. A source only
// counts if _AN_str_info_chal is actually defined in it — a page may
// merely *reference* the variable (e.g. document.write) while defining
// it in an external script.
func (c *AuthClient) fetchChallengeJS(ctx context.Context) string {
	resp, body, err := c.get(ctx, challengePath)
	if err == nil {
		if loc := resp.Header.Get("Location"); loc != "" {
			_, body, err = c.get(ctx, loc)
		}
		if err == nil {
			if definesChallengeVar(string(body)) {
				return string(body)
			}
			// The page references its variables via <script src=...an_chal.js>.
			re := regexp.MustCompile(`src="([^"]*an_chal\.js)"`)
			if m := re.FindSubmatch(body); m != nil {
				if _, js, err := c.get(ctx, string(m[1])); err == nil && definesChallengeVar(string(js)) {
					return string(js)
				}
			}
		}
	}
	// PKU serves the variables here (observed).
	if _, js, err := c.get(ctx, "/prx/000/http/localh/an_chal.js"); err == nil {
		return string(js)
	}
	return ""
}

// definesChallengeVar reports whether the source actually assigns
// _AN_str_info_chal a non-empty value.
func definesChallengeVar(s string) bool {
	return jsString(s, "_AN_str_info_chal") != ""
}

// fetchAAAMethod retrieves the site's AAA method list from an_login.js,
// the same endpoint the official client uses.
func (c *AuthClient) fetchAAAMethod(ctx context.Context) (string, error) {
	_, js, err := c.get(ctx, "/prx/000/http/localhost/an_login.js?devtype=6&localip=&deviceid=&end=1")
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`(?s)_AN_aaa_method\s*=\s*(\[.*?\])\s*;`)
	m := re.FindSubmatch(js)
	if m == nil {
		return "", fmt.Errorf("no AAA method list in an_login.js")
	}
	var methods []aaaMethod
	if err := json.Unmarshal(m[1], &methods); err != nil {
		return "", fmt.Errorf("parse AAA methods: %w", err)
	}
	if len(methods) == 0 {
		return "", fmt.Errorf("site has no AAA methods")
	}
	return methods[0].Name, nil
}

// msgCookie extracts the URL-encoded _AN_msgStr error cookie, if any.
func (c *AuthClient) msgCookie() string {
	for _, ck := range c.jar.Cookies(c.baseURL()) {
		if ck.Name == "_AN_msgStr" && ck.Value != "" {
			v, err := url.QueryUnescape(ck.Value)
			if err != nil {
				v = ck.Value
			}
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// hasSession reports whether the ANsession cookie carries a real session id
// (format "<vsite>+<id>_<hash>") rather than the anonymous "VPN" marker.
func (c *AuthClient) hasSession() bool {
	for _, ck := range c.jar.Cookies(c.baseURL()) {
		if strings.HasPrefix(ck.Name, "ANsession") {
			if v, err := url.PathUnescape(ck.Value); err == nil {
				if strings.Contains(v, "+") {
					return true
				}
			}
		}
	}
	return false
}

func (c *AuthClient) cookieValue(name string) string {
	for _, ck := range c.jar.Cookies(c.baseURL()) {
		if ck.Name == name {
			v, _ := url.QueryUnescape(ck.Value)
			return v
		}
	}
	return ""
}

func (c *AuthClient) cookieHeader() string {
	var parts []string
	for _, ck := range c.jar.Cookies(c.baseURL()) {
		if ck.Name == "_AN_msgStr" {
			continue
		}
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; ")
}

// answerForm parses the first <form> in a challenge page, auto-fills hidden
// fields, prompts for everything else, and submits it.
func (c *AuthClient) answerForm(ctx context.Context, page string) (*http.Response, []byte, error) {
	// Show the user what the page is asking for.
	text := stripTags(page)
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 300 {
		text = text[:300]
	}
	fmt.Fprintf(os.Stderr, "\n--- server asks (verification) ---\n%s\n----------------------------------\n", text)

	formRe := regexp.MustCompile(`(?is)<form[^>]*action="?([^"\s>]+)"?[^>]*>(.*?)</form>`)
	fm := formRe.FindStringSubmatch(page)
	if fm == nil {
		return nil, nil, fmt.Errorf("verification page has no form")
	}
	action, body := html.UnescapeString(fm[1]), fm[2]

	inputRe := regexp.MustCompile(`(?is)<input\s+([^>]*?)/?>`)
	attrRe := regexp.MustCompile(`(?is)(\w+)\s*=\s*"([^"]*)"`)
	vals := url.Values{}
	reader := bufio.NewReader(os.Stdin)
	for _, im := range inputRe.FindAllStringSubmatch(body, -1) {
		attrs := map[string]string{}
		for _, am := range attrRe.FindAllStringSubmatch(im[1], -1) {
			attrs[strings.ToLower(am[1])] = html.UnescapeString(am[2])
		}
		name := attrs["name"]
		if name == "" {
			continue
		}
		typ := strings.ToLower(attrs["type"])
		switch typ {
		case "submit", "button", "image", "reset":
			if typ == "submit" && name != "" && attrs["value"] != "" {
				vals.Set(name, attrs["value"])
			}
		case "hidden", "checkbox", "radio":
			vals.Set(name, attrs["value"])
		default: // text, password, ...
			if attrs["value"] != "" {
				vals.Set(name, attrs["value"])
				continue
			}
			fmt.Fprintf(os.Stderr, "input %q (%s): ", attrs["placeholder"]+attrs["label"]+name, name)
			line, err := waitForInput(ctx, func() (string, error) { return reader.ReadString('\n') })
			if err != nil {
				return nil, nil, err
			}
			vals.Set(name, strings.TrimSpace(line))
		}
	}
	if strings.HasPrefix(action, "/") {
		action = c.base + action
	} else if !strings.HasPrefix(action, "http") {
		action = c.base + "/" + action
	}
	return c.postForm(ctx, action, vals)
}

// jsString extracts var <name> = "value"; from a JS snippet.
func jsString(js, name string) string {
	re := regexp.MustCompile(name + `\s*=\s*"((?:[^"\\]|\\.)*)"`)
	m := re.FindStringSubmatch(js)
	if m == nil {
		return ""
	}
	s, err := strconv.Unquote(`"` + m[1] + `"`)
	if err != nil {
		return m[1]
	}
	return s
}

var tagRe = regexp.MustCompile(`(?s)<[^>]*>`)

func stripTags(s string) string {
	s = tagRe.ReplaceAllString(s, " ")
	return html.UnescapeString(s)
}
