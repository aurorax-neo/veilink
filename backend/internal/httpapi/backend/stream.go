package backend

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// StreamHub SSE 事件总线：日志、节点状态、隧道统计统一走这里推送
type StreamHub struct {
	subs map[chan StreamEvent]bool
	add  chan chan StreamEvent
	del  chan chan StreamEvent
	pub  chan StreamEvent
}

type StreamEvent struct {
	Type string      `json:"-"`
	Data interface{} `json:"-"`
}

func NewStreamHub() *StreamHub {
	h := &StreamHub{
		subs: make(map[chan StreamEvent]bool),
		add:  make(chan chan StreamEvent),
		del:  make(chan chan StreamEvent),
		pub:  make(chan StreamEvent, 256),
	}
	go h.run()
	return h
}

func (h *StreamHub) run() {
	for {
		select {
		case ch := <-h.add:
			h.subs[ch] = true
		case ch := <-h.del:
			delete(h.subs, ch)
			close(ch)
		case ev := <-h.pub:
			for ch := range h.subs {
				select {
				case ch <- ev:
				default:
					// 慢消费者直接踢掉，不阻塞
					delete(h.subs, ch)
					close(ch)
				}
			}
		}
	}
}

// Publish 发布事件（日志、状态变更等调用）
func (h *StreamHub) Publish(eventType string, data interface{}) {
	select {
	case h.pub <- StreamEvent{Type: eventType, Data: data}:
	default:
		// 队列满时丢弃，避免阻塞业务
	}
}

// ServeHTTP GET /api/v1/stream，EventSource 订阅
func (h *StreamHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// SSE 必须的头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // 禁用 nginx 缓冲

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// 可选按类型过滤：?types=log,node,tunnel
	types := parseTypes(r.URL.Query().Get("types"))

	ch := make(chan StreamEvent, 32)
	h.add <- ch
	defer func() { h.del <- ch }()

	// 首次建连先发一条 hello（含服务器时间，客户端可校准）
	fmt.Fprintf(w, "event: hello\ndata: {\"time\":%d}\n\n", time.Now().Unix())
	flusher.Flush()

	// 心跳：25s 一次，防止中间代理掐连接
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case ev := <-ch:
			if len(types) > 0 && !types[ev.Type] {
				continue
			}
			data, err := json.Marshal(ev.Data)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
			flusher.Flush()
		}
	}
}

func parseTypes(s string) map[string]bool {
	if s == "" {
		return nil
	}
	m := make(map[string]bool)
	for _, t := range splitComma(s) {
		m[t] = true
	}
	return m
}

func splitComma(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// --- 一次性 token（解决 EventSource 不能带 Header 的问题）---

// StreamToken 换一次性 token：POST /api/v1/stream/token（需 API Key）
// 返回 {"token": "st_xxx", "expires_in": 60}
type StreamTokenStore struct {
	mu     sync.Mutex
	tokens map[string]int64
}

func NewStreamTokenStore() *StreamTokenStore {
	s := &StreamTokenStore{tokens: make(map[string]int64)}
	go s.cleanup()
	return s
}

func (s *StreamTokenStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		s.mu.Lock()
		for tok, exp := range s.tokens {
			if now > exp {
				delete(s.tokens, tok)
			}
		}
		s.mu.Unlock()
	}
}

func (s *StreamTokenStore) Issue() string {
	tok := "st_" + randomHex(16)
	s.mu.Lock()
	s.tokens[tok] = time.Now().Add(60 * time.Second).Unix()
	s.mu.Unlock()
	return tok
}

func (s *StreamTokenStore) Consume(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.tokens[tok]
	if !ok || time.Now().Unix() > exp {
		return false
	}
	delete(s.tokens, tok) // 一次性
	return true
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
