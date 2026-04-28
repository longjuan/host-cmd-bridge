package service

import "sync"

type waitHub struct {
	mu   sync.Mutex
	subs map[string][]chan struct{}
}

func newWaitHub() *waitHub {
	return &waitHub{subs: make(map[string][]chan struct{})}
}

func (h *waitHub) subscribe(requestID string) chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan struct{}, 1)
	h.subs[requestID] = append(h.subs[requestID], ch)
	return ch
}

func (h *waitHub) unsubscribe(requestID string, target chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	arr := h.subs[requestID]
	if len(arr) == 0 {
		return
	}
	out := arr[:0]
	for _, ch := range arr {
		if ch != target {
			out = append(out, ch)
		}
	}
	if len(out) == 0 {
		delete(h.subs, requestID)
		return
	}
	h.subs[requestID] = out
}

func (h *waitHub) publish(requestID string) {
	h.mu.Lock()
	arr := append([]chan struct{}(nil), h.subs[requestID]...)
	h.mu.Unlock()

	for _, ch := range arr {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
