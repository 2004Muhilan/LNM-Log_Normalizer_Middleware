package frame

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// HTTP is the HTTP receive transport (plan P7): POST a body of newline-delimited events, or a JSON
// array (de-batched downstream), to any path. Bounded (invariant 7): the body is read through a hard
// cap of MaxBodyBytes — bytes beyond it are not read, what arrived is framed with the last frame
// flagged truncated and the request is answered 413 with what was retained; at most MaxConcurrent
// requests are in flight (503 beyond); header and idle timeouts close slow peers. Every request's
// frames are delivered to emit one at a time, tagged with Peer = the remote address.
type HTTP struct {
	Addr          string
	MaxBodyBytes  int64
	MaxEventBytes int
	MaxConcurrent int
	MaxFrames     int64
	// Commit, when set, is called after a request's frames are emitted and before it is answered: 202 then
	// means the frames are durable in the evidence log (group commit, invariant 3). An error answers 503.
	Commit func() error
	// Admit, when set, is asked before a request's frames are emitted (evidence archive): an error — the local
	// evidence buffer at its cap — answers 503 with Retry-After and accepts nothing; the sender keeps the request.
	Admit func() error
	// ReusePort: scale-out — several processes on one address (SO_REUSEPORT); a connection stays with one process
	ReusePort bool

	Requests  atomic.Int64
	Rejected  atomic.Int64 // 503 (too many in flight) or 405
	Truncated atomic.Int64 // 413: body over the cap, prefix retained
	Frames    atomic.Int64
}

func (h *HTTP) Listen() (net.Listener, error) { return listenTCP(h.Addr, h.ReusePort) }

// Serve runs the receiver until ctx is done or MaxFrames is reached.
func (h *HTTP) Serve(ctx context.Context, ln net.Listener, emit func(Frame) error) error {
	maxBody := h.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 8 << 20
	}
	maxBytes := h.MaxEventBytes
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	maxConc := h.MaxConcurrent
	if maxConc <= 0 {
		maxConc = 64
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var emitErr error
	sem := make(chan struct{}, maxConc)
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			h.Rejected.Add(1)
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			h.Rejected.Add(1)
			http.Error(w, "too many requests in flight", http.StatusServiceUnavailable)
			return
		}
		h.Requests.Add(1)
		if h.Admit != nil {
			if err := h.Admit(); err != nil {
				h.Rejected.Add(1)
				w.Header().Set("Retry-After", "5")
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil && len(body) == 0 {
			http.Error(w, "read: "+err.Error(), http.StatusBadRequest)
			return
		}
		over := int64(len(body)) > maxBody
		if over {
			body = body[:maxBody]
		}
		peer := r.RemoteAddr
		var frames []Frame
		trimmed := bytes.TrimLeft(body, " \t\r\n")
		if len(trimmed) > 0 && trimmed[0] == '[' && !over && int64(len(body)) <= int64(maxBytes)*64 {
			// one frame holding the whole batch; the pipeline de-batches it into element frames
			frames = append(frames, Frame{Raw: body, Peer: peer, Framing: Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: []byte{}, FragmentCount: 1,
				OriginalMessageLength: len(body), TruncationStatus: "none", FramingConfidence: "high"}})
		} else {
			_ = Newline{MaxEventBytes: maxBytes}.Scan(bytes.NewReader(body), func(fr Frame) error {
				fr.Peer = peer
				frames = append(frames, fr)
				return nil
			})
			if over && len(frames) > 0 {
				last := &frames[len(frames)-1]
				last.Framing.TruncationStatus, last.Framing.FramingConfidence = "truncated", "low"
			}
		}
		mu.Lock()
		n := 0
		for _, fr := range frames {
			if emitErr != nil {
				break
			}
			if err := emit(fr); err != nil {
				emitErr = err
				cancel()
				break
			}
			n++
			if total := h.Frames.Add(1); h.MaxFrames > 0 && total >= h.MaxFrames {
				cancel()
			}
		}
		var cerr error
		if h.Commit != nil && emitErr == nil {
			cerr = h.Commit()
		}
		mu.Unlock()
		if cerr != nil {
			http.Error(w, "not committed to the evidence log: "+cerr.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if over {
			h.Truncated.Add(1)
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(map[string]any{"status": "truncated", "retained_bytes": len(body), "frames": n, "max_body_bytes": maxBody})
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "frames": n})
	}
	srv := &http.Server{Handler: http.HandlerFunc(handler), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.Serve(ln)
	if err == http.ErrServerClosed {
		err = nil
	}
	if emitErr != nil {
		return emitErr
	}
	if ctx.Err() != nil {
		return nil
	}
	return err
}
