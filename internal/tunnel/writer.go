package tunnel

import (
	"fmt"
	"net"
	"net/http"
)

// streamResponseWriter adapts a raw net.Conn into an http.ResponseWriter so
// httputil.ReverseProxy can write directly back over a yamux stream.
type streamResponseWriter struct {
	stream      net.Conn
	header      http.Header
	wroteHeader bool
	statusCode  int
	// headerErr captures any error from writing the status line / headers in
	// WriteHeader, since the http.ResponseWriter interface gives us no return
	// channel there. Surfaced on the next Write() call so the proxy treats it
	// as a normal write failure.
	headerErr error
}

func (w *streamResponseWriter) Header() http.Header {
	return w.header
}

func (w *streamResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.headerErr != nil {
		return 0, w.headerErr
	}
	return w.stream.Write(data)
}

func (w *streamResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = statusCode

	statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	if _, err := w.stream.Write([]byte(statusLine)); err != nil {
		w.headerErr = fmt.Errorf("failed to write status line: %w", err)
		return
	}

	for key, values := range w.header {
		for _, value := range values {
			headerLine := fmt.Sprintf("%s: %s\r\n", key, value)
			if _, err := w.stream.Write([]byte(headerLine)); err != nil {
				w.headerErr = fmt.Errorf("failed to write header %s: %w", key, err)
				return
			}
		}
	}

	if _, err := w.stream.Write([]byte("\r\n")); err != nil {
		w.headerErr = fmt.Errorf("failed to write headers terminator: %w", err)
	}
}
