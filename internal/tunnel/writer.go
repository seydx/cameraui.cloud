package tunnel

import (
	"fmt"
	"net"
	"net/http"
)

type streamResponseWriter struct {
	stream      net.Conn
	header      http.Header
	wroteHeader bool
	statusCode  int
}

func (w *streamResponseWriter) Header() http.Header {
	return w.header
}

func (w *streamResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.stream.Write(data)
}

func (w *streamResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = statusCode

	// Write status line
	statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	w.stream.Write([]byte(statusLine))

	// Write headers
	for key, values := range w.header {
		for _, value := range values {
			headerLine := fmt.Sprintf("%s: %s\r\n", key, value)
			w.stream.Write([]byte(headerLine))
		}
	}

	// End headers
	w.stream.Write([]byte("\r\n"))
}
