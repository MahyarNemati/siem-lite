package ingest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mahyarnemati/siem-lite/internal/parser"
)

// UDPServer receives one syslog message per datagram.
type UDPServer struct {
	Addr    string
	Handler Handler
	Logger  *slog.Logger
	// OnDrop is called when the handler is saturated.
	OnDrop func()

	mu   sync.Mutex
	conn net.PacketConn
}

// ListenAndServe blocks until ctx is cancelled.
func (s *UDPServer) ListenAndServe(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", s.Addr)
	if err != nil {
		return fmt.Errorf("syslog udp listen: %w", err)
	}
	return s.Serve(ctx, pc)
}

// Serve reads from an existing packet conn.
func (s *UDPServer) Serve(ctx context.Context, pc net.PacketConn) error {
	s.mu.Lock()
	s.conn = pc
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = pc.Close() })
	defer stop()

	buf := make([]byte, MaxMessageSize)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger().Warn("syslog udp read", "err", err)
			continue
		}
		now := time.Now()
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			line = strings.TrimRight(line, "\r\x00")
			if line == "" {
				continue
			}
			r := Record{Format: parser.FormatSyslog, Data: line, Received: now, Transport: "udp", Remote: hostOf(addr)}
			if !s.Handler.TryHandle(r) && s.OnDrop != nil {
				s.OnDrop()
			}
		}
	}
}

// LocalAddr returns the bound address once serving.
func (s *UDPServer) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *UDPServer) logger() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

// TCPServer receives syslog over TCP. Both RFC 6587 framings are accepted
// per connection: octet counting ("123 <34>1 ...") and newline delimited.
type TCPServer struct {
	Addr        string
	Handler     Handler
	Logger      *slog.Logger
	IdleTimeout time.Duration
	MaxConns    int

	mu sync.Mutex
	ln net.Listener
}

// ListenAndServe blocks until ctx is cancelled.
func (s *TCPServer) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("syslog tcp listen: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts on an existing listener.
func (s *TCPServer) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	maxConns := s.MaxConns
	if maxConns <= 0 {
		maxConns = 1024
	}
	sem := make(chan struct{}, maxConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger().Warn("syslog tcp accept", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			s.logger().Warn("syslog tcp connection limit reached", "remote", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.handleConn(ctx, conn)
		}()
	}
}

// ListenerAddr returns the bound address once serving.
func (s *TCPServer) ListenerAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

func (s *TCPServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	idle := s.IdleTimeout
	if idle <= 0 {
		idle = 5 * time.Minute
	}
	remote := hostOf(conn.RemoteAddr())
	br := bufio.NewReaderSize(conn, 32<<10)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		msg, err := readFrame(br)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				s.logger().Debug("syslog tcp connection closed", "remote", remote, "err", err)
			}
			return
		}
		if msg == "" {
			continue
		}
		r := Record{Format: parser.FormatSyslog, Data: msg, Received: time.Now(), Transport: "tcp", Remote: remote}
		if err := s.Handler.Handle(ctx, r); err != nil {
			return
		}
	}
}

func (s *TCPServer) logger() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

var errFrameTooLarge = errors.New("syslog frame exceeds maximum size")

// readFrame reads one message using octet counting when the frame starts
// with a digit and newline framing otherwise.
func readFrame(br *bufio.Reader) (string, error) {
	b, err := br.Peek(1)
	if err != nil {
		return "", err
	}
	if b[0] >= '1' && b[0] <= '9' {
		lenStr, err := br.ReadString(' ')
		if err != nil {
			return "", err
		}
		n, err := strconv.Atoi(strings.TrimSuffix(lenStr, " "))
		if err != nil {
			return "", fmt.Errorf("octet count: %w", err)
		}
		if n > MaxMessageSize {
			return "", errFrameTooLarge
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return strings.TrimRight(string(buf), "\r\n"), nil
	}
	var sb strings.Builder
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) && sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
		if sb.Len()+len(chunk) > MaxMessageSize {
			return "", errFrameTooLarge
		}
		sb.Write(chunk)
		if !isPrefix {
			return strings.TrimRight(sb.String(), "\r\x00"), nil
		}
	}
}

func hostOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
