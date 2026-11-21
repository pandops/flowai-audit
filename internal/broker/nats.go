package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/pandops/flowai-audit/internal/audit"
)

// ConnectOptions are the NATS connection settings.
type ConnectOptions struct {
	URL         string
	CAPEM       []byte
	UserJWT     string
	UserSeed    []byte
	InboxPrefix string
}

// Connect opens a TLS connection with the service's user JWT. It keeps
// reconnecting for the life of the process.
func Connect(o ConnectOptions) (*nats.Conn, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(o.CAPEM) {
		return nil, errors.New("nats CA holds no certificate")
	}
	return nats.Connect(o.URL,
		nats.Name("audit"),
		nats.Secure(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}),
		nats.UserJWTAndSeed(o.UserJWT, string(o.UserSeed)),
		nats.CustomInboxPrefix(o.InboxPrefix),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
}

// JetStreamFetcher pulls from the deployment-created durable consumer. A
// missing consumer is a fetch error, so the service stays unready.
type JetStreamFetcher struct {
	js      jetstream.JetStream
	maxWait time.Duration
	mu      sync.Mutex
	cons    jetstream.Consumer
}

// NewJetStreamFetcher builds a fetcher over nc.
func NewJetStreamFetcher(nc *nats.Conn) (*JetStreamFetcher, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}
	return &JetStreamFetcher{js: js, maxWait: time.Second}, nil
}

func (f *JetStreamFetcher) consumer(ctx context.Context) (jetstream.Consumer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cons == nil {
		c, err := f.js.Consumer(ctx, Stream, Durable)
		if err != nil {
			return nil, err
		}
		f.cons = c
	}
	return f.cons, nil
}

// Fetch returns up to max deliveries, waiting up to one second for them.
func (f *JetStreamFetcher) Fetch(ctx context.Context, max int) ([]audit.Delivery, error) {
	cons, err := f.consumer(ctx)
	if err != nil {
		return nil, err
	}
	batch, err := cons.Fetch(max, jetstream.FetchMaxWait(f.maxWait))
	if err != nil {
		f.forget(err)
		return nil, err
	}
	var out []audit.Delivery
	for m := range batch.Messages() {
		out = append(out, message{m})
	}
	if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) && !errors.Is(err, context.DeadlineExceeded) {
		f.forget(err)
		return out, err
	}
	return out, nil
}

// forget drops the consumer handle after it was deleted, so the next fetch
// looks it up again.
func (f *JetStreamFetcher) forget(err error) {
	if errors.Is(err, jetstream.ErrConsumerNotFound) || errors.Is(err, jetstream.ErrConsumerDeleted) {
		f.mu.Lock()
		f.cons = nil
		f.mu.Unlock()
	}
}

type message struct{ m jetstream.Msg }

func (d message) Subject() string { return d.m.Subject() }
func (d message) Header(k string) string {
	if h := d.m.Headers(); h != nil {
		return h.Get(k)
	}
	return ""
}
func (d message) Data() []byte { return d.m.Data() }
func (d message) Ack() error   { return d.m.Ack() }
func (d message) Term() error  { return d.m.Term() }

// ServeRequests answers audit.ui.list and audit.ui.get in the audit queue
// group. Each reply carries the status header and the reply body.
func ServeRequests(nc *nats.Conn, timeout time.Duration, serve func(context.Context, audit.Request) audit.Reply) ([]*nats.Subscription, error) {
	var subs []*nats.Subscription
	for subject, op := range map[string]string{ListSubject: audit.OperationList, GetSubject: audit.OperationGet} {
		op := op
		sub, err := nc.QueueSubscribe(subject, QueueGroup, func(m *nats.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			header := func(k string) string {
				if m.Header == nil {
					return ""
				}
				return m.Header.Get(k)
			}
			r := serve(ctx, audit.Request{Operation: op, Header: header, Body: m.Data})
			reply := nats.NewMsg(m.Reply)
			reply.Header.Set(StatusHeader, strconv.Itoa(r.Status))
			reply.Data = r.Body
			_ = m.RespondMsg(reply)
		})
		if err != nil {
			for _, s := range subs {
				_ = s.Unsubscribe()
			}
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, nil
}
