// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go_gapic. DO NOT EDIT.

package logging

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"time"

	"github.com/golang/protobuf/proto"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	gtransport "google.golang.org/api/transport/grpc"
	loggingpb "google.golang.org/genproto/googleapis/logging/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

var newMetricsClientHook clientHook

// MetricsCallOptions contains the retry settings for each method of MetricsClient.
type MetricsCallOptions struct {
	ListLogMetrics  []gax.CallOption
	GetLogMetric    []gax.CallOption
	CreateLogMetric []gax.CallOption
	UpdateLogMetric []gax.CallOption
	DeleteLogMetric []gax.CallOption
}

func defaultMetricsClientOptions() []option.ClientOption {
	return []option.ClientOption{
		option.WithEndpoint("logging.googleapis.com:443"),
		option.WithGRPCDialOption(grpc.WithDisableServiceConfig()),
		option.WithScopes(DefaultAuthScopes()...),
		option.WithGRPCDialOption(grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(math.MaxInt32))),
	}
}

func defaultMetricsCallOptions() *MetricsCallOptions {
	return &MetricsCallOptions{
		ListLogMetrics: []gax.CallOption{
			gax.WithRetry(func() gax.Retryer {
				return gax.OnCodes([]codes.Code{
					codes.DeadlineExceeded,
					codes.Internal,
					codes.Unavailable,
				}, gax.Backoff{
					Initial:    100 * time.Millisecond,
					Max:        60000 * time.Millisecond,
					Multiplier: 1.30,
				})
			}),
		},
		GetLogMetric: []gax.CallOption{
			gax.WithRetry(func() gax.Retryer {
				return gax.OnCodes([]codes.Code{
					codes.DeadlineExceeded,
					codes.Internal,
					codes.Unavailable,
				}, gax.Backoff{
					Initial:    100 * time.Millisecond,
					Max:        60000 * time.Millisecond,
					Multiplier: 1.30,
				})
			}),
		},
		CreateLogMetric: []gax.CallOption{},
		UpdateLogMetric: []gax.CallOption{
			gax.WithRetry(func() gax.Retryer {
				return gax.OnCodes([]codes.Code{
					codes.DeadlineExceeded,
					codes.Internal,
					codes.Unavailable,
				}, gax.Backoff{
					Initial:    100 * time.Millisecond,
					Max:        60000 * time.Millisecond,
					Multiplier: 1.30,
				})
			}),
		},
		DeleteLogMetric: []gax.CallOption{
			gax.WithRetry(func() gax.Retryer {
				return gax.OnCodes([]codes.Code{
					codes.DeadlineExceeded,
					codes.Internal,
					codes.Unavailable,
				}, gax.Backoff{
					Initial:    100 * time.Millisecond,
					Max:        60000 * time.Millisecond,
					Multiplier: 1.30,
				})
			}),
		},
	}
}

// MetricsClient is a client for interacting with Cloud Logging API.
//
// Methods, except Close, may be called concurrently. However, fields must not be modified concurrently with method calls.
type MetricsClient struct {
	// Connection pool of gRPC connections to the service.
	connPool gtransport.ConnPool

	// The gRPC API client.
	metricsClient loggingpb.MetricsServiceV2Client

	// The call options for this service.
	CallOptions *MetricsCallOptions

	// The x-goog-* metadata to be sent with each request.
	xGoogMetadata metadata.MD
}

// NewMetricsClient creates a new metrics service v2 client.
//
// Service for configuring logs-based metrics.
func NewMetricsClient(ctx context.Context, opts ...option.ClientOption) (*MetricsClient, error) {
	clientOpts := defaultMetricsClientOptions()

	if newMetricsClientHook != nil {
		hookOpts, err := newMetricsClientHook(ctx, clientHookParams{})
		if err != nil {
			return nil, err
		}
		clientOpts = append(clientOpts, hookOpts...)
	}

	connPool, err := gtransport.DialPool(ctx, append(clientOpts, opts...)...)
	if err != nil {
		return nil, err
	}
	c := &MetricsClient{
		connPool:    connPool,
		CallOptions: defaultMetricsCallOptions(),

		metricsClient: loggingpb.NewMetricsServiceV2Client(connPool),
	}
	c.setGoogleClientInfo()

	return c, nil
}

// Connection returns a connection to the API service.
//
// Deprecated.
func (c *MetricsClient) Connection() *grpc.ClientConn {
	return c.connPool.Conn()
}

// Close closes the connection to the API service. The user should invoke this when
// the client is no longer required.
func (c *MetricsClient) Close() error {
	return c.connPool.Close()
}

// setGoogleClientInfo sets the name and version of the application in
// the `x-goog-api-client` header passed on each request. Intended for
// use by Google-written clients.
func (c *MetricsClient) setGoogleClientInfo(keyval ...string) {
	kv := append([]string{"gl-go", versionGo()}, keyval...)
	kv = append(kv, "gapic", versionClient, "gax", gax.Version, "grpc", grpc.Version)
	c.xGoogMetadata = metadata.Pairs("x-goog-api-client", gax.XGoogHeader(kv...))
}

// ListLogMetrics lists logs-based metrics.
func (c *MetricsClient) ListLogMetrics(ctx context.Context, req *loggingpb.ListLogMetricsRequest, opts ...gax.CallOption) *LogMetricIterator {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "parent", url.QueryEscape(req.GetParent())))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.ListLogMetrics[0:len(c.CallOptions.ListLogMetrics):len(c.CallOptions.ListLogMetrics)], opts...)
	it := &LogMetricIterator{}
	req = proto.Clone(req).(*loggingpb.ListLogMetricsRequest)
	it.InternalFetch = func(pageSize int, pageToken string) ([]*loggingpb.LogMetric, string, error) {
		var resp *loggingpb.ListLogMetricsResponse
		req.PageToken = pageToken
		if pageSize > math.MaxInt32 {
			req.PageSize = math.MaxInt32
		} else {
			req.PageSize = int32(pageSize)
		}
		err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
			var err error
			resp, err = c.metricsClient.ListLogMetrics(ctx, req, settings.GRPC...)
			return err
		}, opts...)
		if err != nil {
			return nil, "", err
		}

		it.Response = resp
		return resp.GetMetrics(), resp.GetNextPageToken(), nil
	}
	fetch := func(pageSize int, pageToken string) (string, error) {
		items, nextPageToken, err := it.InternalFetch(pageSize, pageToken)
		if err != nil {
			return "", err
		}
		it.items = append(it.items, items...)
		return nextPageToken, nil
	}
	it.pageInfo, it.nextFunc = iterator.NewPageInfo(fetch, it.bufLen, it.takeBuf)
	it.pageInfo.MaxSize = int(req.GetPageSize())
	it.pageInfo.Token = req.GetPageToken()
	return it
}

// GetLogMetric gets a logs-based metric.
func (c *MetricsClient) GetLogMetric(ctx context.Context, req *loggingpb.GetLogMetricRequest, opts ...gax.CallOption) (*loggingpb.LogMetric, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "metric_name", url.QueryEscape(req.GetMetricName())))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.GetLogMetric[0:len(c.CallOptions.GetLogMetric):len(c.CallOptions.GetLogMetric)], opts...)
	var resp *loggingpb.LogMetric
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.metricsClient.GetLogMetric(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateLogMetric creates a logs-based metric.
func (c *MetricsClient) CreateLogMetric(ctx context.Context, req *loggingpb.CreateLogMetricRequest, opts ...gax.CallOption) (*loggingpb.LogMetric, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "parent", url.QueryEscape(req.GetParent())))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.CreateLogMetric[0:len(c.CallOptions.CreateLogMetric):len(c.CallOptions.CreateLogMetric)], opts...)
	var resp *loggingpb.LogMetric
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.metricsClient.CreateLogMetric(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateLogMetric creates or updates a logs-based metric.
func (c *MetricsClient) UpdateLogMetric(ctx context.Context, req *loggingpb.UpdateLogMetricRequest, opts ...gax.CallOption) (*loggingpb.LogMetric, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "metric_name", url.QueryEscape(req.GetMetricName())))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.UpdateLogMetric[0:len(c.CallOptions.UpdateLogMetric):len(c.CallOptions.UpdateLogMetric)], opts...)
	var resp *loggingpb.LogMetric
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.metricsClient.UpdateLogMetric(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteLogMetric deletes a logs-based metric.
func (c *MetricsClient) DeleteLogMetric(ctx context.Context, req *loggingpb.DeleteLogMetricRequest, opts ...gax.CallOption) error {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "metric_name", url.QueryEscape(req.GetMetricName())))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.DeleteLogMetric[0:len(c.CallOptions.DeleteLogMetric):len(c.CallOptions.DeleteLogMetric)], opts...)
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		_, err = c.metricsClient.DeleteLogMetric(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	return err
}

// LogMetricIterator manages a stream of *loggingpb.LogMetric.
type LogMetricIterator struct {
	items    []*loggingpb.LogMetric
	pageInfo *iterator.PageInfo
	nextFunc func() error

	// Response is the raw response for the current page.
	// It must be cast to the RPC response type.
	// Calling Next() or InternalFetch() updates this value.
	Response interface{}

	// InternalFetch is for use by the Google Cloud Libraries only.
	// It is not part of the stable interface of this package.
	//
	// InternalFetch returns results from a single call to the underlying RPC.
	// The number of results is no greater than pageSize.
	// If there are no more results, nextPageToken is empty and err is nil.
	InternalFetch func(pageSize int, pageToken string) (results []*loggingpb.LogMetric, nextPageToken string, err error)
}

// PageInfo supports pagination. See the google.golang.org/api/iterator package for details.
func (it *LogMetricIterator) PageInfo() *iterator.PageInfo {
	return it.pageInfo
}

// Next returns the next result. Its second return value is iterator.Done if there are no more
// results. Once Next returns Done, all subsequent calls will return Done.
func (it *LogMetricIterator) Next() (*loggingpb.LogMetric, error) {
	var item *loggingpb.LogMetric
	if err := it.nextFunc(); err != nil {
		return item, err
	}
	item = it.items[0]
	it.items = it.items[1:]
	return item, nil
}

func (it *LogMetricIterator) bufLen() int {
	return len(it.items)
}

func (it *LogMetricIterator) takeBuf() interface{} {
	b := it.items
	it.items = nil
	return b
}
