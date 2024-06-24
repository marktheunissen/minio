// Copyright (c) 2015-2024 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	xhttp "github.com/minio/minio/internal/http"
	xcors "github.com/minio/pkg/v3/cors"
	rscors "github.com/rs/cors"

	"github.com/stretchr/testify/assert"
)

type corsRuleMatcherTest struct {
	name       string
	reqMethod  string
	reqHeaders http.Header
	wantErr    bool
	wantOpts   *rscors.Options
}

func TestCorsRuleMatcher(t *testing.T) {
	testRule := []struct {
		name   string
		config []xcors.Rule
		tests  []corsRuleMatcherTest
	}{
		{
			name: "origin wildcard get method",
			config: []xcors.Rule{
				{
					AllowedOrigin: []string{"*"},
					AllowedMethod: []string{"GET"},
				},
			},
			tests: []corsRuleMatcherTest{
				{
					name:      "match method",
					reqMethod: "GET",
					reqHeaders: http.Header{
						"Origin": []string{"http://example.com"},
					},
					wantErr: false,
					wantOpts: &rscors.Options{
						AllowedOrigins: []string{"*"},
						AllowedMethods: []string{"GET"},
					},
				},
				{
					name:      "no match wrong method",
					reqMethod: "POST",
					reqHeaders: http.Header{
						"Origin": []string{"http://example.com"},
					},
					wantErr: true,
				},
				{
					name:      "match preflight",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						"Origin":                        []string{"http://example.com"},
						"Access-Control-Request-Method": []string{"GET"},
					},
					wantErr: false,
					wantOpts: &rscors.Options{
						AllowedOrigins: []string{"*"},
						AllowedMethods: []string{"GET"},
					},
				},
				{
					name:      "no match preflight",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						"Origin":                        []string{"http://example.com"},
						"Access-Control-Request-Method": []string{"POST"},
					},
					wantErr: true,
				},
			},
		},
		{
			// example 1 from https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html#cors-allowed-origin
			name: "aws example 1",
			config: []xcors.Rule{
				{
					AllowedOrigin: []string{"http://www.example1.com"},
					AllowedMethod: []string{"PUT", "POST", "DELETE"},
					AllowedHeader: []string{"*"},
				},
				{
					AllowedOrigin: []string{"http://www.example2.com"},
					AllowedMethod: []string{"PUT", "POST", "DELETE"},
					AllowedHeader: []string{"*"},
				},
				{
					AllowedOrigin: []string{"*"},
					AllowedMethod: []string{"GET"},
				},
			},
			tests: []corsRuleMatcherTest{
				{
					name:      "match example1 origin",
					reqMethod: "PUT",
					reqHeaders: http.Header{
						"Origin": []string{"http://www.example1.com"},
					},
					wantErr: false,
					wantOpts: &rscors.Options{
						AllowedOrigins: []string{"http://www.example1.com"},
						AllowedMethods: []string{"PUT", "POST", "DELETE"},
						AllowedHeaders: []string{"*"},
					},
				},
				{
					name:      "match example2 origin",
					reqMethod: "PUT",
					reqHeaders: http.Header{
						"Origin": []string{"http://www.example2.com"},
					},
					wantErr: false,
					wantOpts: &rscors.Options{
						AllowedOrigins: []string{"http://www.example2.com"},
						AllowedMethods: []string{"PUT", "POST", "DELETE"},
						AllowedHeaders: []string{"*"},
					},
				},
				{
					name:      "match wildcard origin",
					reqMethod: "GET",
					reqHeaders: http.Header{
						"Origin": []string{"http://www.example3.com"},
					},
					wantErr: false,
					wantOpts: &rscors.Options{
						AllowedOrigins: []string{"*"},
						AllowedMethods: []string{"GET"},
						// TODO: AllowedHeaders: []string{"*"}, ?
					},
				},
				{
					name:      "no match wrong method",
					reqMethod: "POST",
					reqHeaders: http.Header{
						"Origin": []string{"http://www.example3.com"},
					},
					wantErr: true,
				},
				{
					name:      "match preflight example1 origin",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						"Origin":                         []string{"http://www.example1.com"},
						"Access-Control-Request-Method":  []string{"PUT"},
						"Access-Control-Request-Headers": []string{xhttp.AcceptRanges, xhttp.ContentRange, xhttp.ContentEncoding},
					},
					wantErr: false,
					wantOpts: &rscors.Options{
						AllowedOrigins: []string{"http://www.example1.com"},
						AllowedMethods: []string{"PUT", "POST", "DELETE"},
						AllowedHeaders: []string{"*"},
					},
				},
			},
		},
		{
			// example 2 from https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html#cors-allowed-origin
			name: "aws example 2",
			config: []xcors.Rule{
				{
					AllowedOrigin: []string{"http://www.example.com"},
					AllowedMethod: []string{"PUT", "POST", "DELETE"},
					AllowedHeader: []string{"*"},
					MaxAgeSeconds: 3000,
					ExposeHeader:  []string{"x-amz-server-side-encryption", "x-amz-request-id", "x-amz-id-2"},
				},
			},
			tests: []corsRuleMatcherTest{
				{
					name: "match",
					reqHeaders: http.Header{
						"Origin": []string{"http://www.example.com"},
					},
					reqMethod: "PUT",
					wantErr:   false,
					wantOpts: &rscors.Options{
						AllowedOrigins: []string{"http://www.example.com"},
						AllowedMethods: []string{"PUT", "POST", "DELETE"},
						AllowedHeaders: []string{"*"},
						MaxAge:         3000,
						ExposedHeaders: []string{"x-amz-server-side-encryption", "x-amz-request-id", "x-amz-id-2"},
					},
				},
				{
					name: "match preflight",
					reqHeaders: http.Header{
						"Origin":                        []string{"http://www.example.com"},
						"Access-Control-Request-Method": []string{"PUT"},
					},
					reqMethod: "OPTIONS",
					wantErr:   false,
					wantOpts: &rscors.Options{
						AllowedOrigins: []string{"http://www.example.com"},
						AllowedMethods: []string{"PUT", "POST", "DELETE"},
						AllowedHeaders: []string{"*"},
						MaxAge:         3000,
						ExposedHeaders: []string{"x-amz-server-side-encryption", "x-amz-request-id", "x-amz-id-2"},
					},
				},
			},
		},
		{
			name: "general https origin",
			config: []xcors.Rule{
				{
					AllowedOrigin: []string{"https"},
					AllowedMethod: []string{"POST"},
				},
			},
			tests: []corsRuleMatcherTest{
				{
					name: "match",
					reqHeaders: http.Header{
						"Origin": []string{"https://example.com"},
					},
					reqMethod: "POST",
					wantErr:   false,
					wantOpts: &rscors.Options{
						AllowedOrigins: []string{"https://example.com"},
						AllowedMethods: []string{"POST"},
					},
				},
			},
		},
	}

	for _, trule := range testRule {
		for _, test := range trule.tests {
			t.Run(trule.name+"/"+test.name, func(t *testing.T) {
				req := httptest.NewRequest(test.reqMethod, "http://localhost", nil)
				req.Header = test.reqHeaders

				opts, err := matchCorsRule(req, &xcors.Config{CORSRules: trule.config})
				if test.wantErr {
					assert.Error(t, err)
				} else {
					// TODO: Remove testify then re-request it
					assert.Equal(t, test.wantOpts, opts)
				}
			})
		}
	}
}
