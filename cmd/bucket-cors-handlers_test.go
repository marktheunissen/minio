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
	"bytes"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/minio/minio/internal/auth"
)

type bucketCorsTestCase struct {
	name       string
	method     string
	bucketName string
	accessKey  string
	secretKey  string
	// Sent body
	body []byte
	// Expected response
	wantStatus   int
	wantCorsResp []byte
	wantErrResp  *APIErrorResponse
}

// TestBucketCorsWrongCredentials tests the authentication layer is correctly applied
func TestBucketCorsWrongCredentials(t *testing.T) {
	args := ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testBucketCorsHandlersWrongCredentials,
		endpoints:  []string{"GetBucketCors", "PutBucketCors", "DeleteBucketCors"},
	}
	ExecObjectLayerAPITest(args)
}

// testBucketCorsHandlersWrongCredentials tests the authentication layer is correctly applied
func testBucketCorsHandlersWrongCredentials(obj ObjectLayer, instanceType, bucketName string, apiRouter http.Handler, credentials auth.Credentials, t *testing.T) {
	resource := SlashSeparator + bucketName + SlashSeparator
	fakeAccessKey := "AKIAAAAAAAAAABBBBCCC"
	fakeSecretKey := "rJQyQkXGGGGGGGG+AAAABBBBCCCCDDDDEEEFFFFF"
	testCases := []bucketCorsTestCase{
		{
			name:       "GET empty credentials",
			method:     http.MethodGet,
			bucketName: bucketName,
			accessKey:  "",
			secretKey:  "",
			wantStatus: http.StatusForbidden,
			wantErrResp: &APIErrorResponse{
				Resource: resource,
				Code:     "AccessDenied",
				Message:  "Access Denied.",
			},
		},
		{
			name:       "GET wrong credentials",
			method:     http.MethodGet,
			bucketName: bucketName,
			accessKey:  fakeAccessKey,
			secretKey:  fakeSecretKey,
			wantStatus: http.StatusForbidden,
			wantErrResp: &APIErrorResponse{
				Resource: resource,
				Code:     "InvalidAccessKeyId",
				Message:  "The Access Key Id you provided does not exist in our records.",
			},
		},
		{
			name:       "PUT empty credentials",
			method:     http.MethodPut,
			bucketName: bucketName,
			accessKey:  "",
			secretKey:  "",
			wantStatus: http.StatusForbidden,
			wantErrResp: &APIErrorResponse{
				Resource: resource,
				Code:     "AccessDenied",
				Message:  "Access Denied.",
			},
		},
		{
			name:       "PUT wrong credentials",
			method:     http.MethodPut,
			bucketName: bucketName,
			accessKey:  fakeAccessKey,
			secretKey:  fakeSecretKey,
			wantStatus: http.StatusForbidden,
			wantErrResp: &APIErrorResponse{
				Resource: resource,
				Code:     "InvalidAccessKeyId",
				Message:  "The Access Key Id you provided does not exist in our records.",
			},
		},
		{
			name:       "DELETE empty credentials",
			method:     http.MethodDelete,
			bucketName: bucketName,
			accessKey:  "",
			secretKey:  "",
			wantStatus: http.StatusForbidden,
			wantErrResp: &APIErrorResponse{
				Resource: resource,
				Code:     "AccessDenied",
				Message:  "Access Denied.",
			},
		},
		{
			name:       "DELETE wrong credentials",
			method:     http.MethodDelete,
			bucketName: bucketName,
			accessKey:  fakeAccessKey,
			secretKey:  fakeSecretKey,
			wantStatus: http.StatusForbidden,
			wantErrResp: &APIErrorResponse{
				Resource: resource,
				Code:     "InvalidAccessKeyId",
				Message:  "The Access Key Id you provided does not exist in our records.",
			},
		},
	}

	testBucketCors(obj, instanceType, bucketName, apiRouter, t, testCases)
}

// testBucketCors does the actual running of the steps of the test case
func testBucketCors(obj ObjectLayer, instanceType, bucketName string, apiRouter http.Handler, t *testing.T, testCases []bucketCorsTestCase) {
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// HTTP request and recorder
			rec := httptest.NewRecorder()
			req, err := newTestSignedRequestV4(test.method,
				getBucketCorsURL("", test.bucketName),
				int64(len(test.body)),
				bytes.NewReader(test.body),
				test.accessKey,
				test.secretKey,
				nil,
			)
			if err != nil {
				t.Fatalf("Instance: %s, error creating request: %s", instanceType, err)
			}

			// Execute the handler
			apiRouter.ServeHTTP(rec, req)
			if rec.Code != test.wantStatus {
				t.Errorf("Instance: %s, want status code: %d, got: %d", instanceType, test.wantStatus, rec.Code)
			}

			// Check non-error body response against wanted
			if test.wantCorsResp != nil {
				if !bytes.Equal(test.wantCorsResp, rec.Body.Bytes()) {
					t.Errorf("Instance: %s, want response: %s, got: %s", instanceType, string(test.wantCorsResp), rec.Body.String())
				}
			}

			// Check error response against wanted
			if test.wantErrResp != nil {
				errResp := APIErrorResponse{}
				err = xml.Unmarshal(rec.Body.Bytes(), &errResp)
				if err != nil {
					t.Fatalf("Instance: %s, error unmarshalling error response: %s", instanceType, err)
				}
				if errResp.Resource != test.wantErrResp.Resource {
					t.Errorf("Instance: %s, want APIErrorResponse.Resource: %s, got: %s", instanceType, test.wantErrResp.Resource, errResp.Resource)
				}
				if errResp.Message != test.wantErrResp.Message {
					t.Errorf("Instance: %s, want APIErrorResponse.Message: %s, got: %s", instanceType, test.wantErrResp.Message, errResp.Message)
				}
				if errResp.Code != test.wantErrResp.Code {
					t.Errorf("Instance: %s, want APIErrorResponse.Code: %s, got: %s", instanceType, test.wantErrResp.Code, errResp.Code)
				}
			}
		})
	}
}
