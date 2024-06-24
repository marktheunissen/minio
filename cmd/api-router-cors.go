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
	"errors"
	"fmt"
	"net/http"

	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/mux"
	xcors "github.com/minio/pkg/v3/cors"
	"github.com/minio/pkg/v3/wildcard"

	rscors "github.com/rs/cors"
)

// There are two ways to apply CORS in MinIO:
// 1. Global CORS settings: This was the original method that applied to the entire API surface,
//    and was limited to just allowed origins.
// 2. Bucket-specific CORS settings: This is the new method that allows for more fine-grained
//    control over CORS settings, and can be applied on a per-bucket basis. It uses AWS's own spec
//    that allows a number of rules to be specified.
//    https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html

// corsHandler returns a middleware that is able to either apply bucket-specific CORS settings if they exist,
// or fallback to the global CORS settings if they don't.
func corsHandler(handler http.Handler) http.Handler {
	corsGlobal := corsGlobalHandler(handler)
	logger.Info("hello corsHandler")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		bucket := vars["bucket"]
		if bucket == "" {
			// No bucket, continue the request using global cors.
			logger.Info("corsHandler no bucket in request")
			corsGlobal.ServeHTTP(w, r)
			return
		}

		// TODO: Bucket existence check - do we need to do this explicitly, or can GetCorsConfig itself handle that? - seems fine in running.
		// Check if the bucket has a CORS config set.
		config, _, err := globalBucketMetadataSys.GetCorsConfig(bucket)
		if err != nil {
			if errors.Is(err, BucketCorsNotFound{Bucket: bucket}) {
				logger.Info("corsHandler bucket cors not found")
				// No CORS config set on the bucket, continue with the request using global cors.
				corsGlobal.ServeHTTP(w, r)
				return
			}
			logger.Info("another error was encountered, not BucketCorsNotFound: %v", err.Error())
			// TODO: Don't fall back to global cors as that may be a security risk.
			writeErrorResponse(r.Context(), w, toAPIError(r.Context(), err), r.URL)
			return
		}

		// We have bucket specific cors settings, use them instead of global cors handling.
		logger.Info("corsHandler bucket cors found")
		opts, err := matchCorsRule(r, config)
		if err != nil {
			// TODO: No rule found, what now? test what happens on aws in this case. Maybe just fall back to global rules.
			logger.Info("no rule found by matchCorsRule")
			corsGlobal.ServeHTTP(w, r)
			return
		}
		rscors.New(*opts).ServeHTTP(w, r, handler.ServeHTTP)
		return
	})
}

func matchCorsRule(r *http.Request, config *xcors.Config) (*rscors.Options, error) {
	// AWS Docs: When Amazon S3 receives a cross-origin request (or a pre-flight OPTIONS request) against a bucket, it
	// evaluates the cors configuration on the bucket and uses the first CORSRule rule that matches the incoming browser
	// request to enable a cross-origin request. For a rule to match, the following conditions must be met:
	// - The request's Origin header must match AllowedOrigin elements.
	// - The request method (for example, GET, PUT, HEAD, and so on) or the Access-Control-Request-Method header in
	//   case of a pre-flight OPTIONS request must be one of the AllowedMethod elements.
	// - Every header specified in the Access-Control-Request-Headers request header of a pre-flight request must
	//   match an AllowedHeader element.
	logger.Info("matchCorsRule called: %+v", config)

	method := r.Method
	origin := r.Header.Get("Origin")
	acrMethod := r.Header.Get("Access-Control-Request-Method")
	acrHeaders := r.Header.Values("Access-Control-Request-Headers")

	// Find the first matching rule, convert to a rscors.Options
	var opts *rscors.Options
	for _, rule := range config.CORSRules {
		logger.Info("testing matchCorsRule rule: %+v, origin: %v, method: %v, acrMethod: %v, acrHeaders: %v", rule, origin, method, acrMethod, acrHeaders)
		opts = tryMatch(rule, origin, method, acrMethod, acrHeaders)
		if opts != nil {
			break
		}
	}
	if opts == nil {
		return nil, fmt.Errorf("no matching CORS rule found for origin: %s", origin)
	}
	return opts, nil
}

func tryMatch(rule xcors.Rule, origin string, method string, acrMethod string, acrHeaders []string) *rscors.Options {
	allowed, replaceOrigin := rule.HasAllowedOrigin(origin)
	if !allowed {
		return nil
	}

	if method == http.MethodOptions {
		// The request is an OPTIONS pre-flight request, the Access-Control-Request-Method
		// header specifies the method to test.
		if !rule.HasAllowedMethod(acrMethod) {
			return nil
		}

		if len(acrHeaders) == 0 || rule.HasAllOfAllowedHeaders(acrHeaders) {
			return ruleToCorsOptions(&rule, replaceOrigin)
		}
	} else if rule.HasAllowedMethod(method) {
		return ruleToCorsOptions(&rule, replaceOrigin)
	}
	return nil
}

func ruleToCorsOptions(rule *xcors.Rule, replaceOrigin string) *rscors.Options {
	opts := &rscors.Options{
		AllowedOrigins:   rule.AllowedOrigin,
		AllowedMethods:   rule.AllowedMethod,
		AllowedHeaders:   rule.AllowedHeader,
		ExposedHeaders:   rule.ExposeHeader,
		MaxAge:           rule.MaxAgeSeconds,
		AllowCredentials: false, // TODO: Test real S3 to check credentials
	}
	if replaceOrigin != "" {
		opts.AllowedOrigins = []string{replaceOrigin}
	}

	return opts
}

// corsGlobalHandler returns a handler for CORS (Cross Origin Resource Sharing) settings that have been applied
// globally via the "cors_allow_origin" setting. These can be overridden by bucket-specific cors settings by using
// the corsHandler middleware instead.
func corsGlobalHandler(handler http.Handler) http.Handler {
	logger.Info("corsGlobalHandler called")
	commonS3Headers := []string{
		xhttp.Date,
		xhttp.ETag,
		xhttp.ServerInfo,
		xhttp.Connection,
		xhttp.AcceptRanges,
		xhttp.ContentRange,
		xhttp.ContentEncoding,
		xhttp.ContentLength,
		xhttp.ContentType,
		xhttp.ContentDisposition,
		xhttp.LastModified,
		xhttp.ContentLanguage,
		xhttp.CacheControl,
		xhttp.RetryAfter,
		xhttp.AmzBucketRegion,
		xhttp.Expires,
		"X-Amz*",
		"x-amz*",
		"*",
	}
	opts := rscors.Options{
		AllowOriginFunc: func(origin string) bool {
			for _, allowedOrigin := range globalAPIConfig.getCorsAllowOrigins() {
				if wildcard.MatchSimple(allowedOrigin, origin) {
					return true
				}
			}
			return false
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPut,
			http.MethodHead,
			http.MethodPost,
			http.MethodDelete,
			http.MethodOptions,
			http.MethodPatch,
		},
		AllowedHeaders:   commonS3Headers,
		ExposedHeaders:   commonS3Headers,
		AllowCredentials: true,
	}
	return rscors.New(opts).Handler(handler)
}
