package server

import (
	"fmt"
	"net/http"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

func NewLog(config *Config, log api.Log) http.Handler {
	server := newServer(config)
	server.register(types.EndpointGetTreeHead, http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cth, err := log.GetTreeHead(r.Context())
			if err == nil {
				err = cth.ToASCII(w)
			}
			if err != nil {
				reportError(w, r.URL, err)
			}
		}))
	server.register(types.EndpointGetInclusionProof, http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.InclusionProof
			if err := req.FromURLArgs(GetSigsumURLArguments(r)); err != nil {
				reportErrorCode(w, r.URL, http.StatusBadRequest, err)
			}
			if req.Size < 2 {
				// Size:0 => not possible to prove inclusion of anything
				// Size:1 => you don't need an inclusion proof (it is always empty)
				reportErrorCode(w, r.URL, http.StatusBadRequest,
					fmt.Errorf("size(%d) must be larger than one",
						req.Size))
				return
			}
			proof, err := log.GetInclusionProof(r.Context(), req)
			if err == nil {
				err = proof.ToASCII(w)
			}
			if err != nil {
				reportError(w, r.URL, err)
			}
		}))
	server.register(types.EndpointGetConsistencyProof, http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.ConsistencyProof
			if err := req.FromURLArgs(GetSigsumURLArguments(r)); err != nil {
				reportErrorCode(w, r.URL, http.StatusBadRequest, err)
			}
			if req.OldSize < 1 {
				reportErrorCode(w, r.URL, http.StatusBadRequest,
					fmt.Errorf("old_size(%d) must be larger than zero",
						req.OldSize))
				return
			}
			if req.NewSize <= req.OldSize {
				reportErrorCode(w, r.URL, http.StatusBadRequest,
					fmt.Errorf("new_size(%d) must be larger than old_size(%d)",
						req.NewSize, req.OldSize))
				return
			}
			proof, err := log.GetConsistencyProof(r.Context(), req)
			if err == nil {
				err = proof.ToASCII(w)
			}
			if err != nil {
				reportError(w, r.URL, err)
			}
		}))
	server.register(types.EndpointGetConsistencyProof, http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		}))

	server.register(types.EndpointAddLeaf, http.MethodPost,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.Leaf
			var submitHeader *token.SubmitHeader
			if err := req.FromASCII(r.Body); err != nil {
				reportErrorCode(w, r.URL, http.StatusBadRequest, err)
				return
			}
			if headerValue := r.Header.Get("Sigsum-Token"); len(headerValue) > 0 {
				submitHeader = &token.SubmitHeader{}
				if err := submitHeader.FromHeader(headerValue); err != nil {
					reportErrorCode(w, r.URL, http.StatusBadRequest, fmt.Errorf("Invalid Sigsum-Submit: header: %v", err))
					return
				}
			}
			// TODO: Change AddLeaf to return api.ErrAccepted, instead of the persisted flag?
			persisted, err := log.AddLeaf(r.Context(), req, submitHeader)
			if err != nil {
				reportError(w, r.URL, err)
				return
			}
			if !persisted {
				reportError(w, r.URL, api.ErrAccepted)
			}
		}))
	server.register(types.EndpointGetLeaves, http.MethodGet,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requests.Leaves
			if err := req.FromURLArgs(GetSigsumURLArguments(r)); err != nil {
				reportErrorCode(w, r.URL, http.StatusBadRequest, err)
				return
			}
			if req.StartIndex >= req.EndIndex {
				reportErrorCode(w, r.URL, http.StatusBadRequest,
					fmt.Errorf("start_index(%d) must be less than end_index(%d)",
						req.StartIndex, req.EndIndex))
				return
			}
			leaves, err := log.GetLeaves(r.Context(), req)
			if err == nil {
				err = types.LeavesToASCII(w, leaves)
			}
			if err != nil {
				reportError(w, r.URL, err)
			}
		}))

	return server
}
