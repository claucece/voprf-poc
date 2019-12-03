package client

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/alxdavids/oprf-poc/go/jsonrpc"
	"github.com/alxdavids/oprf-poc/go/oerr"
	"github.com/alxdavids/oprf-poc/go/oprf"
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
)

var (
	storedInputs       [][]byte
	storedBlinds       []*big.Int
	storedFinalOutputs [][]byte
)

// Config holds all the relevant information for a client-side OPRF
// implementation
type Config struct {
	ocli oprf.Client
	n    int
	addr string
}

// CreateConfig instantiates the client that will communicate with the HTTP
// server that runs the OPRF server-side instance
func CreateConfig(ciphersuite string, pogInit gg.PrimeOrderGroup, n int) (*Config, oerr.Error) {
	ptpnt, err := oprf.Client{}.Setup(ciphersuite, pogInit)
	if err.Err() != nil {
		return nil, err
	}
	ocli, err := oprf.CastClient(ptpnt)
	if err.Err() != nil {
		return nil, err
	}

	// create server config
	cfg := &Config{
		ocli: ocli,
		n:    n,
		addr: "localhost:3001",
	}
	return cfg, oerr.Nil()
}

// sendOPRFRequest constructs and sends an OPRF request to the OPRF server
// instance. The response is processed by running hte Unblind() and Finalize()
// functionalities.
func (cfg *Config) sendOPRFRequest() ([][]byte, oerr.Error) {
	oprfReq, err := cfg.createOPRFRequest()
	if err.Err() != nil {
		return nil, err
	}
	buf, e := json.Marshal(oprfReq)
	if e != nil {
		return nil, oerr.ErrClientInternal
	}

	// make HTTP request and parse Response
	resp, e := http.Post(cfg.addr, "application/json", bytes.NewBuffer(buf))
	if e != nil {
		return nil, oerr.ErrClientInternal
	}

	// read response body
	defer resp.Body.Close()
	body, e := ioutil.ReadAll(resp.Body)
	if e != nil {
		return nil, oerr.ErrServerResponse
	}

	// attempt to parse Server JSONRPC response
	jsonrpcResp, err := cfg.parseJSONRPCResponse(body)
	if err.Err() != nil {
		return nil, err
	}

	// Process and finalize the server response
	return cfg.processServerResponse(jsonrpcResp)
}

// createOPRFRequest creates the first message in the OPRF protocol to send to
// the OPRF server. The parameter n indicates the number of tokens that should
// be sent
//
// TODO: allow n to be greater than 1
func (cfg *Config) createOPRFRequest() (*jsonrpc.Request, oerr.Error) {
	n := cfg.n
	if n > 1 || n < 0 {
		return nil, oerr.ErrClientUnsupported
	}
	var inputs [][]byte
	var blinds []*big.Int
	var encodedElements [][]byte
	for i := 0; i < n; i++ {
		// sample a random input
		buf := make([]byte, 32)
		_, e := rand.Read(buf)
		if e != nil {
			return nil, oerr.ErrClientInternal
		}
		inputs = append(inputs, buf)

		// create a blinded group element
		ge, blind, err := cfg.ocli.Blind(buf)
		if err.Err() != nil {
			return nil, err
		}
		blinds = append(blinds, blind)

		// Encode group element
		encoded, err := ge.Serialize()
		if err.Err() != nil {
			return nil, err
		}
		encodedElements = append(encodedElements, encoded)
	}
	// store in globals
	storedInputs = inputs
	storedBlinds = blinds
	// return JSONRPC Request object
	return cfg.createJSONRPCRequest(encodedElements, 1), oerr.Nil()
}

func (cfg *Config) processServerResponse(jsonrpcResp *jsonrpc.ResponseSuccess) ([][]byte, oerr.Error) {
	// parse returned group element and unblind
	params := jsonrpcResp.Result
	pog := cfg.ocli.Ciphersuite().POG()
	var finalOutputs [][]byte
	for i := 0; i < cfg.n; i++ {
		buf, e := hex.DecodeString(params[i])
		if e != nil {
			return nil, oerr.ErrServerResponse
		}
		Z, err := gg.CreateGroupElement(pog).Deserialize(buf)
		if err.Err() != nil {
			return nil, err
		}
		N, err := cfg.ocli.Unblind(Z, storedBlinds[i])
		if err.Err() != nil {
			return nil, err
		}
		aux := []byte("oprf_finalization_step")
		y, err := cfg.ocli.Finalize(N, storedInputs[i], aux)
		if err.Err() != nil {
			return nil, err
		}
		finalOutputs = append(finalOutputs, y)
	}
	return finalOutputs, oerr.Nil()
}

// createJSONRPCRequest creates the JSONRPC Request object for sending to the
// OPRF server instance
func (cfg *Config) createJSONRPCRequest(eles [][]byte, id int) *jsonrpc.Request {
	var hexParams []string
	for _, buf := range eles {
		hexParams = append(hexParams, hex.EncodeToString(buf))
	}
	return &jsonrpc.Request{
		Version: "2.0",
		Method:  "eval",
		Params:  hexParams,
		ID:      id,
	}
}

// parseJSONRPCResponse attempts to parse a JSONRPC successful response object.
// If the server has sent an error response then it returns an error instead.
func (cfg *Config) parseJSONRPCResponse(body []byte) (*jsonrpc.ResponseSuccess, oerr.Error) {
	// attempt to parse success
	jsonrpcSuccess := &jsonrpc.ResponseSuccess{}
	jsonrpcError := &jsonrpc.ResponseError{}
	e := json.Unmarshal(body, jsonrpcSuccess)
	if e != nil {
		return nil, oerr.ErrServerResponse
	}

	// if this occurs then it's likely that an error occurred
	if len(jsonrpcSuccess.Result) == 0 {
		// try and decode error response
		e2 := json.Unmarshal(body, jsonrpcError)
		if e2 != nil || jsonrpcError.Error.Message == "" {
			// either error or unable to parse error
			return nil, oerr.ErrServerResponse
		}
		return nil, oerr.New(jsonrpcError.Error.Message, jsonrpcError.Error.Code)
	}

	// otherwise return success
	return jsonrpcSuccess, oerr.Nil()
}