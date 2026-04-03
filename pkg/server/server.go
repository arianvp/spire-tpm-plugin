/*
 ** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/bloomberg/spire-tpm-plugin/pkg/common"
	"github.com/google/go-attestation/attest"
	x509ext "github.com/google/go-attestation/x509"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	trustDomain string
	CaPath      string          `hcl:"ca_path"`
	HashPath    string          `hcl:"hash_path"`
	AWS         AWSConfig       `hcl:"aws"`
	PVE         PVEGlobalConfig `hcl:"pve"`
}

type AWSConfig struct {
	Enabled      bool    `hcl:"enabled"`
	HashPath     string  `hcl:"hash_path"`
}

type PVEGlobalConfig struct {
	Enabled  bool                 `hcl:"enabled"`
	Clusters map[string]PVEConfig `hcl:"cluster"`
}

type PVEConfig struct {
	Hosts                []string `hcl:"hosts"`                // List of PVE control plane hosts
	Port                 int      `hcl:"port"`                 // Optional port, defaults to 9443
	ExpectedSpiffeID     string   `hcl:"expected_spiffe_id"`   // SPIFFE ID to validate on PVE nodes
	HashPath             string   `hcl:"hash_path"`            // Optional path to check hashes
}

// Plugin implements the nodeattestor Plugin interface
type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer
	config           *Config
	m                sync.Mutex
	identityProvider identityproviderv1.IdentityProviderServiceClient
}

func New() *Plugin {
	return &Plugin{}
}

func NewFromConfig(config *Config) *Plugin {
	return &Plugin{config: config}
}

func (p *Plugin) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	if !broker.BrokerClient(&p.identityProvider) {
		return status.Errorf(codes.FailedPrecondition, "IdentityProvider host service is required")
	}
	return nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := &Config{}
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, fmt.Errorf("failed to decode configuration file: %v", err)
	}

	if req.CoreConfiguration == nil {
		return nil, errors.New("global configuration is required")
	}
	if req.CoreConfiguration.TrustDomain == "" {
		return nil, errors.New("trust_domain is required")
	}

	if config.PVE.Enabled {
		newClusters := make(map[string]PVEConfig)
		if len(config.PVE.Clusters) == 0 {
			return nil, errors.New("at least one pve cluster must be defined when pve is enabled")
		}
		for name, cluster := range config.PVE.Clusters {
			if cluster.Port == 0 {
				cluster.Port = 9443
			}
			if len(cluster.Hosts) == 0 {
				return nil, fmt.Errorf("pve hosts list is required for cluster %s", name)
			}
			if cluster.ExpectedSpiffeID == "" {
				cluster.ExpectedSpiffeID = "spiffe://" + req.CoreConfiguration.TrustDomain + "/spiffe-pve-ek"
			}
			if cluster.HashPath != "" {
				if _, err := os.Stat(config.HashPath); os.IsNotExist(err) {
					return nil, errors.New(fmt.Sprintf("hash_path '%s' does not exist", cluster.HashPath))
				}
			}
			newClusters[strings.ReplaceAll(name, "-", "")] = cluster
		}
		config.PVE.Clusters = newClusters
	}

	if config.CaPath != "" {
		if _, err := os.Stat(config.CaPath); os.IsNotExist(err) {
			return nil, errors.New(fmt.Sprintf("ca_path '%s' does not exist", config.CaPath))
		}
	} else {
		var tryCaPath = "/opt/spire/.data/certs"
		if _, err := os.Stat(tryCaPath); !os.IsNotExist(err) {
			config.CaPath = tryCaPath
		}
	}
	if config.HashPath != "" {
		if _, err := os.Stat(config.HashPath); os.IsNotExist(err) {
			return nil, errors.New(fmt.Sprintf("hash_path '%s' does not exist", config.HashPath))
		}
	} else {
		var tryHashPath = "/opt/spire/.data/hashes"
		if _, err := os.Stat(tryHashPath); !os.IsNotExist(err) {
			config.HashPath = tryHashPath
		}
	}

	if config.CaPath == "" && config.HashPath == "" {
		return nil, errors.New("either ca_path, hash_path, or both are required")
	}

	config.trustDomain = req.CoreConfiguration.TrustDomain
	p.config = config

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {

	if p.config == nil {
		return errors.New("plugin not configured")
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	conf := p.getConfiguration()
	if conf == nil {
		return status.Error(codes.FailedPrecondition, "tpm: not configured")
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "tpm: missing attestation payload")
	}

	attestationData := new(common.AttestationData)
	err = json.Unmarshal(payload, attestationData)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "tpm: failed to unmarshal attestation data: %v", err)
	}

	ek, err := common.DecodeEK(attestationData.EK)
	if err != nil {
		return err
	}

	hashEncoded, err := common.GetPubHash(ek)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "tpm: could not get public key hash: %v", err)
	}

	var selectors []string
	caCheck := false
	validEK := false
	if p.config.AWS.Enabled && attestationData.AWS != nil {
		if attestationData.AWS.InstanceID == "" {
			return fmt.Errorf("tpm: bad aws data")
		}
		pubBytes, _ := x509.MarshalPKIXPublicKey(ek.Public)
		awsSelectors, err := p.verifyAWSTPM(stream.Context(), attestationData.AWS.InstanceID, pubBytes)
		if err == nil {
			selectors = append(selectors, awsSelectors...)

			if p.config.AWS.HashPath != "" {
				validEK = checkHashAllowed(p.config.AWS.HashPath, hashEncoded)
			} else {
				validEK = true
			}
		}
	} else if p.config.PVE.Enabled && attestationData.PVE != nil {
		clusterConf, ok := p.config.PVE.Clusters[attestationData.PVE.CUID]
		hashPath := p.config.PVE.Clusters[attestationData.PVE.CUID].HashPath
		if !ok {
			return status.Errorf(codes.PermissionDenied, "tpm: unknown pve cluster cuid: %s", attestationData.PVE.CUID)
		}

		if attestationData.PVE.VMID <= 0 || attestationData.PVE.UUID == "" {
			return fmt.Errorf("tpm: bad pve data %d %s", attestationData.PVE.VMID, attestationData.PVE.UUID)
		}
		resp, err := p.identityProvider.FetchX509Identity(stream.Context(), &identityproviderv1.FetchX509IdentityRequest{})
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "tpm: something went wrong getting our identity: %v", err)
		}

		pveSelectors, err := p.verifyPVETPM(stream.Context(), attestationData.PVE, ek.Public, resp, clusterConf)
		if err == nil {
			selectors = append(selectors, pveSelectors...)
			if hashPath != "" {
				validEK = checkHashAllowed(hashPath, hashEncoded)
			} else {
				validEK = true
			}
		} else {
			return fmt.Errorf("tpm: failed to attest. %w", err)
		}
	} else {
		if p.config.HashPath != "" {
			validEK = checkHashAllowed(p.config.HashPath, hashEncoded)
			caCheck = !validEK
		} else {
			caCheck = true
		}
	}

	if caCheck && p.config.CaPath != "" && ek.Certificate != nil {
		files, err := os.ReadDir(p.config.CaPath)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "tpm: could not open ca directory: %v", err)
		}

		roots := x509.NewCertPool()
		for _, file := range files {
			if !file.IsDir() {
				filename := filepath.Join(p.config.CaPath, file.Name())
				certData, err := os.ReadFile(filename)
				if err != nil {
					return status.Errorf(codes.InvalidArgument, "tpm: could not read cert data for '%s': %v", filename, err)
				}

				ok := roots.AppendCertsFromPEM(certData)
				if ok {
					continue
				}

				root, err := x509.ParseCertificate(certData)
				if err == nil {
					roots.AddCert(root)
					continue
				}

				return status.Errorf(codes.InvalidArgument, "tpm: could not parse cert data for '%s': %v", filename, err)
			}
		}

		ekCert, err := x509ext.ToEKCertificate(ek.Certificate)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "tpm: could not parse EKCert: %v", err)
		}

		opts := x509.VerifyOptions{
			Roots: roots,
			// NOTE: the only ExtKeyUsage that TPM 2.0 sets is the optional 'tcg-kp-EKCertificate' key usage.
			// This is already checked by the x509ext package.
			// An empty KeyUsages defaults to x509.ExtKeyUsageServerAuth which is not set on EK Certs.
			// Thus we MUST set this to ExtKeyUsageAny
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		_, err = ekCert.Verify(opts)
		if err != nil {
			return fmt.Errorf("tpm: could not verify cert: %v", err)
		}
		validEK = true
	}

	if !validEK {
		return fmt.Errorf("tpm: could not validate EK")
	}

	ap := attest.ActivationParameters{
		EK: ek.Public,
		AK: *attestationData.AK,
	}

	secret, ec, err := ap.Generate()
	if err != nil {
		return status.Errorf(codes.Internal, "tpm: could not generate credential challenge: %v", err)
	}

	challenge := &common.Challenge{
		EC: ec,
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		return status.Errorf(codes.Internal, "tpm: unable to marshal challenge: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challengeBytes,
		},
	}); err != nil {
		return status.Errorf(status.Code(err), "tpm: unable to send challenge: %v", err)
	}

	challengeResp, err := stream.Recv()
	if err != nil {
		return status.Errorf(status.Code(err), "tpm: unable to receive challenge response: %v", err)
	}

	response := &common.ChallengeResponse{}
	if err := json.Unmarshal(challengeResp.GetChallengeResponse(), response); err != nil {
		return status.Errorf(codes.InvalidArgument, "tpm: unable to unmarshal challenge response: %v", err)
	}

	if !bytes.Equal(secret, response.Secret) {
		return status.Errorf(codes.PermissionDenied, "tpm: incorrect secret from attestor")
	}

	selectors = append(selectors, "pub_hash:"+hashEncoded)
	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       common.AgentID(p.config.trustDomain, hashEncoded),
				SelectorValues: selectors,
				CanReattest:    true,
			},
		},
	})
}

func (p *Plugin) verifyAWSTPM(ctx context.Context, instanceID string, ekPub []byte) ([]string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := ec2.NewFromConfig(cfg)
	out, err := client.GetInstanceTpmEkPub(ctx, &ec2.GetInstanceTpmEkPubInput{
		InstanceId: aws.String(instanceID),
		KeyFormat:  "der",
		KeyType:    "rsa-2048",
	})
	if err != nil {
		return nil, err
	}
	decodedAWSKey, _ := base64.StdEncoding.DecodeString(*out.KeyValue)
	if !bytes.Equal(decodedAWSKey, ekPub) {
		return nil, errors.New("EK mismatch")
	}
	return []string{"aws:instance_id:" + instanceID}, nil
}

func (p *Plugin) verifyPVETPM(ctx context.Context, pveid *common.PVEInstanceData, ekPub crypto.PublicKey, identity *identityproviderv1.FetchX509IdentityResponse, conf PVEConfig) ([]string, error) {

	i := identity.GetIdentity()
	if i == nil {
		return nil, fmt.Errorf("no identity found in response")
	}
	key, err := x509.ParsePKCS8PrivateKey(i.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: i.CertChain,
		PrivateKey:  key,
	}

	certPool := x509.NewCertPool()
	for _, authority := range identity.Bundle.X509Authorities {
		ca, err := x509.ParseCertificate(authority.Asn1)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trust bundle")
		}
		certPool.AddCert(ca)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{*cert},
				RootCAs:            certPool,
				InsecureSkipVerify: true, // Verification handled in VerifyConnection
				VerifyConnection: func(cs tls.ConnectionState) error {
					opts := x509.VerifyOptions{
						Roots:         certPool,
						Intermediates: x509.NewCertPool(),
					}
					for _, c := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(c)
					}
					_, err := cs.PeerCertificates[0].Verify(opts)
					if err != nil {
						return fmt.Errorf("failed to verify certificate chain: %w", err)
					}
					for _, uri := range cs.PeerCertificates[0].URIs {
						if uri.String() == conf.ExpectedSpiffeID {
							return nil
						}
					}
					return errors.New("remote SPIFFE ID mismatch")
				},
			},
		},
	}

	var targetNode string
	tempHosts := append([]string{}, conf.Hosts...)
	rand.Seed(time.Now().UnixNano())

	for try := 0; try < 3 && len(tempHosts) > 0; try++ {
		idx := rand.Intn(len(tempHosts))
		host := tempHosts[idx]
		tempHosts = append(tempHosts[:idx], tempHosts[idx+1:]...) // Remove chosen host

		lookupURL, _ := url.JoinPath("https://"+host+":"+strconv.Itoa(conf.Port), "vm-to-node", strconv.Itoa(int(pveid.VMID)))
		res, err := client.Get(lookupURL)
		if err != nil {
			continue
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			continue
		}

		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			continue
		}
		targetNode = strings.TrimSpace(string(body))
		break
	}

	if targetNode == "" {
		return nil, fmt.Errorf("could not resolve VM %d to a node after retries", pveid.VMID)
	}

	origionalNode := targetNode
	if !strings.Contains(targetNode, ":") {
		targetNode = fmt.Sprintf("%s:%d", targetNode, conf.Port)
	}

	fullURL, _ := url.JoinPath("https://"+targetNode, "ek-cert", strconv.Itoa(int(pveid.VMID)), pveid.UUID)
	res, err := client.Get(fullURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EK from node")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("target node returned error status: %d", res.StatusCode)
	}

	pveBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body")
	}

	block, _ := pem.Decode(pveBody)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from PVE node")
	}

	pveCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PVE cert: %w", err)
	}

	pveKeyBytes, _ := x509.MarshalPKIXPublicKey(pveCert.PublicKey)
	attestorKeyBytes, _ := x509.MarshalPKIXPublicKey(ekPub)

	if !bytes.Equal(pveKeyBytes, attestorKeyBytes) {
		return nil, errors.New("EK mismatch: PVE certificate key does not match attestor key")
	}

	selectors := []string{
		"pve:vm_id:" + strconv.Itoa(int(pveid.VMID)),
		"pve:uuid:" + pveid.UUID,
		"pve:node:" + origionalNode,
	}
	fullURL, _ = url.JoinPath("https://"+targetNode, "vm-metadata", strconv.Itoa(int(pveid.VMID)))
	res, err = client.Get(fullURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EK from node")
	}
	defer res.Body.Close()
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata body")
	}
	var metadata map[string]interface{}
	if err = json.Unmarshal(bodyBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to read metadata")
	}
	if value, ok := metadata["smbios1"]; !ok {
		return nil, fmt.Errorf("failed to read smbios metadata")
	} else {
		uuidOk := false
		vmidOk := false
		val, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("failed to read smbios metadata value")
		}
		items := strings.Split(val, ",")
		for _, item := range items {
			kv := strings.SplitN(item, "=", 2)
			if len(kv) != 2 {
				continue
			}
			if kv[0] == "uuid" && kv[1] == pveid.UUID {
				uuidOk = true
			}
			if kv[0] == "sku" && kv[1] == strconv.Itoa(int(pveid.VMID)) {
				vmidOk = true
			}
		}
		if !vmidOk || !uuidOk {
			return nil, fmt.Errorf("pve smbios data did not match vm")
		}
	}
	if value, ok := metadata["name"]; ok {
		val, ok := value.(string)
		if ok {
			selectors = append(selectors, "pve:name:"+val)
		}
	}
	if value, ok := metadata["tags"]; ok {
		val, ok := value.(string)
		if ok {
			items := strings.Split(val, ";")
			for _, item := range items {
				selectors = append(selectors, "pve:tag:"+item)
			}
		}
	}
	return selectors, nil
}

func checkHashAllowed(hashPath, hashEncoded string) bool {
	// Check if hashPath is a directory, fail if this is simply a file
	fileInfo, err := os.Stat(hashPath)
	if err != nil || !fileInfo.IsDir() {
		return false
	}

	filename := filepath.Join(hashPath, hashEncoded)
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		return true
	}
	return false
}

func (p *Plugin) getConfiguration() *Config {
	p.m.Lock()
	defer p.m.Unlock()
	return p.config
}
