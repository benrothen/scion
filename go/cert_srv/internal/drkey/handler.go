// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package drkey

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	HandlerTimeout = 5 * time.Second
	EpochBegin     = 0
	EpochEnd       = 3600

	AddressMismatchError = "Source IA of packet did not match IA in DRKey"
)

var (
	// TODO(ben): fix epoch begin and end, add to configuration
	SV = common.RawBytes("AAAABBBBCCCCDDDD")
)

// Handler handles first-level drkey requests.
type Handler struct {
	State *config.State
	IA    addr.IA
}

func (h *Handler) Handle(r *infra.Request) *infra.HandlerResult {
	addr := r.Peer.(*snet.Addr)
	req := r.Message.(*drkey_mgmt.DRKeyLvl1Req)
	if err := h.handle(r, addr, req); err != nil {
		log.Error("[DRKeyHandler] Dropping drkey lvl1 request",
			"addr", addr, "req", req, "err", err)
	}
	// TODO(lukedirtwalker): reflect error in metrics.
	return infra.MetricsResultOk
}

func (h *Handler) handle(r *infra.Request, addr *snet.Addr,
	req *drkey_mgmt.DRKeyLvl1Req) error {

	ctx, cancelF := context.WithTimeout(r.Context(), HandlerTimeout)
	defer cancelF()
	//signed := r.FullMessage.(*ctrl.SignedPld)
	log.Trace("[DRKeyHandler] Received drkey lvl1 request", "addr", addr, "req", req)

	if err := h.validateReq(req, addr); err != nil {
		return common.NewBasicError("Unable to verify request", err)
	}
	// Derive first-level drkey
	key, err := h.deriveKey(req)
	if err != nil {
		return common.NewBasicError("Unable to derive drkey", err)
	}
	// Get the newest certificate for the remote host
	cert, err := h.State.TrustDB.GetLeafCertMaxVersion(ctx, req.SrcIa.IA())
	if err != nil {
		return common.NewBasicError("Unable to fetch certificate for remote host", err)
	}
	// Get a fresh nonce for encryption of the drkey
	nc, err := scrypto.Nonce(24)
	if err != nil {
		return common.NewBasicError("Unable to get random nonce", err)
	}
	cipher, err := drkey.EncryptDRKeyLvl1(key, nc, cert.SubjectEncKey, h.State.GetDecryptKey())
	if err != nil {
		return common.NewBasicError("Unable to encrypt drkey", err)
	}
	rep := &drkey_mgmt.DRKeyLvl1Rep{
		SrcIa:      h.IA.IAInt(),
		EpochBegin: EpochBegin,
		EpochEnd:   EpochEnd,
		Cipher:     cipher,
		Nonce:      nc,
		CertVerDst: cert.Version,
	}
	if err := h.sendRep(ctx, addr, rep, r.ID); err != nil {
		log.Error("[DRKeyReqHandler] Unable to send drkey reply", "err", err)
	}
	return nil
}

func (h *Handler) validateReq(req *drkey_mgmt.DRKeyLvl1Req, addr *snet.Addr) error {
	// TODO(ben): validate request (validity time, etc.)

	// TODO(ben): remove
	log.Debug("[DRKeyReqHandler] Validating drkey lvl1 request", "req", req)
	if !addr.IA.Equal(req.SrcIa.IA()) {
		return common.NewBasicError(AddressMismatchError, nil,
			"expected", addr.IA, "actual", req.SrcIa.IA())
	}
	return nil
}

func (h *Handler) deriveKey(req *drkey_mgmt.DRKeyLvl1Req) (*drkey.DRKeyLvl1, error) {
	// TODO(ben): remove
	log.Debug("[DRKeyReqHandler] Deriving drkey for lvl1 request", "req", req)
	key := &drkey.DRKeyLvl1{
		SrcIa: h.IA,
		DstIa: req.SrcIa.IA(),
		Epoch: drkey.Epoch{
			Begin: EpochBegin,
			End:   EpochEnd,
		},
	}
	if err := key.SetKey(SV); err != nil {
		return nil, err
	}
	return key, nil
}

func (h *Handler) sendRep(ctx context.Context, addr net.Addr, rep *drkey_mgmt.DRKeyLvl1Rep,
	id uint64) error {

	msger, ok := infra.MessengerFromContext(ctx)
	if !ok {
		return common.NewBasicError(
			"[DRKeyReqHandler] Unable to service request, no messenger found", nil)
	}
	return msger.SendDRKeyLvl1(ctx, rep, addr, id)
}

/*
func (h *DRKeyRepHandler) HandleRep(r *infra.Request, config *conf.Conf) {
	saddr := r.Peer.(*snet.Addr)
	rep := r.Message.(*drkey_mgmt.DRKeyLvl1Rep)

	log.Debug("[DRKeyRepHandler] Received drkey lvl1 reply", "addr", saddr, "rep", rep)
	if err := h.validateRep(rep, saddr); err != nil {
		h.logDropRep(saddr, rep, err)
		return
	}
	cert, err := config.TrustDB.GetLeafCertMaxVersion(rep.SrcIa.IA())
	if err != nil {
		log.Error("[DRKeyRepHandler] Unable to fetch certificate for remote host", "err", err)
		return
	}
	key, err := drkey.DecryptDRKeyLvl1(rep.Cipher, rep.Nonce, cert.SubjectEncKey,
		config.GetDecryptKey())
	// TODO(ben): remove
	log.Debug("[DRKeyRepHandler] DRKey received", "key", key)
	// TODO(ben): store in keystore
}

func (h *DRKeyRepHandler) validateRep(rep *drkey_mgmt.DRKeyLvl1Rep, addr *snet.Addr) error {
	// TODO(ben): validate reply (validity time, etc.)
	// TODO(ben): remove
	log.Debug("[DRKeyRepHandler] Validating drkey lvl1 reply", "rep", rep)
	if !addr.IA.Eq(rep.SrcIa.IA()) {
		return common.NewBasicError(AddressMismatchError, nil,
			"expected", addr.IA, "actual", rep.SrcIa.IA())
	}
	return nil
}

*/
