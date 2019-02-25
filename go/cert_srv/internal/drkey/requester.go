// Copyright 2019 ETH Zurich
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
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/config"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/drkey_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	DefaultDRKeyTimeout = 5 * time.Second
	// TODO(ben): move to config
	DRKeyEpochLength = 24 * time.Hour
)

var _ periodic.Task = (*Requester)(nil)

// Requester requests reissued certificate chains before
// expiration of the currently active certificate chain.
type Requester struct {
	Msgr  infra.Messenger
	State *config.State
	IA    addr.IA
}

func (r *Requester) Run(ctx context.Context) {
	crit, err := r.run(ctx)
	switch {
	case crit && err != nil:
		log.Crit("[drkey.Requester] Unable to get first level drkey", "err", err)
	case err != nil:
		log.Error("[drkey.Requester] Unable to get first level drkey", "err", err)
	}
}

func (r *Requester) run(ctx context.Context) (bool, error) {
	// TODO:
	// - derive and store secret value of current epoch
	// - before epoch expires or key for next epoch is requested, get new secret value
	// - fetch first order keys from other ASes if they are not available?
	// - keep track of frequently connected ASes?
	now := util.TimeToSecs(time.Now())
	// FIXME(ben): how to determine destination?
	dst := addr.IA{}
	return r.sendReq(ctx, dst, now)
}

func (r *Requester) sendReq(ctx context.Context, dstIa addr.IA, valTime uint32) (bool, error) {
	req := &drkey_mgmt.DRKeyLvl1Req{
		SrcIa:   r.IA.IAInt(),
		ValTime: valTime,
	}
	a := &snet.Addr{IA: dstIa, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	rep, err := r.Msgr.RequestDRKeyLvl1(ctx, req, a, messenger.NextId())
	if err != nil {
		return false, common.NewBasicError("Unable to request drkey lvl1", err)
	}
	log.Trace("[drkey.Requester] Received drkey lvl1 reply", "addr", a, "rep", rep)
	if crit, err := r.handleRep(ctx, rep); err != nil {
		return crit, common.NewBasicError("Unable to handle reply", err, "addr", a, "rep", rep)
	}
	return false, nil
}

func (r *Requester) handleRep(ctx context.Context, rep *drkey_mgmt.DRKeyLvl1Rep) (bool, error) {
	if err := r.validateRep(ctx, rep); err != nil {
		return false, err
	}
	return false, nil
}

func (r *Requester) validateRep(ctx context.Context, rep *drkey_mgmt.DRKeyLvl1Rep) error {
	// TODO: verify...
	return nil
}
