package chunkinfo

import (
	"context"
	"time"

	"github.com/FavorLabs/favorX/pkg/bitvector"
	"github.com/FavorLabs/favorX/pkg/localstore/chunkstore"
	"github.com/FavorLabs/favorX/pkg/retrieval/aco"
	"github.com/gauss-project/aurorafs/pkg/boson"
)

const (
	cleanTime = 1 * time.Hour
	maxTime   = 24 * 60 * 60
)

func (ci *ChunkInfo) isDiscover(rootCid boson.Address) bool {
	consumerList, err := ci.chunkStore.GetChunk(chunkstore.DISCOVER, rootCid)
	if err != nil {
		ci.logger.Errorf("chunkInfo isDiscover:%w", err)
		return false
	}
	if len(consumerList) <= 0 {
		return false
	}
	return true
}

func (ci *ChunkInfo) getRoutes(rootCid boson.Address, bit int) ([]aco.Route, error) {
	res := make([]aco.Route, 0)
	consumerList, err := ci.chunkStore.GetChunk(chunkstore.DISCOVER, rootCid)
	if err != nil {
		return nil, err
	}

	for _, c := range consumerList {
		if c.Len <= bit {
			continue
		}
		bv, err := bitvector.NewFromBytes(c.B, c.Len)
		if err != nil {
			return nil, err
		}
		if bv.Get(bit) {
			route := aco.NewRoute(c.Overlay, c.Overlay)
			res = append(res, route)
		}
	}
	res = ci.addRoutes(res)
	return res, nil
}

func (ci *ChunkInfo) addRoutes(routes []aco.Route) []aco.Route {
	if len(routes) <= 0 {
		return routes
	}
	res := make([]aco.Route, 0)
	ctx := context.Background()
	for _, route := range routes {
		overlays, errs := ci.route.GetTargetNeighbor(ctx, route.TargetNode, totalRouteCount)
		if errs != nil || overlays == nil {
			continue
		}
		for _, overlay := range overlays {
			v := aco.NewRoute(overlay, route.TargetNode)
			res = append(res, v)
		}
	}
	if len(res) == 0 {
		return routes
	}
	exist := make(map[string]struct{})
	for _, overlay := range res {
		for _, i := range routes {
			if i.TargetNode.Equal(overlay.LinkNode) && i.TargetNode.Equal(i.LinkNode) {
				continue
			}
			if _, e := exist[i.LinkNode.String()]; !e {
				res = append(res, i)
			}
		}
	}
	return res
}

func (ci *ChunkInfo) updateDiscover(rootCid, overlay boson.Address, bv []byte) error {
	var provider chunkstore.Provider
	provider.B = bv
	provider.Len = len(bv) * 8
	provider.Overlay = overlay
	return ci.chunkStore.PutChunk(chunkstore.DISCOVER, rootCid, []chunkstore.Provider{provider})
}

func (ci *ChunkInfo) FindChunkInfo(ctx context.Context, authInfo []byte, rootCid boson.Address, overlays []boson.Address) bool {
	msgChan := make(chan bool, 1)
	for {
		ci.syncMsg.Store(rootCid.String(), msgChan)
		ci.findChunkInfo(ctx, authInfo, rootCid, overlays)
		select {
		case <-ctx.Done():
			return false
		case msg := <-msgChan:
			ci.syncMsg.Delete(rootCid.String())
			return msg
		}
	}
}

func (ci *ChunkInfo) findChunkInfo(ctx context.Context, authInfo []byte, rootCid boson.Address, overlays []boson.Address) {
	ci.pendingFinder.updatePendingFinder(rootCid)
	if ci.getQueue(rootCid.String()) == nil {
		ci.newQueue(rootCid.String())
	}
	for _, overlay := range overlays {
		if ci.getQueue(rootCid.String()).isExists(UnPull, overlay.Bytes()) || ci.getQueue(rootCid.String()).isExists(Pulling, overlay.Bytes()) {
			continue
		}
		if ci.getQueue(rootCid.String()).isExists(Pulled, overlay.Bytes()) {
			ci.getQueue(rootCid.String()).popNode(Pulled, overlay.Bytes())
		}
		ci.getQueue(rootCid.String()).push(UnPull, overlay.Bytes())
	}
	go ci.doFindChunkInfo(ctx, authInfo, rootCid)
}

func (ci *ChunkInfo) doFindChunkInfo(ctx context.Context, _ []byte, rootCid boson.Address) {
	ci.queueProcess(ctx, rootCid)
}

func (ci *ChunkInfo) cleanDiscoverTrigger() {
	t := time.NewTicker(cleanTime)
	go func() {
		for {
			<-t.C
			now := time.Now().Unix()
			discover, err := ci.chunkStore.GetAllChunk(chunkstore.DISCOVER)
			if err != nil {
				ci.logger.Errorf("chunkInfo cleanDiscover get discover:%w", err)
				continue
			}
			for rCid, providerList := range discover {
				rootCid := boson.MustParseHexAddress(rCid)
				if ci.isDownload(rootCid, ci.addr) {
					ci.syncLk.Lock()
					ci.cancelPendingFindInfo(rootCid)
					ci.queues.Delete(rootCid.String())
					ci.syncLk.Unlock()
					err = ci.chunkStore.DeleteAllChunk(chunkstore.DISCOVER, rootCid)
					if err != nil {
						ci.logger.Errorf("chunkInfo cleanDiscover remove discover:%w", err)
					}
					break
				}
				for _, provider := range providerList {
					if provider.Time+maxTime < now {
						err = ci.chunkStore.DeleteChunk(chunkstore.DISCOVER, rootCid, provider.Overlay)
						if err != nil {
							ci.logger.Errorf("chunkInfo cleanDiscover remove discover:%w", err)
						}
						if q, ok := ci.queues.Load(rootCid); ok {
							q.(*queue).popNode(Pulled, provider.Overlay.Bytes())
						}
					}
				}
			}
		}
	}()
}

func (ci *ChunkInfo) cancelPendingFindInfo(rootCid boson.Address) {
	ci.pendingFinder.cancelPendingFinder(rootCid)
}
