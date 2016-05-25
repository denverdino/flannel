package aliyun

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	log "github.com/coreos/flannel/Godeps/_workspace/src/github.com/golang/glog"
	"github.com/coreos/flannel/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/coreos/flannel/subnet"
	"github.com/coreos/flannel/watcher"
	"github.com/denverdino/aliyungo/common"
	"github.com/denverdino/aliyungo/ecs"
)

const (
	routeCheckRetries = 30
)

type Watcher struct {
	sm                subnet.Manager
	rl                []Route
	access_key_id     string
	access_key_secret string
	region            string
	vpc_id            string
	route_table_id    string

	OverwriteMismatch bool
}

type Route struct {
	Dst   *net.IPNet
	Src   net.IP
	Gw    net.IP
	Flags int
}

func init() {
	watcher.RegisterBackend("aliyun", NewWatcher)
}

func NewWatcher(sm subnet.Manager) (watcher.Watcher, error) {
	watcher := &Watcher{
		sm:                sm,
		access_key_id:     os.Getenv("ALIYUN_ACCESS_KEY_ID"),
		access_key_secret: os.Getenv("ALIYUN_ACCESS_KEY_SECRET"),
		region:            os.Getenv("ALIYUN_REGION"),
		vpc_id:            os.Getenv("ALIYUN_VPC_ID"),
		route_table_id:    os.Getenv("ALIYUN_ROUTE_TABLE_ID"),
		OverwriteMismatch: true,
	}
	return watcher, nil
}

func (w *Watcher) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.Info("Aliyun watcher is Watching for new subnet leases")
	evts := make(chan []subnet.Event)
	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, w.sm, "", nil, evts)
		wg.Done()
	}()

	w.rl = make([]Route, 0, 10)
	wg.Add(1)
	go func() {
		w.routeCheck(ctx)
		wg.Done()
	}()

	defer wg.Wait()

	for {
		select {
		case evtBatch := <-evts:
			w.handleSubnetEvents(evtBatch)

		case <-ctx.Done():
			return
		}
	}
}

func (w *Watcher) handleSubnetEvents(batch []subnet.Event) {
	for _, evt := range batch {
		switch evt.Type {
		case subnet.EventAdded:
			log.Infof("Subnet added: %v via %v", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP)

			if evt.Lease.Attrs.BackendType != "" && evt.Lease.Attrs.BackendType != "alloc" {
				log.Warningf("Ignoring non-alloc subnet: type=%v", evt.Lease.Attrs.BackendType)
				continue
			}

			route := Route{
				Dst: evt.Lease.Subnet.ToIPNet(),
				Gw:  evt.Lease.Attrs.PublicIP.ToIP(),
			}

			w.addToRouteList(route)
			err := w.createVPCRoute(route)
			if err != nil {
				if err2, ok := err.(*common.Error); ok && err2.Code == "InvalidCIDRBlock.Duplicate" {
					log.Warningf("Duplicate route %+v. Will double check when syncing.", route)
				} else {
					log.Errorf("Error creating route:", err.Error())
				}
			}

		case subnet.EventRemoved:
			log.Info("Subnet removed: ", evt.Lease.Subnet)

			if evt.Lease.Attrs.BackendType != "" && evt.Lease.Attrs.BackendType != "alloc" {
				log.Warningf("Ignoring non-alloc subnet: type=%v", evt.Lease.Attrs.BackendType)
				continue
			}

			route := Route{
				Dst: evt.Lease.Subnet.ToIPNet(),
				Gw:  evt.Lease.Attrs.PublicIP.ToIP(),
			}

			err := w.removeVPCRoute(route)
			if err != nil {
				log.Errorf("Error removing route:", err.Error())
			}
			w.removeFromRouteList(route)

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}

func (w *Watcher) addToRouteList(route Route) {
	w.rl = append(w.rl, route)
}

func (w *Watcher) removeFromRouteList(route Route) {
	for index, r := range w.rl {
		if routeEqual(r, route) {
			w.rl = append(w.rl[:index], w.rl[index+1:]...)
			return
		}
	}
}

func (w *Watcher) getInstanceIP2ID() (ip2id map[string]string, err error) {
	client := ecs.NewClient(w.access_key_id, w.access_key_secret)
	args2 := &ecs.DescribeInstancesArgs{
		RegionId: common.Region(w.region),
		VpcId:    w.vpc_id,
	}
	results2, _, err := client.DescribeInstances(args2)
	if err != nil {
		return
	}

	ip2id = make(map[string]string)
	for _, instance := range results2 {
		if len(instance.VpcAttributes.PrivateIpAddress.IpAddress) > 0 {
			ip2id[instance.VpcAttributes.PrivateIpAddress.IpAddress[0]] = instance.InstanceId
		}
	}
	return
}

func (w *Watcher) removeVPCRoute(route Route) (err error) {
	ip2id, err := w.getInstanceIP2ID()
	if err != nil {
		return
	}

	var (
		instanceId string
		ok         bool
	)
	gw := route.Gw.String()
	if instanceId, ok = ip2id[gw]; !ok {
		err = errors.New("Unable to get instance id of Gw:" + gw)
		return
	}
	args := &ecs.DeleteRouteEntryArgs{
		RouteTableId:         w.route_table_id,
		DestinationCidrBlock: route.Dst.String(),
		NextHopId:            instanceId,
	}
	client := ecs.NewClient(w.access_key_id, w.access_key_secret)
	err = client.DeleteRouteEntry(args)
	return
}

func (w *Watcher) createVPCRoute(route Route) (err error) {
	ip2id, err := w.getInstanceIP2ID()
	if err != nil {
		return
	}
	var (
		instanceId string
		ok         bool
	)
	gw := route.Gw.String()
	if instanceId, ok = ip2id[gw]; !ok {
		err = errors.New("Unable to get instance id of Gw:" + gw)
		return
	}
	client := ecs.NewClient(w.access_key_id, w.access_key_secret)
	args := &ecs.CreateRouteEntryArgs{
		RouteTableId:         w.route_table_id,
		DestinationCidrBlock: route.Dst.String(),
		NextHopId:            instanceId,
	}
	err = client.CreateRouteEntry(args)
	return
}

func (w *Watcher) routeCheck(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(routeCheckRetries * time.Second):
			w.checkSubnetExistInRoutes()
		}
	}
}

func (w *Watcher) checkSubnetExistInRoutes() {
	client := ecs.NewClient(w.access_key_id, w.access_key_secret)
	args := &ecs.DescribeRouteTablesArgs{
		RouteTableId: w.route_table_id,
	}
	results, _, err := client.DescribeRouteTables(args)
	entries := results[0].RouteEntrys
	if err != nil {
		return
	}

	ip2id, err := w.getInstanceIP2ID()
	if err != nil {
		return
	}

	for _, route := range w.rl {
		var (
			instanceId string
			ok         bool
		)
		exist := false
		for _, r := range entries.RouteEntry {
			if r.DestinationCidrBlock == route.Dst.String() {
				if instanceId, ok = ip2id[route.Gw.String()]; ok && instanceId == r.InstanceId {
					exist = true
					break
				} else {
					log.Warningf("A route with the same CIDR and a different nexthop exists in the VPC. %+v != %+v", r, route)
					if w.OverwriteMismatch {
						log.Infof("Will try to remove the mismatched route")
						args := &ecs.DeleteRouteEntryArgs{
							RouteTableId:         w.route_table_id,
							DestinationCidrBlock: r.DestinationCidrBlock,
							NextHopId:            r.InstanceId,
						}
						err := client.DeleteRouteEntry(args)
						if err != nil {
							log.Errorf("Error deleting the mismatched route:", err.Error())
						}
					} else {
						log.Infof("Will ignore the mismatched route")
						exist = true
					}
					break
				}
			}
		}
		if !exist {
			if instanceId, ok = ip2id[route.Gw.String()]; ok {
				args3 := &ecs.CreateRouteEntryArgs{
					RouteTableId:         w.route_table_id,
					DestinationCidrBlock: route.Dst.String(),
					NextHopId:            instanceId,
				}
				err := client.CreateRouteEntry(args3)
				if err != nil {
					log.Errorf("Error adding route to %v: %v, %v", route.Dst, route.Gw, err)
				}
			}
		}
	}
}

func routeEqual(x, y Route) bool {
	if x.Dst.IP.Equal(y.Dst.IP) && x.Gw.Equal(y.Gw) && bytes.Equal(x.Dst.Mask, y.Dst.Mask) {
		return true
	}
	return false
}
