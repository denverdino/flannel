package watcher

import (
	"errors"

	"github.com/coreos/flannel/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/coreos/flannel/subnet"
)

type Watcher interface {
	Run(ctx context.Context)
}

type factoryFunc func(sm subnet.Manager) (Watcher, error)

var factories = make(map[string]factoryFunc)

func RegisterBackend(name string, factory factoryFunc) {
	factories[name] = factory
}

func NewWatcher(backend string, sm subnet.Manager) (w Watcher, err error) {
	f, ok := factories[backend]
	if ok && f != nil {
		w, err = f(sm)
		return
	}

	return nil, errors.New("No such watcher backend:" + backend)
}
