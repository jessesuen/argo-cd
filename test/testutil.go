package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/argoproj/argo-cd/errors"
	"github.com/ghodss/yaml"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

// StartInformer is a helper to start an informer, wait for its cache to sync and return a cancel func
func StartInformer(informer cache.SharedIndexInformer) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	go informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		log.Fatal("Timed out waiting for informer cache to sync")
	}
	return cancel
}

// GetFreePort finds an available free port on the OS
func GetFreePort() (int, error) {
	ln, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		return 0, err
	}
	return ln.Addr().(*net.TCPAddr).Port, ln.Close()
}

// WaitForPortListen waits until the given address is listening on the port
func WaitForPortListen(addr string, timeout time.Duration) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(timeout)
	if timeout == 0 {
		timer.Stop()
	} else {
		defer timer.Stop()
	}
	for {
		select {
		case <-ticker.C:
			if portIsOpen(addr) {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("timeout after %s", timeout.String())
		}
	}
}

func portIsOpen(addr string) bool {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func UnmarshalYAMLFile(path string) *unstructured.Unstructured {
	data, err := ioutil.ReadFile(path)
	errors.CheckError(err)
	var un unstructured.Unstructured
	err = yaml.Unmarshal(data, &un.Object)
	errors.CheckError(err)
	return &un
}

func UnmarshalJSONFile(path string) *unstructured.Unstructured {
	data, err := ioutil.ReadFile(path)
	errors.CheckError(err)
	var un unstructured.Unstructured
	err = json.Unmarshal(data, &un.Object)
	errors.CheckError(err)
	return &un
}
