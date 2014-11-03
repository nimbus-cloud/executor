// This file was generated by counterfeiter
package fakes

import (
	"io"
	"sync"

	"github.com/cloudfoundry-incubator/executor"
)

type FakeClient struct {
	PingStub        func() error
	pingMutex       sync.RWMutex
	pingArgsForCall []struct{}
	pingReturns struct {
		result1 error
	}
	AllocateContainerStub        func(request executor.Container) (executor.Container, error)
	allocateContainerMutex       sync.RWMutex
	allocateContainerArgsForCall []struct {
		request executor.Container
	}
	allocateContainerReturns struct {
		result1 executor.Container
		result2 error
	}
	GetContainerStub        func(guid string) (executor.Container, error)
	getContainerMutex       sync.RWMutex
	getContainerArgsForCall []struct {
		guid string
	}
	getContainerReturns struct {
		result1 executor.Container
		result2 error
	}
	RunContainerStub        func(guid string) error
	runContainerMutex       sync.RWMutex
	runContainerArgsForCall []struct {
		guid string
	}
	runContainerReturns struct {
		result1 error
	}
	DeleteContainerStub        func(guid string) error
	deleteContainerMutex       sync.RWMutex
	deleteContainerArgsForCall []struct {
		guid string
	}
	deleteContainerReturns struct {
		result1 error
	}
	ListContainersStub        func(executor.Tags) ([]executor.Container, error)
	listContainersMutex       sync.RWMutex
	listContainersArgsForCall []struct {
		arg1 executor.Tags
	}
	listContainersReturns struct {
		result1 []executor.Container
		result2 error
	}
	RemainingResourcesStub        func() (executor.ExecutorResources, error)
	remainingResourcesMutex       sync.RWMutex
	remainingResourcesArgsForCall []struct{}
	remainingResourcesReturns struct {
		result1 executor.ExecutorResources
		result2 error
	}
	TotalResourcesStub        func() (executor.ExecutorResources, error)
	totalResourcesMutex       sync.RWMutex
	totalResourcesArgsForCall []struct{}
	totalResourcesReturns struct {
		result1 executor.ExecutorResources
		result2 error
	}
	GetFilesStub        func(guid string, path string) (io.ReadCloser, error)
	getFilesMutex       sync.RWMutex
	getFilesArgsForCall []struct {
		guid string
		path string
	}
	getFilesReturns struct {
		result1 io.ReadCloser
		result2 error
	}
}

func (fake *FakeClient) Ping() error {
	fake.pingMutex.Lock()
	fake.pingArgsForCall = append(fake.pingArgsForCall, struct{}{})
	fake.pingMutex.Unlock()
	if fake.PingStub != nil {
		return fake.PingStub()
	} else {
		return fake.pingReturns.result1
	}
}

func (fake *FakeClient) PingCallCount() int {
	fake.pingMutex.RLock()
	defer fake.pingMutex.RUnlock()
	return len(fake.pingArgsForCall)
}

func (fake *FakeClient) PingReturns(result1 error) {
	fake.PingStub = nil
	fake.pingReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeClient) AllocateContainer(request executor.Container) (executor.Container, error) {
	fake.allocateContainerMutex.Lock()
	fake.allocateContainerArgsForCall = append(fake.allocateContainerArgsForCall, struct {
		request executor.Container
	}{request})
	fake.allocateContainerMutex.Unlock()
	if fake.AllocateContainerStub != nil {
		return fake.AllocateContainerStub(request)
	} else {
		return fake.allocateContainerReturns.result1, fake.allocateContainerReturns.result2
	}
}

func (fake *FakeClient) AllocateContainerCallCount() int {
	fake.allocateContainerMutex.RLock()
	defer fake.allocateContainerMutex.RUnlock()
	return len(fake.allocateContainerArgsForCall)
}

func (fake *FakeClient) AllocateContainerArgsForCall(i int) executor.Container {
	fake.allocateContainerMutex.RLock()
	defer fake.allocateContainerMutex.RUnlock()
	return fake.allocateContainerArgsForCall[i].request
}

func (fake *FakeClient) AllocateContainerReturns(result1 executor.Container, result2 error) {
	fake.AllocateContainerStub = nil
	fake.allocateContainerReturns = struct {
		result1 executor.Container
		result2 error
	}{result1, result2}
}

func (fake *FakeClient) GetContainer(guid string) (executor.Container, error) {
	fake.getContainerMutex.Lock()
	fake.getContainerArgsForCall = append(fake.getContainerArgsForCall, struct {
		guid string
	}{guid})
	fake.getContainerMutex.Unlock()
	if fake.GetContainerStub != nil {
		return fake.GetContainerStub(guid)
	} else {
		return fake.getContainerReturns.result1, fake.getContainerReturns.result2
	}
}

func (fake *FakeClient) GetContainerCallCount() int {
	fake.getContainerMutex.RLock()
	defer fake.getContainerMutex.RUnlock()
	return len(fake.getContainerArgsForCall)
}

func (fake *FakeClient) GetContainerArgsForCall(i int) string {
	fake.getContainerMutex.RLock()
	defer fake.getContainerMutex.RUnlock()
	return fake.getContainerArgsForCall[i].guid
}

func (fake *FakeClient) GetContainerReturns(result1 executor.Container, result2 error) {
	fake.GetContainerStub = nil
	fake.getContainerReturns = struct {
		result1 executor.Container
		result2 error
	}{result1, result2}
}

func (fake *FakeClient) RunContainer(guid string) error {
	fake.runContainerMutex.Lock()
	fake.runContainerArgsForCall = append(fake.runContainerArgsForCall, struct {
		guid string
	}{guid})
	fake.runContainerMutex.Unlock()
	if fake.RunContainerStub != nil {
		return fake.RunContainerStub(guid)
	} else {
		return fake.runContainerReturns.result1
	}
}

func (fake *FakeClient) RunContainerCallCount() int {
	fake.runContainerMutex.RLock()
	defer fake.runContainerMutex.RUnlock()
	return len(fake.runContainerArgsForCall)
}

func (fake *FakeClient) RunContainerArgsForCall(i int) string {
	fake.runContainerMutex.RLock()
	defer fake.runContainerMutex.RUnlock()
	return fake.runContainerArgsForCall[i].guid
}

func (fake *FakeClient) RunContainerReturns(result1 error) {
	fake.RunContainerStub = nil
	fake.runContainerReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeClient) DeleteContainer(guid string) error {
	fake.deleteContainerMutex.Lock()
	fake.deleteContainerArgsForCall = append(fake.deleteContainerArgsForCall, struct {
		guid string
	}{guid})
	fake.deleteContainerMutex.Unlock()
	if fake.DeleteContainerStub != nil {
		return fake.DeleteContainerStub(guid)
	} else {
		return fake.deleteContainerReturns.result1
	}
}

func (fake *FakeClient) DeleteContainerCallCount() int {
	fake.deleteContainerMutex.RLock()
	defer fake.deleteContainerMutex.RUnlock()
	return len(fake.deleteContainerArgsForCall)
}

func (fake *FakeClient) DeleteContainerArgsForCall(i int) string {
	fake.deleteContainerMutex.RLock()
	defer fake.deleteContainerMutex.RUnlock()
	return fake.deleteContainerArgsForCall[i].guid
}

func (fake *FakeClient) DeleteContainerReturns(result1 error) {
	fake.DeleteContainerStub = nil
	fake.deleteContainerReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeClient) ListContainers(arg1 executor.Tags) ([]executor.Container, error) {
	fake.listContainersMutex.Lock()
	fake.listContainersArgsForCall = append(fake.listContainersArgsForCall, struct {
		arg1 executor.Tags
	}{arg1})
	fake.listContainersMutex.Unlock()
	if fake.ListContainersStub != nil {
		return fake.ListContainersStub(arg1)
	} else {
		return fake.listContainersReturns.result1, fake.listContainersReturns.result2
	}
}

func (fake *FakeClient) ListContainersCallCount() int {
	fake.listContainersMutex.RLock()
	defer fake.listContainersMutex.RUnlock()
	return len(fake.listContainersArgsForCall)
}

func (fake *FakeClient) ListContainersArgsForCall(i int) executor.Tags {
	fake.listContainersMutex.RLock()
	defer fake.listContainersMutex.RUnlock()
	return fake.listContainersArgsForCall[i].arg1
}

func (fake *FakeClient) ListContainersReturns(result1 []executor.Container, result2 error) {
	fake.ListContainersStub = nil
	fake.listContainersReturns = struct {
		result1 []executor.Container
		result2 error
	}{result1, result2}
}

func (fake *FakeClient) RemainingResources() (executor.ExecutorResources, error) {
	fake.remainingResourcesMutex.Lock()
	fake.remainingResourcesArgsForCall = append(fake.remainingResourcesArgsForCall, struct{}{})
	fake.remainingResourcesMutex.Unlock()
	if fake.RemainingResourcesStub != nil {
		return fake.RemainingResourcesStub()
	} else {
		return fake.remainingResourcesReturns.result1, fake.remainingResourcesReturns.result2
	}
}

func (fake *FakeClient) RemainingResourcesCallCount() int {
	fake.remainingResourcesMutex.RLock()
	defer fake.remainingResourcesMutex.RUnlock()
	return len(fake.remainingResourcesArgsForCall)
}

func (fake *FakeClient) RemainingResourcesReturns(result1 executor.ExecutorResources, result2 error) {
	fake.RemainingResourcesStub = nil
	fake.remainingResourcesReturns = struct {
		result1 executor.ExecutorResources
		result2 error
	}{result1, result2}
}

func (fake *FakeClient) TotalResources() (executor.ExecutorResources, error) {
	fake.totalResourcesMutex.Lock()
	fake.totalResourcesArgsForCall = append(fake.totalResourcesArgsForCall, struct{}{})
	fake.totalResourcesMutex.Unlock()
	if fake.TotalResourcesStub != nil {
		return fake.TotalResourcesStub()
	} else {
		return fake.totalResourcesReturns.result1, fake.totalResourcesReturns.result2
	}
}

func (fake *FakeClient) TotalResourcesCallCount() int {
	fake.totalResourcesMutex.RLock()
	defer fake.totalResourcesMutex.RUnlock()
	return len(fake.totalResourcesArgsForCall)
}

func (fake *FakeClient) TotalResourcesReturns(result1 executor.ExecutorResources, result2 error) {
	fake.TotalResourcesStub = nil
	fake.totalResourcesReturns = struct {
		result1 executor.ExecutorResources
		result2 error
	}{result1, result2}
}

func (fake *FakeClient) GetFiles(guid string, path string) (io.ReadCloser, error) {
	fake.getFilesMutex.Lock()
	fake.getFilesArgsForCall = append(fake.getFilesArgsForCall, struct {
		guid string
		path string
	}{guid, path})
	fake.getFilesMutex.Unlock()
	if fake.GetFilesStub != nil {
		return fake.GetFilesStub(guid, path)
	} else {
		return fake.getFilesReturns.result1, fake.getFilesReturns.result2
	}
}

func (fake *FakeClient) GetFilesCallCount() int {
	fake.getFilesMutex.RLock()
	defer fake.getFilesMutex.RUnlock()
	return len(fake.getFilesArgsForCall)
}

func (fake *FakeClient) GetFilesArgsForCall(i int) (string, string) {
	fake.getFilesMutex.RLock()
	defer fake.getFilesMutex.RUnlock()
	return fake.getFilesArgsForCall[i].guid, fake.getFilesArgsForCall[i].path
}

func (fake *FakeClient) GetFilesReturns(result1 io.ReadCloser, result2 error) {
	fake.GetFilesStub = nil
	fake.getFilesReturns = struct {
		result1 io.ReadCloser
		result2 error
	}{result1, result2}
}

var _ executor.Client = new(FakeClient)
