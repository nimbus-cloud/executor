package allocationstore_test

import (
	"time"

	"github.com/cloudfoundry-incubator/executor"
	"github.com/cloudfoundry-incubator/executor/depot/allocationstore"
	"github.com/cloudfoundry-incubator/executor/depot/allocationstore/fakes"
	"github.com/pivotal-golang/clock/fakeclock"
	"github.com/pivotal-golang/lager/lagertest"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var logger = lagertest.NewTestLogger("test")

var _ = Describe("Allocation Store", func() {
	var (
		allocationStore  *allocationstore.AllocationStore
		fakeClock        *fakeclock.FakeClock
		fakeEventEmitter *fakes.FakeEventEmitter
		currentTime      time.Time
	)

	BeforeEach(func() {
		currentTime = time.Now()
		fakeClock = fakeclock.NewFakeClock(currentTime)
		fakeEventEmitter = &fakes.FakeEventEmitter{}
		allocationStore = allocationstore.NewAllocationStore(fakeClock, fakeEventEmitter)
	})

	Describe("List", func() {
		Context("when a container is allocated", func() {
			var container executor.Container

			BeforeEach(func() {
				container = executor.Container{
					Guid:     "banana",
					MemoryMB: 512,
					DiskMB:   512,
				}

				_, err := allocationStore.Allocate(logger, container)
				Expect(err).NotTo(HaveOccurred())
			})

			It("is included in the list", func() {
				allocations := allocationStore.List()
				Expect(allocations).To(HaveLen(1))
				Expect(allocations[0].Guid).To(Equal(container.Guid))
			})

			Context("and then deallocated", func() {
				BeforeEach(func() {
					deallocated := allocationStore.Deallocate(logger, container.Guid)
					Expect(deallocated).To(BeTrue())
				})

				It("is no longer in the list", func() {
					Expect(allocationStore.List()).To(BeEmpty())
				})
			})
		})

		Context("when multiple containers are allocated", func() {
			It("they are added to the store", func() {
				_, err := allocationStore.Allocate(logger, executor.Container{
					Guid:     "banana-1",
					MemoryMB: 512,
					DiskMB:   512,
				})
				Expect(err).NotTo(HaveOccurred())

				_, err = allocationStore.Allocate(logger, executor.Container{
					Guid:     "banana-2",
					MemoryMB: 512,
					DiskMB:   512,
				})
				Expect(err).NotTo(HaveOccurred())

				Expect(allocationStore.List()).To(HaveLen(2))
			})
		})
	})

	Describe("Allocate", func() {
		var container executor.Container
		BeforeEach(func() {
			container = executor.Container{
				Guid:     "banana",
				MemoryMB: 512,
				DiskMB:   512,
			}
		})

		Context("when the guid is available", func() {
			It("it is marked as RESERVED", func() {
				allocation, err := allocationStore.Allocate(logger, container)
				Expect(err).NotTo(HaveOccurred())

				Expect(allocation.Guid).To(Equal(container.Guid))
				Expect(allocation.State).To(Equal(executor.StateReserved))
				Expect(allocation.AllocatedAt).To(Equal(currentTime.UnixNano()))

				Expect(fakeEventEmitter.EmitCallCount()).To(Equal(1))
				Expect(fakeEventEmitter.EmitArgsForCall(0)).To(Equal(executor.NewContainerReservedEvent(allocation)))
			})
		})

		Context("when the guid is not available", func() {
			BeforeEach(func() {
				_, err := allocationStore.Allocate(logger, container)
				Expect(err).NotTo(HaveOccurred())
			})

			It("errors and does not store the duplicate", func() {
				_, err := allocationStore.Allocate(logger, container)
				Expect(err).To(HaveOccurred())
				Expect(allocationStore.List()).To(HaveLen(1))
			})
		})
	})

	Describe("Initialize", func() {
		var container executor.Container
		BeforeEach(func() {
			container = executor.Container{
				Guid:     "banana",
				MemoryMB: 512,
				DiskMB:   512,
			}
			_, err := allocationStore.Allocate(logger, container)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the guid is available", func() {
			It("it is marked as INITIALIZING", func() {
				err := allocationStore.Initialize(logger, container.Guid)
				Expect(err).NotTo(HaveOccurred())

				allocation, err := allocationStore.Lookup(container.Guid)
				Expect(err).NotTo(HaveOccurred())

				Expect(allocation.Guid).To(Equal(container.Guid))
				Expect(allocation.State).To(Equal(executor.StateInitializing))
			})
		})

		Context("when the guid is not available", func() {
			It("errors", func() {
				err := allocationStore.Initialize(logger, "doesnt-exist")
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(executor.ErrContainerNotFound))
			})
		})
	})

	Describe("Lookup", func() {
		var container executor.Container
		BeforeEach(func() {
			container = executor.Container{
				Guid:     "banana",
				MemoryMB: 512,
				DiskMB:   512,
			}
			_, err := allocationStore.Allocate(logger, container)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the guid is available", func() {
			It("it is returns the container", func() {
				allocation, err := allocationStore.Lookup(container.Guid)
				Expect(err).NotTo(HaveOccurred())
				Expect(allocation.Guid).To(Equal(container.Guid))
			})
		})

		Context("when the guid is not available", func() {
			It("errors", func() {
				_, err := allocationStore.Lookup("doesnt-exist")
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(executor.ErrContainerNotFound))
			})
		})
	})

	Describe("Fail", func() {
		var container executor.Container
		BeforeEach(func() {
			container = executor.Container{
				Guid:     "banana",
				MemoryMB: 512,
				DiskMB:   512,
			}
		})

		Context("when the container is not in the allocation store", func() {
			It("errors", func() {
				_, err := allocationStore.Fail(logger, container.Guid, "failure-response")
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(executor.ErrContainerNotFound))

				Expect(fakeEventEmitter.EmitCallCount()).To(Equal(0))
			})
		})

		Context("when the container is in the allocation store", func() {
			BeforeEach(func() {
				_, err := allocationStore.Allocate(logger, container)
				Expect(err).NotTo(HaveOccurred())
			})

			It("it is marked as COMPLETED with failure reason", func() {
				emitCallCount := fakeEventEmitter.EmitCallCount()
				allocation, err := allocationStore.Fail(logger, container.Guid, "failure-reason")
				Expect(err).NotTo(HaveOccurred())

				Expect(allocation.Guid).To(Equal(container.Guid))
				Expect(allocation.State).To(Equal(executor.StateCompleted))
				Expect(allocation.RunResult).To(Equal(executor.ContainerRunResult{
					Failed:        true,
					FailureReason: "failure-reason",
				}))

				Expect(fakeEventEmitter.EmitCallCount()).To(Equal(emitCallCount + 1))
				Expect(fakeEventEmitter.EmitArgsForCall(emitCallCount)).To(Equal(executor.NewContainerCompleteEvent(allocation)))
			})

			It("remains in the allocation store as reserved", func() {
				c, err := allocationStore.Lookup(container.Guid)
				Expect(err).NotTo(HaveOccurred())
				Expect(c.State).To(Equal(executor.StateReserved))
			})

			Context("when the container is already in the completed state", func() {
				BeforeEach(func() {
					err := allocationStore.Initialize(logger, container.Guid)
					Expect(err).NotTo(HaveOccurred())

					_, err = allocationStore.Fail(logger, container.Guid, "force-completed")
					Expect(err).NotTo(HaveOccurred())
				})

				It("remains in the allocation store as completed", func() {
					c, err := allocationStore.Lookup(container.Guid)
					Expect(err).NotTo(HaveOccurred())
					Expect(c.State).To(Equal(executor.StateCompleted))
				})

				It("fails with an invalid transition error", func() {
					expectedEmitCount := fakeEventEmitter.EmitCallCount()

					_, err := allocationStore.Fail(logger, container.Guid, "already-completed")
					Expect(err).To(Equal(executor.ErrInvalidTransition))

					Expect(fakeEventEmitter.EmitCallCount()).To(Equal(expectedEmitCount))
				})
			})
		})
	})

	Describe("Deallocate", func() {
		var container executor.Container

		BeforeEach(func() {
			container = executor.Container{
				Guid:     "banana",
				MemoryMB: 512,
				DiskMB:   512,
			}
		})

		Context("when the guid is in the list", func() {
			BeforeEach(func() {
				_, err := allocationStore.Allocate(logger, container)
				Expect(err).NotTo(HaveOccurred())
			})

			It("it is removed from the list, and returns true", func() {
				count := len(allocationStore.List())

				deallocated := allocationStore.Deallocate(logger, container.Guid)
				Expect(deallocated).To(BeTrue())

				Expect(allocationStore.List()).To(HaveLen(count - 1))
			})
		})

		Context("when the guid is not in the list", func() {
			It("returns false", func() {
				deallocated := allocationStore.Deallocate(logger, "doesnt-exist")
				Expect(deallocated).To(BeFalse())
			})
		})
	})

	Describe("Registry Pruner", func() {
		var (
			expirationTime time.Duration
			process        ifrit.Process
		)

		BeforeEach(func() {
			_, err := allocationStore.Allocate(logger, executor.Container{
				Guid:     "forever-reserved",
				MemoryMB: 512,
				DiskMB:   512,
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = allocationStore.Allocate(logger, executor.Container{
				Guid:     "eventually-initialized",
				MemoryMB: 512,
				DiskMB:   512,
			})
			Expect(err).NotTo(HaveOccurred())

			err = allocationStore.Initialize(logger, "eventually-initialized")
			Expect(err).NotTo(HaveOccurred())

			expirationTime = 20 * time.Millisecond

			pruner := allocationStore.RegistryPruner(logger, expirationTime)
			process = ginkgomon.Invoke(pruner)
		})

		AfterEach(func() {
			ginkgomon.Interrupt(process)
		})

		Context("when the elapsed time is less than expiration period", func() {
			BeforeEach(func() {
				fakeClock.Increment(expirationTime / 2)
			})

			It("all containers are still in the list", func() {
				Consistently(allocationStore.List).Should(HaveLen(2))
			})
		})

		Context("when the elapsed time is more than expiration period", func() {
			BeforeEach(func() {
				fakeClock.Increment(2 * expirationTime)
			})

			It("it removes only RESERVED containers from the list", func() {
				Eventually(allocationStore.List).Should(HaveLen(1))
				Expect(allocationStore.List()[0].Guid).To(Equal("eventually-initialized"))
			})
		})
	})

	Describe("Transitions", func() {
		expectations := []transitionExpectation{
			{to: "reserve", from: "non-existent", assertError: "does not occur"},
			{to: "reserve", from: "reserved", assertError: "occurs"},
			{to: "reserve", from: "initializing", assertError: "occurs"},
			{to: "reserve", from: "failed", assertError: "occurs"},

			{to: "initialize", from: "non-existent", assertError: "occurs"},
			{to: "initialize", from: "reserved", assertError: "does not occur"},
			{to: "initialize", from: "initializing", assertError: "occurs"},
			{to: "initialize", from: "failed", assertError: "occurs"},

			{to: "fail", from: "non-existent", assertError: "occurs"},
			{to: "fail", from: "reserved", assertError: "does not occur"},
			{to: "fail", from: "initializing", assertError: "does not occur"},
			{to: "fail", from: "failed", assertError: "occurs"},
		}

		for _, expectation := range expectations {
			expectation := expectation
			It("error "+expectation.assertError+" when transitioning from "+expectation.from+" to "+expectation.to, func() {
				container := executor.Container{Guid: "some-guid"}
				expectation.driveFromState(allocationStore, container)
				err := expectation.transitionToState(allocationStore, container)
				expectation.checkErrorResult(err)
			})
		}
	})
})

type transitionExpectation struct {
	from        string
	to          string
	assertError string
}

func (expectation transitionExpectation) driveFromState(allocationStore *allocationstore.AllocationStore, container executor.Container) {
	switch expectation.from {
	case "non-existent":

	case "reserved":
		_, err := allocationStore.Allocate(logger, container)
		Expect(err).NotTo(HaveOccurred())

	case "initializing":
		_, err := allocationStore.Allocate(logger, container)
		Expect(err).NotTo(HaveOccurred())

		err = allocationStore.Initialize(logger, container.Guid)
		Expect(err).NotTo(HaveOccurred())

	case "failed":
		_, err := allocationStore.Allocate(logger, container)
		Expect(err).NotTo(HaveOccurred())

		err = allocationStore.Initialize(logger, container.Guid)
		Expect(err).NotTo(HaveOccurred())

		_, err = allocationStore.Fail(logger, container.Guid, "failure-reason")
		Expect(err).NotTo(HaveOccurred())

	default:
		Fail("unknown 'from' state: " + expectation.from)
	}
}

func (expectation transitionExpectation) transitionToState(allocationStore *allocationstore.AllocationStore, container executor.Container) error {
	switch expectation.to {
	case "reserve":
		_, err := allocationStore.Allocate(logger, container)
		return err

	case "initialize":
		return allocationStore.Initialize(logger, container.Guid)

	case "fail":
		_, err := allocationStore.Fail(logger, container.Guid, "failure-reason")
		return err

	default:
		Fail("unknown 'to' state: " + expectation.to)
		return nil
	}
}

func (expectation transitionExpectation) checkErrorResult(err error) {
	switch expectation.assertError {
	case "occurs":
		Expect(err).To(HaveOccurred())
	case "does not occur":
		Expect(err).NotTo(HaveOccurred())
	default:
		Fail("unknown 'assertErr' expectation: " + expectation.assertError)
	}
}
