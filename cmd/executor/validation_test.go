package main_test

import (
	"os/exec"
	"time"

	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("Main", func() {
	Context("Validation", func() {
		It("reports invalid values", func() {
			runner := ginkgomon.New(ginkgomon.Config{
				Name:          "executor",
				AnsiColorCode: "91m",
				StartCheck:    "executor.started",
				// executor may destroy containers on start, which can take a bit
				StartCheckTimeout: 30 * time.Second,
				Command: exec.Command(
					executorPath,
					"-containerMaxCpuShares", "0",
					"-healthyMonitoringInterval", "0",
					"-unhealthyMonitoringInterval", "0",
				),
			})

			ifrit.Invoke(runner)
			Expect(runner).NotTo(gexec.Exit(0))

			Expect(runner).To(gbytes.Say("max-cpu-shares-invalid"))
			Expect(runner).To(gbytes.Say("healthy-monitoring-interval-invalid"))
			Expect(runner).To(gbytes.Say("unhealthy-monitoring-interval-invalid"))
		})
	})
})
