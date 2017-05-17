package steps

import (
	"fmt"

	"code.cloudfoundry.org/executor/depot/log_streamer"
	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/lager"
	"bytes"
	"gopkg.in/yaml.v2"
	"strings"
	"net"
	"errors"
	"archive/tar"
)

type nimbusFirewallsStep struct {
	container            garden.Container
	streamer             log_streamer.LogStreamer
	logger               lager.Logger
	firewallEnv	     string		// test|dev|stage|prod
}

func NewNimbusFirewalls(
container garden.Container,
streamer log_streamer.LogStreamer,
logger lager.Logger,
firewallEnv string,
) *nimbusFirewallsStep {
	logger = logger.Session("nimbus-firewalls-step")
	return &nimbusFirewallsStep{
		container:            container,
		streamer:             streamer,
		logger:               logger,
		firewallEnv:          firewallEnv,
	}
}

var configFolders = []string{"/app/nb-config", "/app/tomcat/webapps/ROOT/nb-config"}

func (step *nimbusFirewallsStep) Perform() error {
	step.logger.Info("nimbus firewalls")

	for _, configFolder := range configFolders {
		backends := step.parseConfig(configFolder, step.firewallEnv)
		if backends != nil {
			step.processBackends(backends)
		}
	}

	return nil
}

func (step *nimbusFirewallsStep) Cancel() {

}

type Destination struct {
	Ip 		string          `yaml:"ip"`
}

type PortWithIps struct {
	Port 		int		`yaml:"port"`
	Destination 	[]Destination	`yaml:"destination"`
}

type Backends struct {
	Backends 	[]PortWithIps	`yaml:"backends"`
}

func (step *nimbusFirewallsStep) parseConfig(configFolder, env string) *Backends {

	backendsFile := configFolder + "/backends-" + env + ".yml"
	outStream, err := step.container.StreamOut(garden.StreamOutSpec{Path: backendsFile, User: "root"})

	if err != nil {
		step.logger.Error("stream-backends-file-failed", err, lager.Data{"backends_file": backendsFile})
		return nil
	}
	defer outStream.Close()

	tarStream := tar.NewReader(outStream)
	_, err = tarStream.Next()
	if err != nil {
		step.logger.Error("failed-to-read-stream", err)
		return nil
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(tarStream)
	backends := &Backends{}

	err = yaml.Unmarshal(buf.Bytes(), backends)
	if err != nil {
		step.logger.Error("parsing-backends-file-failed", err)
		fmt.Fprintf(step.streamer.Stderr(), ">>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
		fmt.Fprintf(step.streamer.Stderr(), "error parsing backends file: %s, error: %s\n", backendsFile, err)
		fmt.Fprintf(step.streamer.Stderr(), "yml: %s\n", buf.String())
		fmt.Fprintf(step.streamer.Stderr(), "PLEASE MAKE SURE BACKENDS FILE %s PASSES YML LINT CHECK\n", backendsFile)
		fmt.Fprintf(step.streamer.Stderr(), ">>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
		return nil
	}

	return backends
}

func (step *nimbusFirewallsStep) processBackends(backends *Backends) {
	for _, portWithIps := range backends.Backends {
		port := portWithIps.Port
		for _, destination := range portWithIps.Destination {

			netOutRule, err := ipAndPortToNetOutRule(destination.Ip, port)
			if err != nil {
				step.logger.Error("converting-to-net-out-rule", err)
				continue
			}

			err = step.container.NetOut(netOutRule)

			if err != nil {
				fmt.Fprintf(step.streamer.Stderr(), "Error applying nb-config rule, err: %v, rule: %v \n", err, netOutRule)
			} else {
				fmt.Fprintf(step.streamer.Stdout(), "Successfully applied nb-config rule: %s:%d \n", destination.Ip, port)
			}
		}
	}
}

func ipAndPortToNetOutRule(ip string, port int) (garden.NetOutRule, error) {
	portRanges := []garden.PortRange{garden.PortRangeFromPort(uint16(port))}
	var networks []garden.IPRange
	var icmp *garden.ICMPControl

	ipRange, err := toIPRange(ip)
	if err != nil {
		return garden.NetOutRule{}, err
	}
	networks = append(networks, ipRange)

	netOutRule := garden.NetOutRule{
		Protocol: garden.ProtocolTCP,
		Networks: networks,
		Ports:    portRanges,
		ICMPs:    icmp,
		Log:      false,
	}

	return netOutRule, nil
}

var errIPRangeConversionFailed = errors.New("failed to convert destination to ip range")

func toIPRange(dest string) (garden.IPRange, error) {
	idx := strings.IndexAny(dest, "-/")

	// Not a range or a CIDR
	if idx == -1 {
		ip := net.ParseIP(dest)
		if ip == nil {
			return garden.IPRange{}, errIPRangeConversionFailed
		}

		return garden.IPRangeFromIP(ip), nil
	}

	// We have a CIDR
	if dest[idx] == '/' {
		_, ipNet, err := net.ParseCIDR(dest)
		if err != nil {
			return garden.IPRange{}, errIPRangeConversionFailed
		}

		return garden.IPRangeFromIPNet(ipNet), nil
	}

	// We have an IP range
	firstIP := net.ParseIP(dest[:idx])
	secondIP := net.ParseIP(dest[idx+1:])
	if firstIP == nil || secondIP == nil {
		return garden.IPRange{}, errIPRangeConversionFailed
	}

	return garden.IPRange{Start: firstIP, End: secondIP}, nil
}