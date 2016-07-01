package steps

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/executor"
	"github.com/cloudfoundry-incubator/executor/depot/log_streamer"
	"github.com/cloudfoundry-incubator/garden"
	"github.com/pivotal-golang/clock"
	"github.com/pivotal-golang/lager"
)

const TERMINATE_TIMEOUT = 10 * time.Second
const EXIT_TIMEOUT = 1 * time.Minute

var ErrExitTimeout = errors.New("process did not exit")

type runStep struct {
	container            garden.Container
	model                models.RunAction
	streamer             log_streamer.LogStreamer
	logger               lager.Logger
	externalIP           string
	portMappings         []executor.PortMapping
	exportNetworkEnvVars bool
	clock                clock.Clock
	zone                 string

	*canceller
}

func NewRun(
container garden.Container,
model models.RunAction,
streamer log_streamer.LogStreamer,
logger lager.Logger,
externalIP string,
portMappings []executor.PortMapping,
exportNetworkEnvVars bool,
clock clock.Clock,
zone string,
) *runStep {
	logger = logger.Session("run-step")
	return &runStep{
		container:            container,
		model:                model,
		streamer:             streamer,
		logger:               logger,
		externalIP:           externalIP,
		portMappings:         portMappings,
		exportNetworkEnvVars: exportNetworkEnvVars,
		clock:                clock,
		zone:                      zone,

		canceller: newCanceller(),
	}
}

func (step *runStep) Perform() error {
	step.logger.Info("running")

	envVars := step.convertEnvironmentVariables(step.model.Env)

	if step.exportNetworkEnvVars {
		envVars = append(envVars, step.networkingEnvVars()...)
	}

	cancel := step.Cancelled()

	select {
	case <-cancel:
		step.logger.Info("cancelled-before-creating-process")
		return ErrCancelled
	default:
	}

	exitStatusChan := make(chan int, 1)
	errChan := make(chan error, 1)

	step.logger.Info("creating-process")
	var nofile *uint64
	if step.model.ResourceLimits != nil {
		nofile = step.model.ResourceLimits.Nofile
	}
	process, err := step.container.Run(garden.ProcessSpec{
		Path: step.model.Path,
		Args: step.model.Args,
		Dir:  step.model.Dir,
		Env:  envVars,
		User: step.model.User,

		Limits: garden.ResourceLimits{Nofile: nofile},
	}, garden.ProcessIO{
		Stdout: step.streamer.Stdout(),
		Stderr: step.streamer.Stderr(),
	})
	if err != nil {
		step.logger.Error("failed-creating-process", err)
		return err
	}

	logger := step.logger.WithData(lager.Data{"process": process.ID()})
	logger.Info("successful-process-create")

	go func() {
		exitStatus, err := process.Wait()
		if err != nil {
			errChan <- err
		} else {
			exitStatusChan <- exitStatus
		}
	}()

	var killSwitch <-chan time.Time
	var exitTimeout <-chan time.Time

	for {
		select {
		case exitStatus := <-exitStatusChan:
			cancelled := cancel == nil

			logger.Info("process-exit", lager.Data{
				"exitStatus": exitStatus,
				"cancelled":  cancelled,
			})
			step.streamer.Stdout().Write([]byte(fmt.Sprintf("Exit status %d", exitStatus)))
			step.streamer.Flush()

			if cancelled {
				return ErrCancelled
			}

			if exitStatus != 0 {
				info, err := step.container.Info()
				if err != nil {
					logger.Error("failed-to-get-info", err)
				} else {
					for _, ev := range info.Events {
						if ev == "out of memory" {
							return NewEmittableError(nil, "Exited with status %d (out of memory)", exitStatus)
						}
					}
				}

				return NewEmittableError(nil, "Exited with status %d", exitStatus)
			}

			return nil

		case err := <-errChan:
			logger.Error("running-error", err)
			return err

		case <-cancel:
			logger.Debug("signalling-terminate")
			err := process.Signal(garden.SignalTerminate)
			if err != nil {
				logger.Error("signalling-terminate-failed", err)
			}

			logger.Debug("signalling-terminate-success")
			cancel = nil

			killTimer := step.clock.NewTimer(TERMINATE_TIMEOUT)
			defer killTimer.Stop()

			killSwitch = killTimer.C()

		case <-killSwitch:
			logger.Debug("signalling-kill")
			err := process.Signal(garden.SignalKill)
			if err != nil {
				logger.Error("signalling-kill-failed", err)
			}

			logger.Debug("signalling-kill-success")
			killSwitch = nil

			exitTimer := step.clock.NewTimer(EXIT_TIMEOUT)
			defer exitTimer.Stop()

			exitTimeout = exitTimer.C()

		case <-exitTimeout:
			logger.Error("process-did-not-exit", nil, lager.Data{
				"timeout": EXIT_TIMEOUT,
			})

			return ErrExitTimeout
		}
	}

	panic("unreachable")
}

func (step *runStep) convertEnvironmentVariables(environmentVariables []*models.EnvironmentVariable) []string {
	converted := []string{}

	for _, env := range environmentVariables {
		val := step.dezoneVcapServices(env)
		converted = append(converted, env.Name + "=" + val)
	}

	return converted
}

func (step *runStep) dezoneVcapServices(env *models.EnvironmentVariable) string {

	if env.Name == "VCAP_SERVICES" {
		return step.checkIfZonedConfig(env.Value)
	}

	return env.Value
}

func (step *runStep) checkIfZonedConfig(vcapServicesJson string) string {

	var parsed map[string]interface{}

	err := json.Unmarshal([]byte(vcapServicesJson), &parsed)
	if err != nil {
		step.logger.Error("error-parsing-vcap-services-json", err)
		return vcapServicesJson
	}

	for _, v := range parsed {
		vv, ok := v.([]interface{})
		if ok {
			vvv, ok := vv[0].(map[string]interface{})
			if ok {
				creds, ok := vvv["credentials"].(map[string]interface{})
				if ok {
					if val, ok := creds[step.zone]; ok {
						// replace zoned credentials with details for the zone we are in
						vvv["credentials"] = val
					}
				}
			}
		}
	}

	data, err := json.Marshal(parsed)
	if err != nil {
		step.logger.Error("error-marshalling-vcap-services", err)
		return vcapServicesJson
	}

	return string(data)
}

func (step *runStep) networkingEnvVars() []string {
	var envVars []string

	envVars = append(envVars, "CF_INSTANCE_IP="+step.externalIP)

	if len(step.portMappings) > 0 {
		envVars = append(envVars, fmt.Sprintf("CF_INSTANCE_PORT=%d", step.portMappings[0].HostPort))
		envVars = append(envVars, fmt.Sprintf("CF_INSTANCE_ADDR=%s:%d", step.externalIP, step.portMappings[0].HostPort))

		type cfPortMapping struct {
			External uint16 `json:"external"`
			Internal uint16 `json:"internal"`
		}

		cfPortMappings := make([]cfPortMapping, len(step.portMappings))
		for i, portMapping := range step.portMappings {
			cfPortMappings[i] = cfPortMapping{
				Internal: portMapping.ContainerPort,
				External: portMapping.HostPort,
			}
		}

		mappingsValue, err := json.Marshal(cfPortMappings)
		if err != nil {
			step.logger.Error("marshal-networking-env-vars-failed", err)
			mappingsValue = []byte("[]")
		}

		envVars = append(envVars, fmt.Sprintf("CF_INSTANCE_PORTS=%s", mappingsValue))
	} else {
		envVars = append(envVars, "CF_INSTANCE_PORT=")
		envVars = append(envVars, "CF_INSTANCE_ADDR=")
		envVars = append(envVars, "CF_INSTANCE_PORTS=[]")
	}

	return envVars
}
