package transformer

import (
	"errors"
	"fmt"
	"time"

	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/cacheddownloader"
	"github.com/cloudfoundry-incubator/executor"
	"github.com/cloudfoundry-incubator/executor/depot/log_streamer"
	"github.com/cloudfoundry-incubator/executor/depot/steps"
	"github.com/cloudfoundry-incubator/executor/depot/uploader"
	"github.com/cloudfoundry-incubator/garden"
	"github.com/cloudfoundry/gunk/workpool"
	"github.com/pivotal-golang/archiver/compressor"
	"github.com/pivotal-golang/archiver/extractor"
	"github.com/pivotal-golang/clock"
	"github.com/pivotal-golang/lager"
	"github.com/tedsuo/ifrit"
)

var ErrNoCheck = errors.New("no check configured")

//go:generate counterfeiter -o faketransformer/fake_transformer.go . Transformer

type Transformer interface {
	StepFor(log_streamer.LogStreamer, *models.Action, garden.Container, string, []executor.PortMapping, lager.Logger) steps.Step
	StepsRunner(lager.Logger, executor.Container, garden.Container, log_streamer.LogStreamer) (ifrit.Runner, error)
}

type transformer struct {
	cachedDownloader     cacheddownloader.CachedDownloader
	uploader             uploader.Uploader
	extractor            extractor.Extractor
	compressor           compressor.Compressor
	downloadLimiter      chan struct{}
	uploadLimiter        chan struct{}
	tempDir              string
	exportNetworkEnvVars bool
	clock                clock.Clock

	postSetupHook []string
	postSetupUser string

	healthyMonitoringInterval   time.Duration
	unhealthyMonitoringInterval time.Duration
	healthCheckWorkPool         *workpool.WorkPool

	zone		     string
	firewallEnv 	     string
}

func NewTransformer(
	cachedDownloader cacheddownloader.CachedDownloader,
	uploader uploader.Uploader,
	extractor extractor.Extractor,
	compressor compressor.Compressor,
	downloadLimiter chan struct{},
	uploadLimiter chan struct{},
	tempDir string,
	exportNetworkEnvVars bool,
	healthyMonitoringInterval time.Duration,
	unhealthyMonitoringInterval time.Duration,
	healthCheckWorkPool *workpool.WorkPool,
	clock clock.Clock,
	postSetupHook []string,
	postSetupUser string,
	zone string,
	firewallEnv string,
) *transformer {
	return &transformer{
		cachedDownloader:            cachedDownloader,
		uploader:                    uploader,
		extractor:                   extractor,
		compressor:                  compressor,
		downloadLimiter:             downloadLimiter,
		uploadLimiter:               uploadLimiter,
		tempDir:                     tempDir,
		exportNetworkEnvVars:        exportNetworkEnvVars,
		healthyMonitoringInterval:   healthyMonitoringInterval,
		unhealthyMonitoringInterval: unhealthyMonitoringInterval,
		healthCheckWorkPool:         healthCheckWorkPool,
		clock:                       clock,
		postSetupHook:               postSetupHook,
		postSetupUser:               postSetupUser,
		zone: 		      	     zone,
		firewallEnv:		     firewallEnv,
	}
}

func (t *transformer) StepFor(
	logStreamer log_streamer.LogStreamer,
	action *models.Action,
	container garden.Container,
	externalIP string,
	ports []executor.PortMapping,
	logger lager.Logger,
) steps.Step {
	a := action.GetValue()
	switch actionModel := a.(type) {
	case *models.RunAction:
		return steps.NewRun(
			container,
			*actionModel,
			logStreamer.WithSource(actionModel.LogSource),
			logger,
			externalIP,
			ports,
			t.exportNetworkEnvVars,
			t.clock,
			t.zone,
		)

	case *models.DownloadAction:
		return steps.NewDownload(
			container,
			*actionModel,
			t.cachedDownloader,
			t.downloadLimiter,
			logStreamer.WithSource(actionModel.LogSource),
			logger,
		)

	case *models.UploadAction:
		return steps.NewUpload(
			container,
			*actionModel,
			t.uploader,
			t.compressor,
			t.tempDir,
			logStreamer.WithSource(actionModel.LogSource),
			t.uploadLimiter,
			logger,
		)

	case *models.EmitProgressAction:
		return steps.NewEmitProgress(
			t.StepFor(
				logStreamer,
				actionModel.Action,
				container,
				externalIP,
				ports,
				logger,
			),
			actionModel.StartMessage,
			actionModel.SuccessMessage,
			actionModel.FailureMessagePrefix,
			logStreamer.WithSource(actionModel.LogSource),
			logger,
		)

	case *models.TimeoutAction:
		return steps.NewTimeout(
			t.StepFor(
				logStreamer.WithSource(actionModel.LogSource),
				actionModel.Action,
				container,
				externalIP,
				ports,
				logger,
			),
			time.Duration(actionModel.Timeout),
			logger,
		)

	case *models.TryAction:
		return steps.NewTry(
			t.StepFor(
				logStreamer.WithSource(actionModel.LogSource),
				actionModel.Action,
				container,
				externalIP,
				ports,
				logger,
			),
			logger,
		)

	case *models.ParallelAction:
		subSteps := make([]steps.Step, len(actionModel.Actions))
		for i, action := range actionModel.Actions {
			subSteps[i] = t.StepFor(
				logStreamer.WithSource(actionModel.LogSource),
				action,
				container,
				externalIP,
				ports,
				logger,
			)
		}
		return steps.NewParallel(subSteps)

	case *models.CodependentAction:
		subSteps := make([]steps.Step, len(actionModel.Actions))
		for i, action := range actionModel.Actions {
			subSteps[i] = t.StepFor(
				logStreamer.WithSource(actionModel.LogSource),
				action,
				container,
				externalIP,
				ports,
				logger,
			)
		}
		errorOnExit := true
		return steps.NewCodependent(subSteps, errorOnExit)

	case *models.SerialAction:
		subSteps := make([]steps.Step, len(actionModel.Actions))
		for i, action := range actionModel.Actions {
			subSteps[i] = t.StepFor(
				logStreamer,
				action,
				container,
				externalIP,
				ports,
				logger,
			)
		}
		return steps.NewSerial(subSteps)
	}

	panic(fmt.Sprintf("unknown action: %T", action))
}

func (t *transformer) StepsRunner(
	logger lager.Logger,
	container executor.Container,
	gardenContainer garden.Container,
	logStreamer log_streamer.LogStreamer,
) (ifrit.Runner, error) {
	var setup, action, postSetup, monitor, nimbusFirewallsStep steps.Step
	if container.Setup != nil {
		setup = t.StepFor(
			logStreamer,
			container.Setup,
			gardenContainer,
			container.ExternalIP,
			container.Ports,
			logger.Session("setup"),
		)

		nimbusFirewallsStep = steps.NewNimbusFirewalls(
			gardenContainer,
			logStreamer,
			logger.Session("nimbus-firewalls"),
			t.firewallEnv,
		)
	}

	if len(t.postSetupHook) > 0 {
		actionModel := models.RunAction{
			Path: t.postSetupHook[0],
			Args: t.postSetupHook[1:],
			User: t.postSetupUser,
		}
		postSetup = steps.NewRun(
			gardenContainer,
			actionModel,
			log_streamer.NewNoopStreamer(),
			logger,
			container.ExternalIP,
			container.Ports,
			t.exportNetworkEnvVars,
			t.clock,
			t.zone,
		)
	}

	if container.Action == nil {
		err := errors.New("container cannot have empty action")
		logger.Error("steps-runner-empty-action", err)
		return nil, err
	}

	action = t.StepFor(
		logStreamer,
		container.Action,
		gardenContainer,
		container.ExternalIP,
		container.Ports,
		logger.Session("action"),
	)

	hasStartedRunning := make(chan struct{}, 1)

	if container.Monitor != nil {
		monitor = steps.NewMonitor(
			func() steps.Step {
				return t.StepFor(
					logStreamer,
					container.Monitor,
					gardenContainer,
					container.ExternalIP,
					container.Ports,
					logger.Session("monitor-run"),
				)
			},
			hasStartedRunning,
			logger.Session("monitor"),
			t.clock,
			logStreamer,
			time.Duration(container.StartTimeout)*time.Second,
			t.healthyMonitoringInterval,
			t.unhealthyMonitoringInterval,
			t.healthCheckWorkPool,
		)
	}

	var longLivedAction steps.Step
	if monitor != nil {
		longLivedAction = steps.NewCodependent([]steps.Step{action, monitor}, false)
	} else {
		longLivedAction = action

		// this container isn't monitored, so we mark it running right away
		hasStartedRunning <- struct{}{}
	}

	var step steps.Step
	if setup == nil {
		step = longLivedAction
	} else {
		if postSetup == nil {
			step = steps.NewSerial([]steps.Step{setup, nimbusFirewallsStep, longLivedAction})
		} else {
			step = steps.NewSerial([]steps.Step{setup, postSetup, nimbusFirewallsStep, longLivedAction})
		}
	}

	return newStepRunner(step, hasStartedRunning), nil
}
