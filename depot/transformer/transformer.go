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
	"github.com/pivotal-golang/archiver/compressor"
	"github.com/pivotal-golang/archiver/extractor"
	"github.com/pivotal-golang/clock"
	"github.com/pivotal-golang/lager"
)

var ErrNoCheck = errors.New("no check configured")

type Transformer struct {
	cachedDownloader     cacheddownloader.CachedDownloader
	uploader             uploader.Uploader
	extractor            extractor.Extractor
	compressor           compressor.Compressor
	downloadLimiter      chan struct{}
	uploadLimiter        chan struct{}
	tempDir              string
	exportNetworkEnvVars bool
	clock                clock.Clock
	zone		     string
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
	clock clock.Clock,
	zone string,
) *Transformer {
	return &Transformer{
		cachedDownloader:     cachedDownloader,
		uploader:             uploader,
		extractor:            extractor,
		compressor:           compressor,
		downloadLimiter:      downloadLimiter,
		uploadLimiter:        uploadLimiter,
		tempDir:              tempDir,
		exportNetworkEnvVars: exportNetworkEnvVars,
		clock:                clock,
		zone: 		      zone,
	}
}

func (transformer *Transformer) StepFor(
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
			transformer.exportNetworkEnvVars,
			transformer.clock,
			transformer.zone,
		)

	case *models.DownloadAction:
		return steps.NewDownload(
			container,
			*actionModel,
			transformer.cachedDownloader,
			transformer.downloadLimiter,
			logStreamer.WithSource(actionModel.LogSource),
			logger,
		)

	case *models.UploadAction:
		return steps.NewUpload(
			container,
			*actionModel,
			transformer.uploader,
			transformer.compressor,
			transformer.tempDir,
			logStreamer.WithSource(actionModel.LogSource),
			transformer.uploadLimiter,
			logger,
		)

	case *models.EmitProgressAction:
		return steps.NewEmitProgress(
			transformer.StepFor(
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
			transformer.StepFor(
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
			transformer.StepFor(
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
			subSteps[i] = transformer.StepFor(
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
			subSteps[i] = transformer.StepFor(
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
			subSteps[i] = transformer.StepFor(
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
