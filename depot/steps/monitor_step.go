package steps

import (
	"fmt"
	"time"

	"github.com/cloudfoundry/gunk/timeprovider"
	"github.com/pivotal-golang/lager"
)

type HealthEvent bool

const (
	Healthy   HealthEvent = true
	Unhealthy HealthEvent = false
)

func invalidInterval(field string, interval time.Duration) error {
	return fmt.Errorf("The %s interval, %s, is not positive.", field, interval.String())
}

type monitorStep struct {
	check  Step
	events chan<- HealthEvent

	logger       lager.Logger
	timeProvider timeprovider.TimeProvider

	startTimeout      time.Duration
	healthyInterval   time.Duration
	unhealthyInterval time.Duration

	cancel chan struct{}
}

func NewMonitor(
	check Step,
	events chan<- HealthEvent,
	logger lager.Logger,
	timeProvider timeprovider.TimeProvider,
	startTimeout time.Duration,
	healthyInterval time.Duration,
	unhealthyInterval time.Duration,
) Step {
	logger = logger.Session("MonitorAction")

	return &monitorStep{
		check:             check,
		events:            events,
		logger:            logger,
		timeProvider:      timeProvider,
		startTimeout:      startTimeout,
		healthyInterval:   healthyInterval,
		unhealthyInterval: unhealthyInterval,
		cancel:            make(chan struct{}),
	}
}

func (step *monitorStep) Perform() error {

	if step.healthyInterval <= 0 {
		return invalidInterval("healthy", step.healthyInterval)
	}

	if step.unhealthyInterval <= 0 {
		return invalidInterval("unhealthy", step.unhealthyInterval)
	}

	healthy := false
	interval := step.unhealthyInterval

	var startBy *time.Time
	if step.startTimeout > 0 {
		t := step.timeProvider.Now().Add(step.startTimeout)
		startBy = &t
	}

	timer := step.timeProvider.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case now := <-timer.C():
			stepErr := step.check.Perform()
			nowHealthy := stepErr == nil

			if healthy && !nowHealthy {
				step.logger.Info("transitioned-to-unhealthy")
				step.events <- Unhealthy
				return stepErr
			} else if !healthy && nowHealthy {
				step.logger.Info("transitioned-to-healthy")
				healthy = true
				step.events <- Healthy
				interval = step.healthyInterval
				startBy = nil
			}

			if startBy != nil && now.After(*startBy) {
				if !healthy {
					step.logger.Info("timed-out-before-healthy")
					step.events <- Unhealthy
					return stepErr
				}
				startBy = nil
			}
		case <-step.cancel:
			return nil
		}

		timer.Reset(interval)
	}

	return nil
}

func (step *monitorStep) Cancel() {
	step.logger.Info("cancelling")
	close(step.cancel)
}