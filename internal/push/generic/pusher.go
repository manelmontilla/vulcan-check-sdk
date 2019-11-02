package generic

import (
	log "github.com/sirupsen/logrus"
)

// Sender represents the concrete service that sends
// the status updates to the channel.
type Sender interface {
	Push(CheckID string, state interface{}) error
}

// Pusher send check status updates to a generic async channel.
type Pusher struct {
	logger  *log.Entry
	checkID string
	s       Sender
}

// NewRestPusher Creates a new push component that can be used to inform the agent state changes
// of the check by using http rest calls.
func NewRestPusher(checkID string, sender Sender, logger *log.Entry) *Pusher {
	logger.WithFields(log.Fields{checkID: checkID}).Debug("Creating NewRestPusher with params")
	r := &Pusher{
		checkID: checkID,
		logger:  logger,
		s:       sender,
	}
	return r
}

// UpdateState sends a update state message to an agent by calling the rest api
// the agent must expose. Note that the function doesn't return any kind of
// error, that's because a Pusher is expected to handle error in sending push
// messages by it's own. WARN: Calling this method after calling ShutDown method
// will cause the program to panic.
func (p *Pusher) UpdateState(state interface{}) {
	l := p.logger.WithField("msg", state)
	l.Debugf("pushing check state %+v", state)
	err := p.s.Push(p.checkID, state)
	// An error sending a status change makes the check to panic.
	if err != nil {
		panic(err)
	}
}

// Shutdown signals the pusher to stop accepting messages and wait for the
// pending messages to be send.
func (p *Pusher) Shutdown() {}
