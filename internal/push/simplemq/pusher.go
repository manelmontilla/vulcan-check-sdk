package simplemq

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// Pusher send check status updates to a simplemq queue.
type Pusher struct {
	logger  *log.Entry
	checkID string
	addr    string
}

// NewPusher Creates a new push component that can be used to inform the agent state changes
// of the check by using http rest calls.
func NewPusher(checkID string, config string, logger *log.Entry) *Pusher {

	logger.WithFields(log.Fields{checkID: checkID}).Debug("Creating NewRestPusher with params")
	// For the simplemq pusher the config is just the address the mq is listening on.
	addr := config
	r := &Pusher{
		checkID: checkID,
		logger:  logger,
		addr:    addr,
	}
	return r
}

// UpdateState sends a update state message to the simplemq service.
func (p *Pusher) UpdateState(state interface{}) {
	l := p.logger.WithField("msg", state)
	l.Debugf("pushing check state %+v", state)
	err := p.Push(p.checkID, state)
	// An error sending a status change makes the check to panic.
	if err != nil {
		panic(err)
	}
}

// Push sends a message to simplemq endpoint.
func (p *Pusher) Push(checkID string, state interface{}) error {
	c := http.Client{}
	url := fmt.Sprintf("%s/messages/%s", p.addr, checkID)
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	r := bytes.NewReader(payload)
	resp, err := c.Post(url, "text/plain", r)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status sending msg to simplemq: %d", resp.StatusCode)
	}
	return nil
}

// Shutdown signals the pusher to stop accepting messages and wait for the
// pending messages to be send.
func (p *Pusher) Shutdown() {}
