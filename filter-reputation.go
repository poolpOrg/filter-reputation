package main

/*
 * Copyright (c) 2024 Gilles Chehade <gilles@poolp.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/poolpOrg/OpenSMTPD-framework/filter"
)

const (
	basePenalty = .1
	baseReward  = .05
)

var degradationFactors = map[string]float64{
	"IP":         1.0,
	"rDNS":       0.8,
	"heloname":   0.6,
	"mailFrom":   0.4,
	"mailDomain": 0.2,
	"recipient":  0.5,
}

const (
	ipWeight       = 0.5
	rdnsWeight     = 0.3
	helonameWeight = 0.2
)

func clamp(value float64, min float64, max float64) float64 {
	if value < min {
		return min
	} else if value > max {
		return max
	}
	return value
}

func applyPenalty(resourceType string, reputationScore float64) float64 {
	penalty := basePenalty * degradationFactors[resourceType]
	return clamp(reputationScore-penalty, 0.0, 1.0)
}

func applyReward(resourceType string, reputationScore float64) float64 {
	reward := baseReward * degradationFactors[resourceType]
	return clamp(reputationScore+reward, 0.0, 1.0)
}

var reputation *Reputation

type Reputation struct {
	ipAddress map[string]float64
	rdns      map[string]float64
	hostname  map[string]float64
}

func NewReputation() *Reputation {
	return &Reputation{
		ipAddress: make(map[string]float64),
		rdns:      make(map[string]float64),
		hostname:  make(map[string]float64),
	}
}

func (r *Reputation) IPAddress(ip net.IP) float64 {
	if score, ok := r.ipAddress[ip.String()]; ok {
		return score
	}
	return 0.5
}

func (r *Reputation) ReverseDNS(hostname string) float64 {
	if score, ok := r.rdns[hostname]; ok {
		return score
	}
	return 0.5
}

func (r *Reputation) Hostname(hostname string) float64 {
	if score, ok := r.hostname[hostname]; ok {
		return score
	}
	return 0.5
}

func (r *Reputation) MailFrom(hostname string) float64 {
	return 0.5
}

func (r *Reputation) MailFromDomain(hostname string) float64 {
	return 0.5
}

func (r *Reputation) Feedback(session *SessionData) {
	// Overall reputation score at the end of the session
	overallReputation := session.overallReputation

	// Calculate the feedback for each resource
	ipFeedback := overallReputation * ipWeight
	rdnsFeedback := overallReputation * rdnsWeight
	hostnameFeedback := overallReputation * helonameWeight

	// Update the resource reputations with the feedback
	session.ipReputation = clamp((session.ipReputation+ipFeedback)/2, 0.0, 1.0)
	session.rdnsReputation = clamp((session.rdnsReputation+rdnsFeedback)/2, 0.0, 1.0)
	session.heloReputation = clamp((session.heloReputation+hostnameFeedback)/2, 0.0, 1.0)

	// Update the global reputation scores
	r.ipAddress[session.ip.String()] = session.ipReputation
	r.rdns[session.rDNS] = session.rdnsReputation
	r.hostname[session.heloname] = session.heloReputation

	fmt.Fprintf(os.Stderr, "Reputation IP updated to: %.2f\n", session.ipReputation)
	fmt.Fprintf(os.Stderr, "Reputation RDNS updated to: %.2f\n", session.rdnsReputation)
	fmt.Fprintf(os.Stderr, "Reputation Hostname updated to: %.2f\n", session.heloReputation)

}

type SessionData struct {
	hasReverseDNS   bool
	hasFcReverseDNS bool
	hasStartTLS     bool
	hasAuth         bool
	hasEHLO         bool

	rDNS     string
	ip       net.IP
	heloname string

	txBegin    int
	txData     int
	txCommit   int
	txRollback int
	txMailFrom int
	txRcptTo   int

	rsetCount int

	failedAuth int
	failedMail int
	failedRcpt int

	overallReputation float64
	ipReputation      float64
	rdnsReputation    float64
	heloReputation    float64
}

func linkConnectCb(timestamp time.Time, session filter.Session, rdns string, fcrdns string, src net.Addr, dest net.Addr) {
	session.Get().(*SessionData).ip = src.(*net.TCPAddr).IP
	session.Get().(*SessionData).rDNS = strings.ToLower(rdns)
	session.Get().(*SessionData).hasReverseDNS = rdns != "<unknown>"
	session.Get().(*SessionData).hasFcReverseDNS = fcrdns != "ok"

	ipScore := reputation.IPAddress(session.Get().(*SessionData).ip)
	rdnsScore := reputation.ReverseDNS(session.Get().(*SessionData).rDNS)
	overallReputation := ((ipScore * ipWeight) + (rdnsScore * rdnsWeight)) / 2

	if !session.Get().(*SessionData).hasReverseDNS {
		ipScore = applyPenalty("rDNS", ipScore)
		rdnsScore = applyPenalty("rDNS", rdnsScore)
	} else {
		ipScore = applyReward("rDNS", ipScore)
		rdnsScore = applyReward("rDNS", rdnsScore)
	}

	if !session.Get().(*SessionData).hasFcReverseDNS {
		ipScore = applyPenalty("FCrDNS", ipScore)
		rdnsScore = applyPenalty("rDNS", rdnsScore)
	} else {
		ipScore = applyReward("FCrDNS", ipScore)
		rdnsScore = applyReward("rDNS", rdnsScore)
	}

	session.Get().(*SessionData).overallReputation = overallReputation
	session.Get().(*SessionData).ipReputation = ipScore
	session.Get().(*SessionData).rdnsReputation = rdnsScore

	fmt.Fprintf(os.Stderr, "%s: %s: reputation: %f\n", timestamp, session, overallReputation)
}

func linkDisconnectCb(timestamp time.Time, session filter.Session) {
	fmt.Fprintf(os.Stderr, "%s: %s: link-disconnect\n", timestamp, session)
	reputation.Feedback(session.Get().(*SessionData))
}

func linkIdentifyCb(timestamp time.Time, session filter.Session, method string, hostname string) {
	session.Get().(*SessionData).hasEHLO = method == "EHLO"
	session.Get().(*SessionData).heloname = strings.ToLower(hostname)

	ipScore := reputation.IPAddress(session.Get().(*SessionData).ip)
	rdnsScore := reputation.ReverseDNS(session.Get().(*SessionData).rDNS)
	helonameScore := reputation.Hostname(session.Get().(*SessionData).heloname)

	if session.Get().(*SessionData).hasReverseDNS {
		if strings.ToLower(hostname) != session.Get().(*SessionData).rDNS {
			ipScore = applyPenalty("heloname", ipScore)
			rdnsScore = applyPenalty("heloname", rdnsScore)
			helonameScore = applyPenalty("heloname", helonameScore)
		} else {
			ipScore = applyReward("heloname", ipScore)
			rdnsScore = applyReward("heloname", rdnsScore)
			helonameScore = applyReward("heloname", helonameScore)
		}
	}
	session.Get().(*SessionData).heloReputation = helonameScore

	overallReputation := ((ipScore * ipWeight) + (rdnsScore * rdnsWeight) + (helonameScore * helonameWeight)) / 3
	session.Get().(*SessionData).overallReputation = overallReputation
	fmt.Fprintf(os.Stderr, "%s: %s: reputation: %f\n", timestamp, session, overallReputation)
}

func linkAuthCb(timestamp time.Time, session filter.Session, result string, username string) {
	// reward for authenticating, penalize for failing
	if result != "ok" {
		session.Get().(*SessionData).failedAuth++
	} else {
		session.Get().(*SessionData).hasAuth = true
	}
}

func linkTLSCb(timestamp time.Time, session filter.Session, tlsString string) {
	// reward for starting TLS
	session.Get().(*SessionData).hasStartTLS = true
}

func txResetCb(timestamp time.Time, session filter.Session, messageId string) {
	// penalize if the ratio of reset / commit is too high
	session.Get().(*SessionData).rsetCount += 1
}

func txBeginCb(timestamp time.Time, session filter.Session, messageId string) {
	// reward for starting a transaction
	session.Get().(*SessionData).txBegin += 1
}

func txMailCb(timestamp time.Time, session filter.Session, messageId string, result string, from string) {
	// reward each valid sender and penalize each invalid sender
	// compute a local reputation score for the transaction ... and update the overall reputation (with weight)

	session.Get().(*SessionData).txMailFrom += 1
	if result != "ok" {
		session.Get().(*SessionData).failedMail++
		session.Get().(*SessionData).overallReputation = applyPenalty("mailFrom", session.Get().(*SessionData).overallReputation)
	} else {
		session.Get().(*SessionData).overallReputation = applyReward("mailFrom", session.Get().(*SessionData).overallReputation)
	}
	fmt.Fprintf(os.Stderr, "%s: %s: reputation: %f\n", timestamp, session, session.Get().(*SessionData).overallReputation)
}

func txRcptCb(timestamp time.Time, session filter.Session, messageId string, result string, to string) {
	// reward each valid recipient and penalize each invalid recipient
	session.Get().(*SessionData).txRcptTo += 1
	if result != "ok" {
		session.Get().(*SessionData).failedRcpt++
		session.Get().(*SessionData).overallReputation = applyPenalty("recipient", session.Get().(*SessionData).overallReputation)
	} else {
		session.Get().(*SessionData).overallReputation = applyReward("recipient", session.Get().(*SessionData).overallReputation)
	}
	fmt.Fprintf(os.Stderr, "%s: %s: reputation: %f\n", timestamp, session, session.Get().(*SessionData).overallReputation)
}

func txDataCb(timestamp time.Time, session filter.Session, messageId string, result string) {
	// reward for sending data
	session.Get().(*SessionData).txData += 1
}

func txCommitCb(timestamp time.Time, session filter.Session, messageId string, messageSize int) {
	// reward for successful commit
	session.Get().(*SessionData).txCommit += 1
}

func txRollbackCb(timestamp time.Time, session filter.Session, messageId string) {
	// penalty for rollback
	session.Get().(*SessionData).txRollback += 1
}

func main() {
	reputation = NewReputation()

	filter.Init()

	filter.SMTP_IN.SessionAllocator(func() filter.SessionData {
		return &SessionData{}
	})

	filter.SMTP_IN.OnLinkConnect(linkConnectCb)
	filter.SMTP_IN.OnLinkDisconnect(linkDisconnectCb)
	filter.SMTP_IN.OnLinkIdentify(linkIdentifyCb)
	filter.SMTP_IN.OnLinkAuth(linkAuthCb)
	filter.SMTP_IN.OnLinkTLS(linkTLSCb)
	filter.SMTP_IN.OnTxReset(txResetCb)
	filter.SMTP_IN.OnTxBegin(txBeginCb)
	filter.SMTP_IN.OnTxMail(txMailCb)
	filter.SMTP_IN.OnTxRcpt(txRcptCb)
	filter.SMTP_IN.OnTxData(txDataCb)
	filter.SMTP_IN.OnTxCommit(txCommitCb)
	filter.SMTP_IN.OnTxRollback(txRollbackCb)

	filter.Dispatch()
}
