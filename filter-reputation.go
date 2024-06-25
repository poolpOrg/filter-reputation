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
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/poolpOrg/OpenSMTPD-framework/filter"
)

var ipScoring map[string][]Scoring = make(map[string][]Scoring)
var ipScoringMutex sync.Mutex

func init() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			ipScoringMutex.Lock()
			for ip, scoring := range ipScoring {
				if len(scoring) > 100 {
					ipScoring[ip] = scoring[len(scoring)-100:]
				} else if scoring[len(scoring)-1].Timestamp.Add(5 * 24 * time.Hour).Before(time.Now()) {
					fmt.Fprintf(os.Stderr, "last event over five days ago, deleting scoring for %s\n", ip)
					delete(ipScoring, ip)
				}
			}
			ipScoringMutex.Unlock()
		}
	}()
}

type Scoring struct {
	Timestamp     time.Time
	Score         float64
	AuthFailures  int
	AuthSuccesses int
	Resets        int
	RcptCount     int
	DataCount     int
	CommitCount   int
	RollbackCount int
}

type Transaction struct {
	beginTime time.Time
	endTime   time.Time

	mailFromOK     bool
	rcptToOK       int
	rcptToTempfail int
	rcptToPermfail int

	sawData   bool
	committed bool
}

type SessionData struct {
	skip bool

	connectTime    time.Time
	disconnectTime time.Time

	addr   net.IP
	rdns   bool
	fcrdns bool

	cmdHelo  bool
	cmdEhlo  bool
	heloname string

	cmdAuth  bool
	authok   int
	authfail int

	cmdTLS    bool // pretend smtps is an implicit starttls
	tlsString string

	nResets int

	transactions []*Transaction
}

func scoreTransaction(tx *Transaction) float64 {
	const (
		validSenderWeight         = 0.4
		dataWeight                = 0.3
		commitWeight              = 0.3
		successfulRecipientWeight = 0.1
		failedRecipientPenalty    = 0.2
	)

	baseScore := 0.0

	if tx.mailFromOK {
		baseScore += validSenderWeight
	}
	if tx.sawData {
		baseScore += dataWeight
	}
	if tx.committed {
		baseScore += commitWeight
	}

	// Add points for each successful recipient
	baseScore += float64(tx.rcptToOK) * successfulRecipientWeight

	// Subtract points for each failed recipient
	baseScore -= float64(tx.rcptToTempfail+tx.rcptToPermfail) * failedRecipientPenalty

	// Ensure the score is between 0.0 and 1.0
	score := math.Max(0.0, math.Min(1.0, baseScore))
	return score
}

func scoreSession(session *SessionData) float64 {
	const (
		authSuccessWeight  = 0.1
		authFailurePenalty = 0.1
		tlsWeight          = 0.2
		rdnsWeight         = 0.1
		fcrdnsWeight       = 0.1
		resetPenalty       = 0.05
	)

	baseScore := 0.0

	// Score each transaction
	totalTransactions := len(session.transactions)
	if totalTransactions > 0 {
		transactionScore := 0.0
		for _, tx := range session.transactions {
			transactionScore += scoreTransaction(tx)
		}
		// Normalize transaction score by the number of transactions
		baseScore += transactionScore / float64(totalTransactions)
	}

	// Adjust score for successful authentications
	baseScore += float64(session.authok) * authSuccessWeight

	// Apply penalty for failed authentications
	baseScore -= float64(session.authfail) * authFailurePenalty

	// Add points for TLS
	if session.cmdTLS {
		baseScore += tlsWeight
	}

	// Add points for reverse DNS success
	if session.rdns {
		baseScore += rdnsWeight
	}

	// Add points for FCrDNS validation success
	if session.fcrdns {
		baseScore += fcrdnsWeight
	}

	// Apply penalty for resets
	baseScore -= float64(session.nResets) * resetPenalty

	// Ensure the score is between 0.0 and 1.0
	score := math.Max(0.0, math.Min(1.0, baseScore))

	return score
}

func summarizeSession(session *SessionData) Scoring {
	rcptCount := 0
	dataCount := 0
	commitCount := 0
	rollbackCount := 0

	for _, tx := range session.transactions {
		rcptCount += tx.rcptToOK + tx.rcptToTempfail + tx.rcptToPermfail
		if tx.sawData {
			dataCount++
		}
		if tx.committed {
			commitCount++
		} else {
			rollbackCount++
		}
	}

	return Scoring{
		Timestamp:     time.Now(),
		Score:         scoreSession(session),
		AuthFailures:  session.authfail,
		AuthSuccesses: session.authok,
		Resets:        session.nResets,
		RcptCount:     rcptCount,
		DataCount:     dataCount,
		CommitCount:   commitCount,
		RollbackCount: rollbackCount,
	}
}

func aggregateScoring(scores []Scoring) Scoring {
	if len(scores) == 0 {
		return Scoring{}
	}

	totalScores := len(scores)
	aggregate := Scoring{}

	for _, score := range scores {
		aggregate.Score += score.Score
		aggregate.AuthFailures += score.AuthFailures
		aggregate.AuthSuccesses += score.AuthSuccesses
		aggregate.Resets += score.Resets
		aggregate.RcptCount += score.RcptCount
		aggregate.DataCount += score.DataCount
		aggregate.CommitCount += score.CommitCount
		aggregate.RollbackCount += score.RollbackCount
	}

	// Averaging the score
	aggregate.Score /= float64(totalScores)

	return aggregate
}

func linkConnectCb(timestamp time.Time, session filter.Session, rdns string, fcrdns string, src net.Addr, dest net.Addr) {
	addr, ok := src.(*net.TCPAddr)
	if !ok {
		session.Get().(*SessionData).skip = true
		return
	}

	session.Get().(*SessionData).transactions = make([]*Transaction, 0)
	session.Get().(*SessionData).connectTime = timestamp
	session.Get().(*SessionData).addr = addr.IP
	session.Get().(*SessionData).rdns = rdns != "<unknown>"
	session.Get().(*SessionData).fcrdns = fcrdns == "ok" || fcrdns == "pass"

	var score float64

	ipScoringMutex.Lock()
	scorings, exists := ipScoring[session.Get().(*SessionData).addr.String()]
	ipScoringMutex.Unlock()
	if !exists || len(scorings) < 5 {
		score = 0.5
	} else {
		score = aggregateScoring(scorings).Score
	}
	fmt.Fprintf(os.Stderr, "connect: ip-address=%s score=%.04f\n", addr.IP.String(), score)
}

func linkDisconnectCb(timestamp time.Time, session filter.Session) {
	if session.Get().(*SessionData).skip {
		return
	}
	session.Get().(*SessionData).disconnectTime = timestamp

	ipScoringMutex.Lock()
	ipScoring[session.Get().(*SessionData).addr.String()] = append(ipScoring[session.Get().(*SessionData).addr.String()], summarizeSession(session.Get().(*SessionData)))
	ipScoringMutex.Unlock()

	fmt.Fprintf(os.Stderr, "disconnect: ip-address=%s score=%.04f\n", session.Get().(*SessionData).addr.String(), scoreSession(session.Get().(*SessionData)))
}

func linkIdentifyCb(timestamp time.Time, session filter.Session, method string, hostname string) {
	if session.Get().(*SessionData).skip {
		return
	}
	if method == "HELO" {
		session.Get().(*SessionData).cmdHelo = true
	}
	if method == "EHLO" {
		session.Get().(*SessionData).cmdEhlo = true
	}
	session.Get().(*SessionData).heloname = hostname
}

func linkAuthCb(timestamp time.Time, session filter.Session, result string, username string) {
	if session.Get().(*SessionData).skip {
		return
	}
	session.Get().(*SessionData).cmdAuth = true
	if result == "ok" {
		session.Get().(*SessionData).authok++
	} else {
		session.Get().(*SessionData).authfail++
	}
}

func linkTLSCb(timestamp time.Time, session filter.Session, tlsString string) {
	if session.Get().(*SessionData).skip {
		return
	}
	session.Get().(*SessionData).cmdTLS = true
	session.Get().(*SessionData).tlsString = tlsString
}

func txResetCb(timestamp time.Time, session filter.Session, messageId string) {
	if session.Get().(*SessionData).skip {
		return
	}
	session.Get().(*SessionData).nResets++
}

func txBeginCb(timestamp time.Time, session filter.Session, messageId string) {
	if session.Get().(*SessionData).skip {
		return
	}

	tx := &Transaction{
		beginTime: timestamp,
	}
	session.Get().(*SessionData).transactions = append(session.Get().(*SessionData).transactions, tx)
	fmt.Fprintf(os.Stderr, "txBegin: %s\n", timestamp)
}

func txMailCb(timestamp time.Time, session filter.Session, messageId string, result string, from string) {
	if session.Get().(*SessionData).skip {
		return
	}
	fmt.Fprintf(os.Stderr, "txMail: %s\n", timestamp)
	tx := session.Get().(*SessionData).transactions[len(session.Get().(*SessionData).transactions)-1]
	if result == "ok" {
		tx.mailFromOK = true
	}
}

func txRcptCb(timestamp time.Time, session filter.Session, messageId string, result string, to string) {
	if session.Get().(*SessionData).skip {
		return
	}
	tx := session.Get().(*SessionData).transactions[len(session.Get().(*SessionData).transactions)-1]
	if result == "ok" {
		tx.rcptToOK++
	} else if result == "tempfail" {
		tx.rcptToTempfail++
	} else if result == "permfail" {
		tx.rcptToPermfail++
	}
}

func txDataCb(timestamp time.Time, session filter.Session, messageId string, result string) {
	if session.Get().(*SessionData).skip {
		return
	}
	tx := session.Get().(*SessionData).transactions[len(session.Get().(*SessionData).transactions)-1]
	tx.sawData = true
}

func txCommitCb(timestamp time.Time, session filter.Session, messageId string, messageSize int) {
	if session.Get().(*SessionData).skip {
		return
	}
	tx := session.Get().(*SessionData).transactions[len(session.Get().(*SessionData).transactions)-1]
	tx.endTime = timestamp
	tx.committed = true

	fmt.Fprintf(os.Stderr, "txCommit: score=%.04f\n", scoreTransaction(tx))
}

func txRollbackCb(timestamp time.Time, session filter.Session, messageId string) {
	if session.Get().(*SessionData).skip {
		return
	}
	tx := session.Get().(*SessionData).transactions[len(session.Get().(*SessionData).transactions)-1]
	tx.endTime = timestamp

	fmt.Fprintf(os.Stderr, "txRollback: score=%.04f\n", scoreTransaction(tx))
}

func main() {
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
