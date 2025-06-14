
package ReVer

import (
	"fmt"
	"sync"
	"time" 
	"sort" 

	"github.com/gitferry/bamboo/blockchain"
	"github.com/gitferry/bamboo/config"
	"github.com/gitferry/bamboo/crypto"
	"github.com/gitferry/bamboo/election"
	"github.com/gitferry/bamboo/log"
	"github.com/gitferry/bamboo/node"
	"github.com/gitferry/bamboo/pacemaker"
	"github.com/gitferry/bamboo/types"

)

const (
    FORK = "fork"
    SoftWait = iota
    SoftSyncing
    SoftAlerted
    FallbackVote
)

// 状态
type StateSyncRequest struct {
    NodeID types.Identifier
    View   types.View
}

type StateSyncResponse struct {
    NodeID   types.Identifier
    HighQC   *blockchain.QC
    View     types.View
    Signature []byte
}

type SecurityMetrics struct {
	ForkEvents        []*ForkEvent
	InvalidQCEvents   []*InvalidQCEvent
	VotingRecords     map[types.View][]*VoteRecord
	CommitLatency     map[crypto.Identifier]time.Duration 
	mu                sync.Mutex
}

type ForkEvent struct {
	View          types.View
	ForkDepth     int
}

type InvalidQCEvent struct {
	View       types.View
	Reason     string
}

type VoteRecord struct {
	NodeID   crypto.Identifier
	BlockID  crypto.Identifier
	Voted    bool
}

func NewSecurityMetrics() *SecurityMetrics {
	return &SecurityMetrics{
		ForkEvents:      make([]*ForkEvent, 0),
		InvalidQCEvents: make([]*InvalidQCEvent, 0),
		VotingRecords:   make(map[types.View][]*VoteRecord),
		CommitLatency:   make(map[crypto.Identifier]time.Duration),
	}
}

type ReVer struct {
	node.Node
	election.Election
	pm              *pacemaker.Pacemaker
	lastVotedView   types.View
	preferredView   types.View
	softVoteState    int
    	softVoteTimer    *time.Timer
    	softVoteView     types.View
    	neighborHighQCs  map[types.Identifier]*blockchain.QC
	bc              *blockchain.BlockChain
	committedBlocks chan *blockchain.Block
	forkedBlocks    chan *blockchain.Block
	bufferedQCs     map[crypto.Identifier]*blockchain.QC
	bufferedBlocks  map[types.View]*blockchain.Block
	securityMetrics *SecurityMetrics 
	blockTimestamps map[crypto.Identifier]time.Time
	highQC          *blockchain.QC
	mu              sync.Mutex
	privateKey      crypto.PrivateKey
	lastStateSnapshot types.View 
}

func NewReVer(
	node node.Node,
	pm *pacemaker.Pacemaker,
	elec election.Election,
	committedBlocks chan *blockchain.Block,
	forkedBlocks chan *blockchain.Block) *ReVer {
	
	f := new(ReVer)
	f.Node = node
	f.Election = elec
	f.pm = pm
	f.bc = blockchain.NewBlockchain(config.GetConfig().N())
	f.bufferedBlocks = make(map[types.View]*blockchain.Block)
	f.bufferedQCs = make(map[crypto.Identifier]*blockchain.QC)
	f.highQC = &blockchain.QC{View: 0}
	f.committedBlocks = committedBlocks
	f.forkedBlocks = forkedBlocks
	f.securityMetrics = NewSecurityMetrics()
	f.blockTimestamps = make(map[crypto.Identifier]time.Time)
	f.softVoteState = SoftWait 
	f.privateKey = node.PrivateKey()
	f.softVoteView = 0
	f.neighborHighQCs = nil
	f.lastStateSnapshot = 0
	return f
}

unc (f *ReVer) transitionToState(newState int) {
    f.mu.Lock()
    defer f.mu.Unlock()
    
    log.Infof("[%v] transitioning from %d to %d", f.ID(), f.softVoteState, newState)
    f.softVoteState = newState
    
    switch newState {
    case SoftSyncing:
        f.syncWithNeighbors()
        // 定时器
        f.softVoteTimer = time.AfterFunc(2*time.Second, func() {
            f.transitionToState(SoftAlerted)
        })
        
    case SoftAlerted:
        f.broadcastAlert()
        f.softVoteTimer = time.AfterFunc(1*time.Second, func() {
            f.transitionToState(FallbackVote)
        })
        
    case FallbackVote:
        f.performFallbackVote()
        // 重置
        time.AfterFunc(3*time.Second, func() {
            f.resetSoftVoteState()
        })
    }
}

func (f *ReVer) EnterSoftVoteMode(block *blockchain.Block) {
    log.Infof("[%v] entering soft-vote mode for block view: %v", f.ID(), block.View)
    
    f.mu.Lock()
    f.softVoteView = block.View
    f.neighborHighQCs = make(map[types.Identifier]*blockchain.QC)
    f.mu.Unlock()
    
    f.transitionToState(SoftSyncing)
}

// 重置
func (f *ReVer) resetSoftVoteState() {
    f.mu.Lock()
    defer f.mu.Unlock()
    
    if f.softVoteTimer != nil {
        f.softVoteTimer.Stop()
    }
    
    f.softVoteState = SoftWait
    f.softVoteView = 0
    f.neighborHighQCs = nil
}

func (f *ReVer) broadcastAlert() {
    alert := &SoftVoteAlert{
        NodeID:  f.ID(),
        View:    f.softVoteView,
        State:   SoftAlerted,
    }
    
    alert.Signature = crypto.Sign(f.PrivateKey(), alert.ToBytes())
    for _, nodeID := range f.GetAllNodes() {
        if nodeID != f.ID() {
            f.Send(nodeID, alert)
        }
    }
}

func (f *ReVer) performFallbackVote() {
    // 选择最频繁出现的高QC
    qcCount := make(map[types.Identifier]int)
    var highestQC *blockchain.QC
    
    for _, qc := range f.neighborHighQCs {
        if qc == nil {
            continue
        }
        id := qc.BlockID
        qcCount[id]++
        
        if highestQC == nil || qc.View > highestQC.View || 
           (qc.View == highestQC.View && qcCount[id] > qcCount[highestQC.BlockID]) {
            highestQC = qc
        }
    }
    
    if highestQC != nil {
        log.Infof("[%v] performing fallback vote for QC: %x", f.ID(), highestQC.BlockID)
        f.updateHighQC(highestQC)
        f.pm.AdvanceView(highestQC.View)
    }
}

// 邻居同步
func (f *ReVer) syncWithNeighbors() {
    log.Infof("[%v] starting state sync with neighbors", f.ID())
    
    request := &StateSyncRequest{
        NodeID: f.ID(),
        View:   f.pm.GetCurView(),
    }
    
    for _, neighbor := range f.GetNeighbors() {
        f.Send(neighbor, request)
    }
}

// 状态同步
func (f *ReVer) HandleStateSyncRequest(req *StateSyncRequest) {
    response := &StateSyncResponse{
        NodeID: f.ID(),
        HighQC: f.highQC,
        View:   f.pm.GetCurView(),
    }
    
    response.Signature = crypto.Sign(f.PrivateKey(), response.ToBytes())
    f.Send(req.NodeID, response)
}

func (f *ReVer) HandleStateSyncResponse(resp *StateSyncResponse) {
    valid, err := crypto.PubVerify(resp.Signature, resp.ToBytes(), resp.NodeID)
    if !valid || err != nil {
        log.Warningf("[%v] invalid state sync response signature from %v", f.ID(), resp.NodeID)
        return
    }
    
    f.mu.Lock()
    defer f.mu.Unlock()
    
    if f.softVoteState != SoftSyncing {
        return
    }
    
    if f.neighborHighQCs == nil {
        f.neighborHighQCs = make(map[types.Identifier]*blockchain.QC)
    }
    f.neighborHighQCs[resp.NodeID] = resp.HighQC
    
    if len(f.neighborHighQCs) >= config.QuorumSize()/2 {
        f.analyzeNeighborStates()
    }
}

func (f *ReVer) analyzeNeighborStates() {
    qcViews := make(map[types.View]int)
    var maxView types.View
    
    for _, qc := range f.neighborHighQCs {
        if qc == nil {
            continue
        }
        qcViews[qc.View]++
        if qc.View > maxView {
            maxView = qc.View
        }
    }
    
    // 检查是否有共识
    if qcViews[maxView] > len(f.neighborHighQCs)/2 {
        // 找到对应的QC
        for _, qc := range f.neighborHighQCs {
            if qc != nil && qc.View == maxView {
                log.Infof("[%v] consensus found in neighbor states: view %v", f.ID(), maxView)
                f.updateHighQC(qc)
                f.pm.AdvanceView(maxView)
                f.transitionToState(SoftWait)
                return
            }
        }
    }
    
    log.Infof("[%v] no consensus in neighbor states", f.ID())
}

func (f *ReVer) ProcessPartialQC(pqc *blockchain.PartialQC) error {
    // 验证签名阈值
    if len(pqc.Signers) < config.ThresholdPartial() {
        return fmt.Errorf("insufficient signatures in partial QC")
    }
    
    // 验证签名
    msg := crypto.IDToByte(pqc.BlockID)
    aggPubKey := crypto.AggregatePublicKeys(pqc.Signers)
    if !crypto.VerifyAggSig(pqc.Sig, aggPubKey, msg) {
        return fmt.Errorf("invalid partial QC signature")
    }
    
    f.updateHighQC(&blockchain.QC{
        BlockID: pqc.BlockID,
        View:    pqc.View,
        AggSig:  pqc.Sig,
        Signers: pqc.Signers,
    })
    
    // 部分提交
    f.tryPartialCommit(pqc)
    return nil
}

func (f *ReVer) tryPartialCommit(pqc *blockchain.PartialQC) {
    block, err := f.bc.GetBlockByID(pqc.BlockID)
    if err != nil {
        log.Debugf("[%v] block not found for partial QC: %x", f.ID(), pqc.BlockID)
        return
    }
    
    if pqc.View >= 2 && pqc.View+2 == f.pm.GetCurView() {
        committedBlocks, forkedBlocks, err := f.bc.CommitBlock(block.ID, pqc.View)
        if err != nil {
            log.Warningf("[%v] partial commit failed: %v", f.ID(), err)
            return
        }
        
        for _, cBlock := range committedBlocks {
            f.committedBlocks <- cBlock
        }
        for _, fBlock := range forkedBlocks {
            f.forkedBlocks <- fBlock
            f.RecordFork(1)
        }
    }
}

func (f *ReVer) ProcessBlockWithReVerQC(block *blockchain.Block) error {
	startTime := time.Now()
	defer func() {
		log.Debugf("[%v] processed block %x in %v", f.ID(), block.ID, time.Since(startTime))
	}()
	
	f.blockTimestamps[block.ID] = time.Now()
  
	log.Debugf("[%v] is processing block with ReVer-QC, view: %v, id: %x", f.ID(), block.View, block.ID)
	curView := f.pm.GetCurView()
	if block.Proposer != f.ID() {
		blockIsVerified, _ := crypto.PubVerify(block.Sig, crypto.IDToByte(block.ID), block.Proposer)
		if !blockIsVerified {
			log.Warningf("[%v] received a block with an invalid signature", f.ID())
		}
	}
	if block.View > curView+1 {
		f.bufferedBlocks[block.View-1] = block
		log.Debugf("[%v] the block is buffered, view: %v, current view is: %v, id: %x", f.ID(), block.View, curView, block.ID)
		return nil
	}
	if block.QC != nil {
	        if f.softVoteState != SoftWait {
	            log.Infof("[%v] in soft-vote state (%d), deferring block processing", 
	                f.ID(), f.softVoteState)
	            return nil
	        }

		// ReVer-QC验证
		if !f.VerifyQCContainsSelfSig(block.QC) {
			log.Warningf("[%v] QC does not contain self signature. Entering soft-vote mode.", f.ID())
			f.EnterSoftVoteMode(block)
			return nil
		}
		f.updateHighQC(block.QC)
	} else {
		return fmt.Errorf("the block should contain a QC")
	}
	if block.Proposer != f.ID() {
		f.processCertificate(block.QC)
	}
	curView = f.pm.GetCurView()
	if block.View < curView {
		log.Warningf("[%v] received a stale proposal from %v, block view: %v, current view: %v, block id: %x", f.ID(), block.Proposer, block.View, curView, block.ID)
		return nil
	}
	if !f.Election.IsLeader(block.Proposer, block.View) {
		return fmt.Errorf("received a proposal (%v) from an invalid leader (%v)", block.View, block.Proposer)
	}
	f.bc.AddBlock(block)

	qc := block.QC
	if qc.View >= 2 && qc.View+1 == block.View {
		ok, b, _ := f.commitRule(block)
		if !ok {
			return nil
		}

		committedBlocks, forkedBlocks, err := f.bc.CommitBlock(b.ID, f.pm.GetCurView())
		if err != nil {
			return fmt.Errorf("[%v] cannot commit blocks", f.ID())
		}
		
		// 提交延迟
		for _, cBlock := range committedBlocks {
			if createTime, ok := f.blockTimestamps[cBlock.ID]; ok {
				latency := time.Since(createTime)
				
				f.securityMetrics.mu.Lock()
				f.securityMetrics.CommitLatency[cBlock.ID] = latency
				f.securityMetrics.mu.Unlock()
				
				delete(f.blockTimestamps, cBlock.ID)
			}
			f.committedBlocks <- cBlock
		}
		
		// 分叉事件
		if len(forkedBlocks) > 0 {
			f.RecordFork(len(forkedBlocks))
			for _, fBlock := range forkedBlocks {
				f.forkedBlocks <- fBlock
			}
		}
	}

	qc, ok := f.bufferedQCs[block.ID]
	if ok {
		f.processCertificate(qc)
		delete(f.bufferedQCs, block.ID)
	}

	shouldVote, err := f.votingRule(block)
	if err != nil {
		log.Errorf("cannot decide whether to vote the block, %w", err)
		return err
	}
	
	// 记录投票
	voteRecord := &VoteRecord{
		NodeID:  f.ID(),
		BlockID: block.ID,
		Voted:   shouldVote,
	}
	
	f.securityMetrics.mu.Lock()
	if f.securityMetrics.VotingRecords[block.View] == nil {
		f.securityMetrics.VotingRecords[block.View] = make([]*VoteRecord, 0)
	}
	f.securityMetrics.VotingRecords[block.View] = append(f.securityMetrics.VotingRecords[block.View], voteRecord)
	f.securityMetrics.mu.Unlock()
	
	if !shouldVote {
		log.Debugf("[%v] is not going to vote for block, id: %x", f.ID(), block.ID)
		return nil
	}
	
	vote := blockchain.MakeVote(block.View, f.ID(), block.ID)
	voteAggregator := f.FindLeaderFor(block.View + 1)
  
	if voteAggregator == f.ID() {
		f.ProcessVote(vote)
	} else {
		f.Send(voteAggregator, vote)
	}
	log.Debugf("[%v] vote is sent, id: %x", f.ID(), vote.BlockID)

	b, ok := f.bufferedBlocks[block.View]
	if ok {
		err := f.ProcessBlockWithReVerQC(b)
		return err
	}

	return nil
}

func (f *ReVer) VerifyQCContainsSelfSig(qc *blockchain.QC) bool {
	aggPubKey := crypto.AggregatePublicKeys(qc.Signers)
	myPubKey := crypto.GetPublicKey(f.ID())
	msg := crypto.IDToByte(qc.BlockID)
	aggWithoutMine := crypto.RemovePubKeyFromAgg(aggPubKey, myPubKey)
	if crypto.VerifyAggSig(qc.AggSig, aggWithoutMine, msg) {
		// 无效QC
		event := &InvalidQCEvent{
			View:   f.pm.GetCurView(),
			Reason: "missing_self_signature",
		}
		
		f.securityMetrics.mu.Lock()
		f.securityMetrics.InvalidQCEvents = append(f.securityMetrics.InvalidQCEvents, event)
		f.securityMetrics.mu.Unlock()
		return false
	}
	return true
}

// func (f *ReVer) EnterSoftVoteMode(block *blockchain.Block) {
// 	log.Infof("[%v] entering soft-vote mode for block view: %v", f.ID(), block.View)
// 	f.transitionToState(SoftSyncing)	
// }

func (f *ReVer) FetchLatestQCFromNearby() *blockchain.QC {
	return &blockchain.QC{View: f.pm.GetCurView() - 1}
}

func (f *ReVer) RecordFork(forkDepth int) {
	event := &ForkEvent{
		View:      f.pm.GetCurView(),
		ForkDepth: forkDepth,
	}
	
	f.securityMetrics.mu.Lock()
	f.securityMetrics.ForkEvents = append(f.securityMetrics.ForkEvents, event)
	f.securityMetrics.mu.Unlock()
}

func (sm *SecurityMetrics) ForkProbability() float64 {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	if len(sm.ForkEvents) == 0 {
		return 0.0
	}
	
	// 最大视图数
	maxView := types.View(0)
	for view := range sm.VotingRecords {
		if view > maxView {
			maxView = view
		}
	}
	
	if maxView == 0 {
		return 0.0
	}
	
	uniqueForkViews := make(map[types.View]bool)
	for _, event := range sm.ForkEvents {
		uniqueForkViews[event.View] = true
	}
	
	return float64(len(uniqueForkViews)) / float64(maxView)
}

func (sm *SecurityMetrics) InvalidQCRate() float64 {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	totalQCs := 0
	for _, records := range sm.VotingRecords {
		totalQCs += len(records)
	}
	
	if totalQCs == 0 {
		return 0.0
	}
	return float64(len(sm.InvalidQCEvents)) / float64(totalQCs)
}

func (sm *SecurityMetrics) VotingConsistency(view types.View) float64 {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	records, exists := sm.VotingRecords[view]
	if !exists || len(records) == 0 {
		return 0.0
	}
	
	voteCount := make(map[crypto.Identifier]int)
	for _, record := range records {
		if record.Voted {
			voteCount[record.BlockID]++
		}
	}
	
	maxCount := 0
	for _, count := range voteCount {
		if count > maxCount {
			maxCount = count
		}
	}
	
	return float64(maxCount) / float64(len(records))
}

func (sm *SecurityMetrics) AverageCommitTime() time.Duration {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	if len(sm.CommitLatency) == 0 {
		return 0
	}
	
	total := time.Duration(0)
	count := 0
	for _, latency := range sm.CommitLatency {
		if latency > 0 { 
			total += latency
			count++
		}
	}
	
	if count == 0 {
		return 0
	}
	return total / time.Duration(count)
}

func (f *ReVer) MetricsSummary() map[string]interface{} {
	return map[string]interface{}{
		"fork_probability":   f.securityMetrics.ForkProbability(),
		"invalid_qc_rate":    f.securityMetrics.InvalidQCRate(),
		"avg_commit_time_ms": f.securityMetrics.AverageCommitTime().Milliseconds(),
	}
}

func (f *ReVer) updateHighQC(qc *blockchain.QC) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if qc.View > f.highQC.View {
		f.highQC = qc
	}
}

func (f *ReVer) processCertificate(qc *blockchain.QC) {
	log.Debugf("[%v] is processing a QC, block id: %x", f.ID(), qc.BlockID)
	if qc.View < f.pm.GetCurView() {
		return
	}
	if qc.Leader != f.ID() {
		quorumIsVerified, _ := crypto.VerifyQuorumSignature(qc.AggSig, qc.BlockID, qc.Signers)
		if quorumIsVerified == false {
			log.Warningf("[%v] received a quorum with invalid signatures", f.ID())
			return
		}
	}
	if f.IsByz() && config.GetConfig().Strategy == FORK && f.IsLeader(f.ID(), qc.View+1) {
		f.pm.AdvanceView(qc.View)
		return
	}
	err := f.updatePreferredView(qc)
	if err != nil {
		f.bufferedQCs[qc.BlockID] = qc
		log.Debugf("[%v] a qc is buffered, view: %v, id: %x", f.ID(), qc.View, qc.BlockID)
		return
	}
	f.updateHighQC(qc)
	f.pm.AdvanceView(qc.View)
}

func (f *ReVer) commitRule(block *blockchain.Block) (bool, *blockchain.Block, error) {
	qc := block.QC
	parentBlock, err := f.bc.GetParentBlock(qc.BlockID)
	if err != nil {
		return false, nil, fmt.Errorf("cannot commit any block: %w", err)
	}
	if (parentBlock.View + 1) == qc.View {
		return true, parentBlock, nil
	}
  
	return false, nil, nil
}

func (f *ReVer) votingRule(block *blockchain.Block) (bool, error) {
	if block.View <= 2 {
		return true, nil
	}
	parentBlock, err := f.bc.GetParentBlock(block.ID)
	if err != nil {
		return false, fmt.Errorf("cannot vote for block: %w", err)
	}
	if (block.View <= f.lastVotedView) || (parentBlock.View < f.preferredView) {
		if parentBlock.View < f.preferredView {
			log.Debugf("[%v] parent block view is: %v and preferred view is: %v", f.ID(), parentBlock.View, f.preferredView)
		}
		return false, nil
	}
	return true, nil
}


func (f *ReVer) ProcessVote(vote *blockchain.Vote) {
	log.Debugf("[%v] is processing the vote from %v, block id: %x", f.ID(), vote.Voter, vote.BlockID)
	if f.ID() != vote.Voter {
		voteIsVerified, err := crypto.PubVerify(vote.Signature, crypto.IDToByte(vote.BlockID), vote.Voter)
		if err != nil {
			log.Fatalf("[%v] Error in verifying the signature in vote id: %x", f.ID(), vote.BlockID)
			return
		}
		if !voteIsVerified {
			log.Warningf("[%v] received a vote with unvalid signature. vote id: %x", f.ID(), vote.BlockID)
			return
		}
	}
	isBuilt, qc := f.bc.AddVote(vote)
	if isBuilt {
		qc.Leader = f.ID()
		_, err := f.bc.GetBlockByID(qc.BlockID)
		if err != nil {
			f.bufferedQCs[qc.BlockID] = qc
			return
		}
		f.processCertificate(qc)
	} else {
		// 检查是否达到部分QC阈值
		votes := f.bc.GetVotesForBlock(vote.BlockID)
		if len(votes) >= config.ThresholdPartial() {
			pqc := f.formPartialQC(vote.BlockID, votes)
			f.broadcastPartialQC(pqc)
		}
	}
}

func (f *ReVer) formPartialQC(blockID types.Identifier, votes []*blockchain.Vote) *blockchain.PartialQC {
    signers := make([]types.Identifier, len(votes))
    signatures := make([][]byte, len(votes))
    
    for i, vote := range votes {
        signers[i] = vote.Voter
        signatures[i] = vote.Signature
    }
    
    // 聚合签名
    aggSig := crypto.AggregateSignatures(signatures)
    
    return &blockchain.PartialQC{
        BlockID: blockID,
        View:    votes[0].View,
        Signers: signers,
        Sig:     aggSig,
    }
}

// 广播部分QC
func (f *ReVer) broadcastPartialQC(pqc *blockchain.PartialQC) {
    for _, nodeID := range f.GetAllNodes() {
        if nodeID != f.ID() {
            f.Send(nodeID, pqc)
        }
    }
}
