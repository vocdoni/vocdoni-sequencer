package storage

import "github.com/vocdoni/vocdoni-z-sandbox/util"

func (s *Storage) PushBallot(b *Ballot) error {
	if err := s.setArtifact(ballotPrefix, b.Nullifier, b); err != nil {
		return err
	}

	return nil
}

// NextBallot returns the next ballot to be processed.
// It returns ErrNoMoreElements if there are no more ballots.
func (s *Storage) NextBallot() (*Ballot, error) {
	s.ballotLock.Lock()
	defer s.ballotLock.Unlock()
	artifact, err := s.getAndDeleteNextArtifact(ballotPrefix, nil)
	if err != nil {
		return nil, err
	}
	if artifact == nil {
		return nil, ErrNotFound
	}
	b, ok := artifact.(*Ballot)
	if !ok {
		panic("unexpected artifact type")
	}
	s.setArtifact(ballotProcessingPrefix, b.Nullifier, b)
	return b, nil
}

// PushVerifiedBallot marks a ballot as processed and stores the verified ballot in the storage.
func (s *Storage) PushVerifiedBallot(v *VerifiedBallot) error {
	if err := s.deleteArtifact(ballotProcessingPrefix, v.Nullifier); err != nil {
		return err
	}

	if err := s.setArtifact(verifiedBallotPrefix, append(v.ProcessID, v.Nullifier...), v); err != nil {
		return err
	}
	return nil
}

// NextVerifiedBallot returns the next verified ballot to be processed.
func (s *Storage) NextVerifiedBallot(processID []byte) (*VerifiedBallot, error) {
	s.ballotLock.Lock()
	defer s.ballotLock.Unlock()
	artifact, err := s.getAndDeleteNextArtifact(verifiedBallotPrefix, processID)
	if err != nil {
		return nil, err
	}
	if artifact == nil {
		return nil, ErrNotFound
	}
	v, ok := artifact.(*VerifiedBallot)
	if !ok {
		panic("unexpected artifact type")
	}
	if err := s.setArtifact(verifiedBallotProcessingPrefix, append(processID, v.Nullifier...), v); err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Storage) PushAggregatedBallotBatch(abb *AggregatedBallotBatch) error {
	r := util.RandomBytes(8)
	return s.setArtifact(aggrPrefix, append(abb.ProcessID, r...), abb)
}

func (s *Storage) NextAggregatedBallotBatch(processID []byte) (*AggregatedBallotBatch, []byte, error) {
	artifact, err := s.getAndDeleteNextArtifact(aggrPrefix, processID)
	if err != nil {
		return nil, nil, err
	}
	if artifact == nil {
		return nil, nil, ErrNotFound
	}
	abb, ok := artifact.(*AggregatedBallotBatch)
	if !ok {
		panic("unexpected artifact type")
	}
	r := util.RandomBytes(8)
	if err := s.setArtifact(aggrProcessingPrefix, append(abb.ProcessID, r...), abb); err != nil {
		return nil, nil, err
	}
	return abb, append(abb.ProcessID, r...), nil
}

func (s *Storage) CleanAggregatedBallotBatch(id []byte) error {
	return s.deleteArtifact(aggrProcessingPrefix, id)
}
