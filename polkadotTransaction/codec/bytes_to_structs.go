package codec

import (
	"math/big"
)

type KeyValue struct {
	Key   Bytes
	Value Bytes
}

//ToKeyValue ... (Vec<u8>, Vec<u8>)
func (sb *OffsetBytes) ToKeyValue() (res KeyValue, err error) {
	key, err := sb.ToBytes()
	if err != nil {
		return
	}
	value, err := sb.ToBytes()
	if err != nil {
		return
	}
	res.Key = key
	res.Value = value
	return
}

type ValidatorPrefs struct {
	ValidatorPayment Balance
}

//ToValidatorPrefs ... (Compact<Balance>)
func (sb *OffsetBytes) ToValidatorPrefs() (res ValidatorPrefs, err error) {
	value, err := sb.ToBalance()
	if err != nil {
		return
	}

	res.ValidatorPayment = value
	return
}

type ValidatorPrefsLegacy struct {
	UnstakeThreshold U32
	ValidatorPayment Balance
}

//ToValidatorPrefsLegacy ... (Compact<u32>,Compact<Balance>)
func (sb *OffsetBytes) ToValidatorPrefsLegacy() (res ValidatorPrefsLegacy, err error) {
	unstakeThreshold, err := sb.ToCompactUInt32()
	if err != nil {
		return
	}

	validatorPayment, err := sb.ToCompactBalance()
	if err != nil {
		return
	}
	res.UnstakeThreshold = unstakeThreshold
	res.ValidatorPayment = validatorPayment
	return
}

type UnlockChunk struct {
	Value Balance
	Era   EraIndex
}

//ToUnlockChunk ... (Compact<Balance>, Compact<EraIndex>)
func (sb *OffsetBytes) ToUnlockChunk() (res UnlockChunk, err error) {
	value, err := sb.ToCompactBalance()
	if err != nil {
		return
	}
	era, err := sb.ToCompactEraIndex()
	if err != nil {
		return
	}
	res.Value = value
	res.Era = era
	return
}

type StakingLedger struct {
	Stash     AccountId
	Total     Balance
	Active    Balance
	Unlocking []UnlockChunk
}

//ToStakingLedger ... (AccountId, Compact<Balance>, Compact<Balance>, Vec<UnlockChunk<Balance>>)
func (sb *OffsetBytes) ToStakingLedger() (res StakingLedger, err error) {
	stash, err := sb.ToAccountId()
	if err != nil {
		return
	}
	total, err := sb.ToCompactBalance()
	if err != nil {
		return
	}
	active, err := sb.ToCompactBalance()
	if err != nil {
		return
	}
	length, err := sb.ToVecCount()
	if err != nil {
		return
	}
	var counter U32
	for ; counter <= length; counter++ {
		value, verr := sb.ToUnlockChunk()
		if verr != nil {
			err = verr
			return
		}
		res.Unlocking = append(res.Unlocking, value)
	}
	res.Stash = stash
	res.Active = active
	res.Total = total
	return
}

type IndividualExposure struct {
	Who   AccountId
	Value Balance
}

//ToIndividualExposure ... (AccountId, Compact<Balance>)
func (sb *OffsetBytes) ToIndividualExposure() (res IndividualExposure, err error) {
	who, err := sb.ToAccountId()
	if err != nil {
		return
	}
	value, err := sb.ToCompactBalance()
	if err != nil {
		return
	}
	res.Who = who
	res.Value = value
	return
}

type Exposure struct {
	Total  Balance
	Own    Balance
	Others []IndividualExposure
}

//ToExposure ... (Compact<Balance>, Compact<Balance>, Compact<Balance>, Vec<IndividualExposure<AccountId, Balance>>)
func (sb *OffsetBytes) ToExposure() (res Exposure, err error) {
	total, err := sb.ToCompactBalance()
	if err != nil {
		return
	}
	own, err := sb.ToCompactBalance()
	if err != nil {
		return
	}
	length, err := sb.ToVecCount()
	if err != nil {
		return
	}
	var counter U32
	for ; counter <= length; counter++ {
		value, verr := sb.ToIndividualExposure()
		if verr != nil {
			err = verr
			return
		}
		res.Others = append(res.Others, value)
	}
	res.Total = total
	res.Own = own
	return
}

type StoredPendingChange struct {
	ScheduledAt U32
	Forced      U32
}

//ToStoredPendingChange ... (U32, U32)
func (sb *OffsetBytes) ToStoredPendingChange() (res StoredPendingChange, err error) {
	scheduledAt, err := sb.ToUint32()
	if err != nil {
		return
	}
	forced, err := sb.ToUint32()
	if err != nil {
		return
	}
	res.ScheduledAt = scheduledAt
	res.Forced = forced
	return
}

type VestingSchedule struct {
	Offset        Balance
	PerBlock      Balance
	StartingBlock BlockNumber
}

//ToVestingSchedule ... (Balance, Balance, BlockNumber)
func (sb *OffsetBytes) ToVestingSchedule() (res VestingSchedule, err error) {
	offset, err := sb.ToBalance()
	if err != nil {
		return
	}
	perBlock, err := sb.ToBalance()
	if err != nil {
		return
	}
	startingBlock, err := sb.ToBlockNumber()
	if err != nil {
		return
	}
	res.Offset = offset
	res.PerBlock = perBlock
	res.StartingBlock = startingBlock
	return
}

type VoterInfo struct {
	LastActive VoteIndex
	LastWin    VoteIndex
	Pot        Balance
	Stake      Balance
}

//ToVoterInfo ... (VoteIndex, VoteIndex, Balance, Balance)
func (sb *OffsetBytes) ToVoterInfo() (res VoterInfo, err error) {
	lastActive, err := sb.ToVoteIndex()
	if err != nil {
		return
	}
	lastWin, err := sb.ToVoteIndex()
	if err != nil {
		return
	}
	pot, err := sb.ToBalance()
	if err != nil {
		return
	}
	stake, err := sb.ToBalance()
	if err != nil {
		return
	}
	res.LastActive = lastActive
	res.LastWin = lastWin
	res.Pot = pot
	res.Stake = stake
	return
}

type PrefabWasmModule struct {
	ScheduleVersion U32
	Initial         U32
	Maximum         U32
	Code            Bytes
}

//ToPrefabWasmModule ... (Compact<u32>, Compact<u32>, Compact<u32>, Option<Null>, OffsetBytes)
func (sb *OffsetBytes) ToPrefabWasmModule() (res PrefabWasmModule, err error) {
	scheduleVersion, err := sb.ToCompactUInt32()
	if err != nil {
		return
	}
	initial, err := sb.ToCompactUInt32()
	if err != nil {
		return
	}
	maximum, err := sb.ToCompactUInt32()
	if err != nil {
		return
	}
	sb.ToBool() // skipping byte for reserving purposes
	code, err := sb.ToBytes()
	if err != nil {
		return
	}
	res.ScheduleVersion = scheduleVersion
	res.Initial = initial
	res.Maximum = maximum
	res.Code = code
	return
}

type OpaqueNetworkState struct {
	PeerId            OpaquePeerId
	ExternalAddresses OpaqueMultiaddr
}

//ToOpaqueNetworkState ... (OpaquePeerId, Vec<OpaqueMultiaddr>)
func (sb *OffsetBytes) ToOpaqueNetworkState() (res OpaqueNetworkState, err error) {
	peerId, err := sb.ToOpaquePeerId()
	if err != nil {
		return
	}
	externalAddresses, err := sb.ToOpaqueMultiaddr()
	if err != nil {
		return
	}
	res.PeerId = peerId
	res.ExternalAddresses = externalAddresses
	return
}

type Heartbeat struct {
	BlockNumber  BlockNumber
	NetworkState OpaqueNetworkState
	SessionIndex SessionIndex
	AuthorityId  AuthorityId
}

//ToOpaqueNetworkState ... (BlockNumber, OpaqueNetworkState, SessionIndex, AuthorityId)
func (sb *OffsetBytes) ToHeartbeat() (res Heartbeat, err error) {
	blockNumber, err := sb.ToBlockNumber()
	if err != nil {
		return
	}
	networkState, err := sb.ToOpaqueNetworkState()
	if err != nil {
		return
	}
	sessionIndex, err := sb.ToSessionIndex()
	if err != nil {
		return
	}
	authorityId, err := sb.ToAuthorityId()
	if err != nil {
		return
	}
	res.BlockNumber = blockNumber
	res.NetworkState = networkState
	res.SessionIndex = sessionIndex
	res.AuthorityId = authorityId
	return
}

type SessionKeysSubstrate struct {
	Grandpa  AccountId
	Babe     AccountId
	ImOnline AccountId
}

//ToSessionKeysSubstrate ... (AccountId, AccountId, AccountId)
func (sb *OffsetBytes) ToSessionKeysSubstrate() (res SessionKeysSubstrate, err error) {
	grandpa, err := sb.ToAccountId()
	if err != nil {
		return
	}
	babe, err := sb.ToAccountId()
	if err != nil {
		return
	}
	imOnline, err := sb.ToAccountId()
	if err != nil {
		return
	}
	res.Grandpa = grandpa
	res.Babe = babe
	res.ImOnline = imOnline
	return
}

type SessionKeysPolkadot struct {
	Grandpa    AccountId
	Babe       AccountId
	ImOnline   AccountId
	Parachains AccountId
}

//ToSessionKeysPolkadot ... (AccountId, AccountId, AccountId, AccountId)
func (sb *OffsetBytes) ToSessionKeysPolkadot() (res SessionKeysPolkadot, err error) {
	grandpa, err := sb.ToAccountId()
	if err != nil {
		return
	}
	babe, err := sb.ToAccountId()
	if err != nil {
		return
	}
	imOnline, err := sb.ToAccountId()
	if err != nil {
		return
	}
	parachains, err := sb.ToAccountId()
	if err != nil {
		return
	}
	res.Grandpa = grandpa
	res.Babe = babe
	res.ImOnline = imOnline
	res.Parachains = parachains
	return
}

type LegacyKeys struct {
	Grandpa AccountId
	Babe    AccountId
}

//ToLegacyKeys ... (AccountId, AccountId)
func (sb *OffsetBytes) ToLegacyKeys() (res LegacyKeys, err error) {
	grandpa, err := sb.ToAccountId()
	if err != nil {
		return
	}
	babe, err := sb.ToAccountId()
	if err != nil {
		return
	}
	res.Grandpa = grandpa
	res.Babe = babe
	return
}

type EdgewareKeys struct {
	Grandpa AccountId
}

//ToEdgewareKeys ... (AccountId)
func (sb *OffsetBytes) ToEdgewareKeys() (res EdgewareKeys, err error) {
	grandpa, err := sb.ToAccountId()
	if err != nil {
		return
	}
	res.Grandpa = grandpa
	return
}

//TODO: Keys?
type QueuedKeys struct {
	Validator ValidatorId
	Keys      SessionKeysPolkadot
}

//ToQueuedKeys ... (ValidatorId, Keys)
func (sb *OffsetBytes) ToQueuedKeys() (res QueuedKeys, err error) {
	validator, err := sb.ToValidatorId()
	if err != nil {
		return
	}
	keys, err := sb.ToSessionKeysPolkadot()
	if err != nil {
		return
	}
	res.Validator = validator
	res.Keys = keys
	return
}

//ToVecQueuedKeys ... Vec<(ValidatorId, Keys)>
func (sb *OffsetBytes) ToVecQueuedKeys() (res []QueuedKeys, err error) {
	length, err := sb.ToVecCount()
	if err != nil {
		return
	}
	var counter U32
	for ; counter <= length; counter++ {
		value, verr := sb.ToQueuedKeys()
		if verr != nil {
			err = verr
			return
		}
		res = append(res, value)
	}
	return
}

type LegacyQueuedKeys struct {
	Validator ValidatorId
	Keys      LegacyKeys
}

//ToLegacyQueuedKeys ... (ValidatorId, LegacyKeys)
func (sb *OffsetBytes) ToLegacyQueuedKeys() (res LegacyQueuedKeys, err error) {
	validator, err := sb.ToValidatorId()
	if err != nil {
		return
	}
	keys, err := sb.ToLegacyKeys()
	if err != nil {
		return
	}
	res.Validator = validator
	res.Keys = keys
	return
}

type EdgewareQueuedKeys struct {
	Validator ValidatorId
	Keys      EdgewareKeys
}

//ToEdgewareQueuedKeys ... (ValidatorId, EdgewareQueuedKeys)
func (sb *OffsetBytes) ToEdgewareQueuedKeys() (res EdgewareQueuedKeys, err error) {
	validator, err := sb.ToValidatorId()
	if err != nil {
		return
	}
	keys, err := sb.ToEdgewareKeys()
	if err != nil {
		return
	}
	res.Validator = validator
	res.Keys = keys
	return
}

//TODO: Unknown LockIdentifier
type BalanceLock struct {
	Id      string
	Amount  big.Int
	Until   uint64
	Reasons string
}

//TODO: Unknown structures
type OffenceDetails struct {
}
