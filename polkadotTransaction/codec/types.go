package codec

import (
	"encoding/binary"
	"math/big"
	"time"
)

type H256 string
type AccountId H256
type AuthorityId H256
type AttestedCandidate H256
type ContentId H256
type Hash H256
type SessionKey H256
type ValidatorId H256

type Reporter AccountId

type U8 uint8
type Vote U8
type LockPeriods U8

type U32 uint32
type AccountIndex U32
type ApprovalFlag U32
type EraIndex U32
type ParaId U32
type Permill U32
type PropIndex U32
type ProposalIndex U32
type ReferendumIndex U32
type SessionIndex uint32
type SetIndex U32
type VoteIndex U32

type U64 uint64
type AuthorityWeight U64
type BlockNumber U64
type CategoryId U64
type DataObjectTypeId U64
type DataObjectStorageRelationshipId U64
type DownloadSessionid U64
type Gas U64
type Index U64
type LiabilityIndex U64
type MemberId U64
type Moment U64
type PaidTermId U64
type PostId U64
type SchemaId U64
type SubscriptionId U64
type ThreadId uint64

type U128 big.Int
type Balance U128
type BalanceOf Balance

type Bytes []U8
type Attestation Bytes
type HeadData Bytes
type IdentityType Bytes
type Identity Bytes
type IPNSIdentity Bytes
type Key Bytes
type Url Bytes
type OpaquePeerId Bytes
type OpaqueMultiaddr Bytes
type ProposalContents Bytes
type ProposalTitle Bytes

type NewAccountOutcome U32

func (sb *OffsetBytes) ToAccountId() (res AccountId, err error) {
	v, err := sb.ToH256()
	if err != nil {
		return
	}
	res = AccountId(v)
	return
}

func (sb *OffsetBytes) ToAuthorityId() (res AuthorityId, err error) {
	v, err := sb.ToH256()
	if err != nil {
		return
	}
	res = AuthorityId(v)
	return
}

func (sb *OffsetBytes) ToAttestedCandidate() (res AttestedCandidate, err error) {
	v, err := sb.ToH256()
	if err != nil {
		return
	}
	res = AttestedCandidate(v)
	return
}

func (sb *OffsetBytes) ToContentId() (res ContentId, err error) {
	v, err := sb.ToH256()
	if err != nil {
		return
	}
	res = ContentId(v)
	return
}

func (sb *OffsetBytes) ToHash() (res Hash, err error) {
	v, err := sb.ToH256()
	if err != nil {
		return
	}
	res = Hash(v)
	return
}

func (sb *OffsetBytes) ToReporter() (res Reporter, err error) {
	v, err := sb.ToAccountId()
	if err != nil {
		return
	}
	res = Reporter(v)
	return
}

func (sb *OffsetBytes) ToSessionKey() (res SessionKey, err error) {
	v, err := sb.ToH256()
	if err != nil {
		return
	}
	res = SessionKey(v)
	return
}

func (sb *OffsetBytes) ToValidatorId() (res ValidatorId, err error) {
	v, err := sb.ToH256()
	if err != nil {
		return
	}
	res = ValidatorId(v)
	return
}

func (sb *OffsetBytes) ToUint8() (res U8, err error) {
	v, err := sb.GetNextByte()
	if err != nil {
		return
	}
	res = U8(v)
	return
}

func (sb *OffsetBytes) ToVote() (res Vote, err error) {
	v, err := sb.ToUint8()
	if err != nil {
		return
	}
	res = Vote(v)
	return
}

func (sb *OffsetBytes) ToLockPeriods() (res LockPeriods, err error) {
	v, err := sb.ToUint8()
	if err != nil {
		return
	}
	res = LockPeriods(v)
	return
}

func (sb *OffsetBytes) ToUint32() (res U32, err error) {
	bytes, err := sb.GetNextBytes(4)
	if err != nil {
		return
	}
	bytes = ExtendLEBytes(bytes, 4)
	v := binary.LittleEndian.Uint32(bytes)
	res = U32(v)
	return
}

func (sb *OffsetBytes) ToAccountIndex() (res AccountIndex, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = AccountIndex(v)
	return
}

func (sb *OffsetBytes) ToApprovalFlag() (res ApprovalFlag, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = ApprovalFlag(v)
	return
}

func (sb *OffsetBytes) ToEraIndex() (res EraIndex, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = EraIndex(v)
	return
}

func (sb *OffsetBytes) ToCompactEraIndex() (res EraIndex, err error) {
	v, err := sb.ToCompactUInt32()
	if err != nil {
		return
	}
	res = EraIndex(v)
	return
}

func (sb *OffsetBytes) ToParaId() (res ParaId, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = ParaId(v)
	return
}

func (sb *OffsetBytes) ToPermill() (res Permill, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = Permill(v)
	return
}

func (sb *OffsetBytes) ToPropIndex() (res PropIndex, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = PropIndex(v)
	return
}

func (sb *OffsetBytes) ToProposalIndex() (res ProposalIndex, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = ProposalIndex(v)
	return
}

func (sb *OffsetBytes) ToReferendumIndex() (res ReferendumIndex, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = ReferendumIndex(v)
	return
}

func (sb *OffsetBytes) ToSessionIndex() (res SessionIndex, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = SessionIndex(v)
	return
}

func (sb *OffsetBytes) ToSetIndex() (res SetIndex, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = SetIndex(v)
	return
}

func (sb *OffsetBytes) ToVoteIndex() (res VoteIndex, err error) {
	v, err := sb.ToUint32()
	if err != nil {
		return
	}
	res = VoteIndex(v)
	return
}

func (sb *OffsetBytes) ToUint64() (res U64, err error) {
	bytes, err := sb.GetNextBytes(8)
	if err != nil {
		return
	}
	bytes = ExtendLEBytes(bytes, 8)
	v := binary.LittleEndian.Uint64(bytes)
	res = U64(v)
	return
}

func (sb *OffsetBytes) ToAuthorityWeight() (res AuthorityWeight, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = AuthorityWeight(v)
	return
}

func (sb *OffsetBytes) ToBlockNumber() (res BlockNumber, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = BlockNumber(v)
	return
}

func (sb *OffsetBytes) ToCategoryId() (res CategoryId, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = CategoryId(v)
	return
}

func (sb *OffsetBytes) ToDataObjectTypeId() (res DataObjectTypeId, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = DataObjectTypeId(v)
	return
}

func (sb *OffsetBytes) ToDataObjectStorageRelationshipId() (res DataObjectStorageRelationshipId, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = DataObjectStorageRelationshipId(v)
	return
}

func (sb *OffsetBytes) ToDownloadSessionid() (res DownloadSessionid, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = DownloadSessionid(v)
	return
}

func (sb *OffsetBytes) ToGas() (res Gas, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = Gas(v)
	return
}

func (sb *OffsetBytes) ToIndex() (res Index, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = Index(v)
	return
}

func (sb *OffsetBytes) ToLiabilityIndex() (res LiabilityIndex, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = LiabilityIndex(v)
	return
}

func (sb *OffsetBytes) ToMemberId() (res MemberId, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = MemberId(v)
	return
}

func (sb *OffsetBytes) ToMoment() (res Moment, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = Moment(v)
	return
}

func (sb *OffsetBytes) ToCompactMoment() (res time.Time, err error) {
	bytes, err := sb.FromCompact()
	if err != nil {
		return
	}
	intValue, err := bytes.ToMoment()
	if err != nil {
		return
	}
	res = time.Unix(int64(intValue), 0)
	return
}

func (sb *OffsetBytes) ToPaidTermId() (res PaidTermId, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = PaidTermId(v)
	return
}

func (sb *OffsetBytes) ToPostId() (res PostId, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = PostId(v)
	return
}

func (sb *OffsetBytes) ToSchemaId() (res SchemaId, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = SchemaId(v)
	return
}

func (sb *OffsetBytes) ToSubscriptionId() (res SubscriptionId, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = SubscriptionId(v)
	return
}

func (sb *OffsetBytes) ToThreadId() (res ThreadId, err error) {
	v, err := sb.ToUint64()
	if err != nil {
		return
	}
	res = ThreadId(v)
	return
}

func (sb *OffsetBytes) ToUint128() (res U128, err error) {
	bytes, err := sb.GetNextBytes(16)
	bytes = RevertBytes(bytes)
	bytes = ExtendLEBytes(bytes, 16)
	var v big.Int
	v.SetBytes(bytes)
	res = U128(v)
	return
}

func (sb *OffsetBytes) ToCompactBalance() (res Balance, err error) {
	v, err := sb.ToCompactUint128()
	if err != nil {
		return
	}
	res = Balance(v)
	return
}

func (sb *OffsetBytes) ToBalance() (res Balance, err error) {
	v, err := sb.ToUint128()
	if err != nil {
		return
	}
	res = Balance(v)
	return
}

func (sb *OffsetBytes) ToBalanceOf() (res BalanceOf, err error) {
	v, err := sb.ToUint128()
	if err != nil {
		return
	}
	res = BalanceOf(v)
	return
}

//ToVecUint8ByLength ...
func (sb *OffsetBytes) ToVecUint8ByLength(length U32) (res Bytes, err error) {
	var counter U32
	for ; counter <= length; counter++ {
		value, verr := sb.ToUint8()
		if verr != nil {
			err = verr
			return
		}
		res = append(res, value)
	}
	return
}

//ToBytes ... <Vec<u8>> i.e. OffsetBytes
func (sb *OffsetBytes) ToBytes() (res Bytes, err error) {
	length, err := sb.ToVecCount()
	if err != nil {
		return
	}
	res, err = sb.ToVecUint8ByLength(length)
	return
}

func (sb *OffsetBytes) ToAttestation() (res Attestation, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = Attestation(v)
	return
}

func (sb *OffsetBytes) ToHeadData() (res HeadData, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = HeadData(v)
	return
}

func (sb *OffsetBytes) ToIdentityType() (res IdentityType, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = IdentityType(v)
	return
}

func (sb *OffsetBytes) ToIdentity() (res Identity, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = Identity(v)
	return
}

func (sb *OffsetBytes) ToIPNSIdentity() (res IPNSIdentity, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = IPNSIdentity(v)
	return
}

func (sb *OffsetBytes) ToKey() (res Key, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = Key(v)
	return
}

func (sb *OffsetBytes) ToUrl() (res Url, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = Url(v)
	return
}

func (sb *OffsetBytes) ToOpaquePeerId() (res OpaquePeerId, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = OpaquePeerId(v)
	return
}

func (sb *OffsetBytes) ToOpaqueMultiaddr() (res OpaqueMultiaddr, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = OpaqueMultiaddr(v)
	return
}

func (sb *OffsetBytes) ToProposalContents() (res ProposalContents, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = ProposalContents(v)
	return
}

func (sb *OffsetBytes) ToProposalTitle() (res ProposalTitle, err error) {
	v, err := sb.ToBytes()
	if err != nil {
		return
	}
	res = ProposalTitle(v)
	return
}

func (sb *OffsetBytes) ToNewAccountOutcome() (res NewAccountOutcome, err error) {
	v, err := sb.ToCompactUInt32()
	if err != nil {
		return
	}
	res = NewAccountOutcome(v)
	return
}
