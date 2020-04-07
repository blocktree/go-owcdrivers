package codec

var RewardDestination = []string{"Staked", "Stash", "Controller"}
var VoteThreshold = []string{"SuperMajorityApprove", "SuperMajorityAgainst", "SimpleMajority"}
var StorageHasher = []string{"Blake2_128", "Blake2_256", "Twox128", "Twox256", "Twox128Concat"}
var WithdrawReasons = []string{"TransactionPayment", "Transfer", "Reserve", "Fee"}
var Bidder = []string{"NewBidder", "ParaId"}
var Conviction = []string{"None", "Locked1x", "Locked2x", "Locked3x", "Locked4x", "Locked5x"}
var ParachainDispatchOrigin = []string{"Signed", "Parachain"}
var StoredState = []string{"Live", "PendingPause", "Paused", "PendingResume"}
var UncleEntryItem = []string{"InclusionHeight", "Uncle"}
var VoteType = []string{"Binary", "MultiOption"}
var ProposalStage = []string{"PreVoting", "Voting", "Completed"}
var ProposalCategory = []string{"Signaling"}
var VoteStage = []string{"PreVoting", "Commit", "Voting", "Completed"}
var TallyType = []string{"OnePerson", "OneCoin"}
var Role = []string{"Storage"}
var ContentVisibility = []string{"Draft", "Public"}
var LiaisonJudgement = []string{"Pending", "Accepted", "Rejected"}
var DownloadState = []string{"Started", "Ended"}
var EntryMethod = []string{"Paid", "Screening"}
var ProposalStatus = []string{"Active", "Cancelled", "Expired", "Approved", "Rejected", "Slashed"}
var VoteKind = []string{"Abstain", "Approve", "Reject", "Slash"}

func (sb *OffsetBytes) ToRewardDestination() (string, error) {
	return sb.ToEnumValue(RewardDestination)
}

func (sb *OffsetBytes) ToVoteThreshold() (string, error) {
	return sb.ToEnumValue(VoteThreshold)
}

func (sb *OffsetBytes) ToStorageHasher() (string, error) {
	return sb.ToEnumValue(StorageHasher)
}

func (sb *OffsetBytes) ToWithdrawReasons() (string, error) {
	return sb.ToEnumValue(WithdrawReasons)
}

func (sb *OffsetBytes) ToBidder() (string, error) {
	return sb.ToEnumValue(Bidder)
}

func (sb *OffsetBytes) ToConviction() (string, error) {
	return sb.ToEnumValue(Conviction)
}

func (sb *OffsetBytes) ToParachainDispatchOrigin() (string, error) {
	return sb.ToEnumValue(ParachainDispatchOrigin)
}

func (sb *OffsetBytes) ToSoredState() (string, error) {
	return sb.ToEnumValue(StoredState)
}

func (sb *OffsetBytes) ToUncleEntryItem() (string, error) {
	return sb.ToEnumValue(UncleEntryItem)
}

func (sb *OffsetBytes) ToVoteType() (string, error) {
	return sb.ToEnumValue(VoteType)
}

func (sb *OffsetBytes) ToProposalStage() (string, error) {
	return sb.ToEnumValue(ProposalStage)
}

func (sb *OffsetBytes) ToProposalCategory() (string, error) {
	return sb.ToEnumValue(ProposalCategory)
}

func (sb *OffsetBytes) ToVoteStage() (string, error) {
	return sb.ToEnumValue(VoteStage)
}

func (sb *OffsetBytes) ToTallyType() (string, error) {
	return sb.ToEnumValue(TallyType)
}

func (sb *OffsetBytes) ToRole() (string, error) {
	return sb.ToEnumValue(Role)
}

func (sb *OffsetBytes) ToContentVisibility() (string, error) {
	return sb.ToEnumValue(ContentVisibility)
}

func (sb *OffsetBytes) ToLiaisonJudgement() (string, error) {
	return sb.ToEnumValue(LiaisonJudgement)
}

func (sb *OffsetBytes) ToDownloadState() (string, error) {
	return sb.ToEnumValue(DownloadState)
}

func (sb *OffsetBytes) ToEntryMethod() (string, error) {
	return sb.ToEnumValue(EntryMethod)
}

func (sb *OffsetBytes) ToProposalStatus() (string, error) {
	return sb.ToEnumValue(ProposalStatus)
}

func (sb *OffsetBytes) ToVoteKind() (string, error) {
	return sb.ToEnumValue(VoteKind)
}
