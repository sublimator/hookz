import Hookz.Contracts.Common

namespace Hookz.Contracts.Reward

open Hookz.Contracts

inductive TxKind where
  | claimReward
  | other
  deriving DecidableEq, Repr

inductive ClaimState where
  | firstClaim
  | hasAccumulator
  deriving DecidableEq, Repr

structure Input where
  txKind : TxKind
  outgoing : Bool
  rewardsEnabled : Bool
  rewardConfigValid : Bool
  claimState : ClaimState
  delayPassed : Bool
  deriving DecidableEq, Repr

structure Outcome where
  verdict : Verdict
  emittedCount : Nat
  deriving DecidableEq, Repr

def reject : Outcome :=
  { verdict := .reject, emittedCount := 0 }

def acceptNoEmit : Outcome :=
  { verdict := .accept, emittedCount := 0 }

def acceptEmit : Outcome :=
  { verdict := .accept, emittedCount := 1 }

-- @@start model
def expected (input : Input) : Outcome :=
  match input.txKind with
  | .other => acceptNoEmit
  | .claimReward =>
      if input.outgoing then acceptNoEmit
      else if !input.rewardsEnabled then reject
      else if !input.rewardConfigValid then reject
      else
        match input.claimState with
        | .firstClaim => acceptNoEmit
        | .hasAccumulator =>
            if input.delayPassed then acceptEmit else reject
-- @@end model

-- @@start theorems
theorem non_claim_accepts (input : Input)
    (hTx : input.txKind = .other) :
    expected input = acceptNoEmit := by
  simp [expected, hTx]

theorem outgoing_accepts (input : Input)
    (hTx : input.txKind = .claimReward)
    (hOutgoing : input.outgoing = true) :
    expected input = acceptNoEmit := by
  simp [expected, hTx, hOutgoing]

theorem rewards_disabled_rejects (input : Input)
    (hTx : input.txKind = .claimReward)
    (hIncoming : input.outgoing = false)
    (hEnabled : input.rewardsEnabled = false) :
    expected input = reject := by
  simp [expected, hTx, hIncoming, hEnabled]

theorem first_claim_accepts_without_emit (input : Input)
    (hTx : input.txKind = .claimReward)
    (hIncoming : input.outgoing = false)
    (hEnabled : input.rewardsEnabled = true)
    (hConfig : input.rewardConfigValid = true)
    (hState : input.claimState = .firstClaim) :
    expected input = acceptNoEmit := by
  simp [expected, hTx, hIncoming, hEnabled, hConfig, hState]

theorem successful_claim_emits (input : Input)
    (hTx : input.txKind = .claimReward)
    (hIncoming : input.outgoing = false)
    (hEnabled : input.rewardsEnabled = true)
    (hConfig : input.rewardConfigValid = true)
    (hState : input.claimState = .hasAccumulator)
    (hDelay : input.delayPassed = true) :
    expected input = acceptEmit := by
  simp [expected, hTx, hIncoming, hEnabled, hConfig, hState, hDelay]

theorem claim_too_soon_rejects (input : Input)
    (hTx : input.txKind = .claimReward)
    (hIncoming : input.outgoing = false)
    (hEnabled : input.rewardsEnabled = true)
    (hConfig : input.rewardConfigValid = true)
    (hState : input.claimState = .hasAccumulator)
    (hDelay : input.delayPassed = false) :
    expected input = reject := by
  simp [expected, hTx, hIncoming, hEnabled, hConfig, hState, hDelay]
-- @@end theorems

-- @@start pytest-cases
example :
    expected {
      txKind := .other,
      outgoing := false,
      rewardsEnabled := true,
      rewardConfigValid := true,
      claimState := .firstClaim,
      delayPassed := false
    } = acceptNoEmit := by
  native_decide

example :
    expected {
      txKind := .claimReward,
      outgoing := true,
      rewardsEnabled := true,
      rewardConfigValid := true,
      claimState := .firstClaim,
      delayPassed := false
    } = acceptNoEmit := by
  native_decide

example :
    expected {
      txKind := .claimReward,
      outgoing := false,
      rewardsEnabled := false,
      rewardConfigValid := true,
      claimState := .hasAccumulator,
      delayPassed := true
    } = reject := by
  native_decide

example :
    expected {
      txKind := .claimReward,
      outgoing := false,
      rewardsEnabled := true,
      rewardConfigValid := true,
      claimState := .firstClaim,
      delayPassed := false
    } = acceptNoEmit := by
  native_decide

example :
    expected {
      txKind := .claimReward,
      outgoing := false,
      rewardsEnabled := true,
      rewardConfigValid := true,
      claimState := .hasAccumulator,
      delayPassed := true
    } = acceptEmit := by
  native_decide

example :
    expected {
      txKind := .claimReward,
      outgoing := false,
      rewardsEnabled := true,
      rewardConfigValid := true,
      claimState := .hasAccumulator,
      delayPassed := false
    } = reject := by
  native_decide
-- @@end pytest-cases

end Hookz.Contracts.Reward
