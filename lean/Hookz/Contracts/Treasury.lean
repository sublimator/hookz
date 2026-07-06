import Hookz.Contracts.Common

namespace Hookz.Contracts.Treasury

open Hookz.Contracts

inductive Action where
  | none
  | withdraw
  | claim
  deriving DecidableEq, Repr

structure Input where
  txKind : TxKind
  amountValid : Bool
  ledgerLimitValid : Bool
  destinationExists : Bool
  action : Action
  withdrawWithinLimit : Bool
  cooldownPassed : Bool
  claimFirstSetup : Bool
  claimDelayPassed : Bool
  deriving DecidableEq, Repr

structure Outcome where
  verdict : Verdict
  emittedCount : Nat
  writesLastRelease : Bool
  deriving DecidableEq, Repr

def reject : Outcome :=
  { verdict := .reject, emittedCount := 0, writesLastRelease := false }

def acceptNoEmit : Outcome :=
  { verdict := .accept, emittedCount := 0, writesLastRelease := false }

def acceptEmit (writesLastRelease : Bool) : Outcome :=
  { verdict := .accept, emittedCount := 1, writesLastRelease := writesLastRelease }

-- @@start model
def expected (input : Input) : Outcome :=
  match input.txKind with
  | .invoke =>
      if !input.amountValid then reject
      else if !input.ledgerLimitValid then reject
      else if !input.destinationExists then reject
      else
        match input.action with
        | .none => reject
        | .withdraw =>
            if !input.withdrawWithinLimit then reject
            else if !input.cooldownPassed then reject
            else acceptEmit true
        | .claim =>
            if input.claimFirstSetup then acceptEmit false
            else if input.claimDelayPassed then acceptEmit false
            else reject
  | .payment => reject
  | .other => reject
-- @@end model

-- @@start theorems
theorem non_invoke_rejects (input : Input)
    (hTx : input.txKind = .payment) :
    expected input = reject := by
  simp [expected, hTx]

theorem missing_or_invalid_amount_rejects (input : Input)
    (hTx : input.txKind = .invoke)
    (hAmount : input.amountValid = false) :
    expected input = reject := by
  simp [expected, hTx, hAmount]

theorem invalid_ledger_limit_rejects (input : Input)
    (hTx : input.txKind = .invoke)
    (hAmount : input.amountValid = true)
    (hLedger : input.ledgerLimitValid = false) :
    expected input = reject := by
  simp [expected, hTx, hAmount, hLedger]

theorem missing_destination_rejects (input : Input)
    (hTx : input.txKind = .invoke)
    (hAmount : input.amountValid = true)
    (hLedger : input.ledgerLimitValid = true)
    (hDest : input.destinationExists = false) :
    expected input = reject := by
  simp [expected, hTx, hAmount, hLedger, hDest]

theorem successful_withdrawal_emits_and_writes_last (input : Input)
    (hTx : input.txKind = .invoke)
    (hAmount : input.amountValid = true)
    (hLedger : input.ledgerLimitValid = true)
    (hDest : input.destinationExists = true)
    (hAction : input.action = .withdraw)
    (hWithin : input.withdrawWithinLimit = true)
    (hCooldown : input.cooldownPassed = true) :
    expected input = acceptEmit true := by
  simp [expected, hTx, hAmount, hLedger, hDest, hAction, hWithin, hCooldown]

theorem withdraw_too_soon_rejects (input : Input)
    (hTx : input.txKind = .invoke)
    (hAmount : input.amountValid = true)
    (hLedger : input.ledgerLimitValid = true)
    (hDest : input.destinationExists = true)
    (hAction : input.action = .withdraw)
    (hWithin : input.withdrawWithinLimit = true)
    (hCooldown : input.cooldownPassed = false) :
    expected input = reject := by
  simp [expected, hTx, hAmount, hLedger, hDest, hAction, hWithin, hCooldown]

theorem first_claim_setup_emits (input : Input)
    (hTx : input.txKind = .invoke)
    (hAmount : input.amountValid = true)
    (hLedger : input.ledgerLimitValid = true)
    (hDest : input.destinationExists = true)
    (hAction : input.action = .claim)
    (hFirst : input.claimFirstSetup = true) :
    expected input = acceptEmit false := by
  simp [expected, hTx, hAmount, hLedger, hDest, hAction, hFirst]
-- @@end theorems

-- @@start pytest-cases
example :
    expected {
      txKind := .payment,
      amountValid := true,
      ledgerLimitValid := true,
      destinationExists := true,
      action := .withdraw,
      withdrawWithinLimit := true,
      cooldownPassed := true,
      claimFirstSetup := false,
      claimDelayPassed := false
    } = reject := by
  native_decide

example :
    expected {
      txKind := .invoke,
      amountValid := false,
      ledgerLimitValid := true,
      destinationExists := true,
      action := .withdraw,
      withdrawWithinLimit := true,
      cooldownPassed := true,
      claimFirstSetup := false,
      claimDelayPassed := false
    } = reject := by
  native_decide

example :
    expected {
      txKind := .invoke,
      amountValid := true,
      ledgerLimitValid := false,
      destinationExists := true,
      action := .withdraw,
      withdrawWithinLimit := true,
      cooldownPassed := true,
      claimFirstSetup := false,
      claimDelayPassed := false
    } = reject := by
  native_decide

example :
    expected {
      txKind := .invoke,
      amountValid := true,
      ledgerLimitValid := true,
      destinationExists := false,
      action := .withdraw,
      withdrawWithinLimit := true,
      cooldownPassed := true,
      claimFirstSetup := false,
      claimDelayPassed := false
    } = reject := by
  native_decide

example :
    expected {
      txKind := .invoke,
      amountValid := true,
      ledgerLimitValid := true,
      destinationExists := true,
      action := .withdraw,
      withdrawWithinLimit := true,
      cooldownPassed := true,
      claimFirstSetup := false,
      claimDelayPassed := false
    } = acceptEmit true := by
  native_decide

example :
    expected {
      txKind := .invoke,
      amountValid := true,
      ledgerLimitValid := true,
      destinationExists := true,
      action := .withdraw,
      withdrawWithinLimit := false,
      cooldownPassed := true,
      claimFirstSetup := false,
      claimDelayPassed := false
    } = reject := by
  native_decide

example :
    expected {
      txKind := .invoke,
      amountValid := true,
      ledgerLimitValid := true,
      destinationExists := true,
      action := .withdraw,
      withdrawWithinLimit := true,
      cooldownPassed := false,
      claimFirstSetup := false,
      claimDelayPassed := false
    } = reject := by
  native_decide

example :
    expected {
      txKind := .invoke,
      amountValid := true,
      ledgerLimitValid := true,
      destinationExists := true,
      action := .none,
      withdrawWithinLimit := true,
      cooldownPassed := true,
      claimFirstSetup := false,
      claimDelayPassed := false
    } = reject := by
  native_decide

example :
    expected {
      txKind := .invoke,
      amountValid := true,
      ledgerLimitValid := true,
      destinationExists := true,
      action := .claim,
      withdrawWithinLimit := true,
      cooldownPassed := true,
      claimFirstSetup := true,
      claimDelayPassed := false
    } = acceptEmit false := by
  native_decide
-- @@end pytest-cases

end Hookz.Contracts.Treasury
