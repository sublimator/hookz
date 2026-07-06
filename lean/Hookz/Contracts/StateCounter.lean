import Hookz.Contracts.Common

namespace Hookz.Contracts.StateCounter

open Hookz.Contracts

structure Input where
  txKind : TxKind
  owner : Bool
  counterState : Option Nat
  counterParam : Option Nat
  deriving DecidableEq, Repr

structure Outcome where
  verdict : Verdict
  counterState : Option Nat
  deriving DecidableEq, Repr

def incrementCounter : Option Nat -> Nat
  | none => 1
  | some n => n + 1

-- @@start model
def expected (input : Input) : Outcome :=
  match input.txKind with
  | .payment =>
      { verdict := .accept, counterState := some (incrementCounter input.counterState) }
  | .invoke =>
      if input.owner then
        match input.counterParam with
        | some n => { verdict := .accept, counterState := some n }
        | none => { verdict := .reject, counterState := input.counterState }
      else
        { verdict := .reject, counterState := input.counterState }
  | .other =>
      { verdict := .accept, counterState := input.counterState }
-- @@end model

-- @@start theorems
theorem first_payment_sets_one (input : Input)
    (hTx : input.txKind = .payment)
    (hState : input.counterState = none) :
    expected input = { verdict := .accept, counterState := some 1 } := by
  simp [expected, hTx, hState, incrementCounter]

theorem payment_increments_existing (input : Input) (n : Nat)
    (hTx : input.txKind = .payment)
    (hState : input.counterState = some n) :
    expected input = { verdict := .accept, counterState := some (n + 1) } := by
  simp [expected, hTx, hState, incrementCounter]

theorem owner_invoke_sets_counter (input : Input) (n : Nat)
    (hTx : input.txKind = .invoke)
    (hOwner : input.owner = true)
    (hParam : input.counterParam = some n) :
    expected input = { verdict := .accept, counterState := some n } := by
  simp [expected, hTx, hOwner, hParam]

theorem non_owner_invoke_rejects (input : Input)
    (hTx : input.txKind = .invoke)
    (hOwner : input.owner = false) :
    (expected input).verdict = .reject := by
  simp [expected, hTx, hOwner]

theorem owner_invoke_without_param_rejects (input : Input)
    (hTx : input.txKind = .invoke)
    (hOwner : input.owner = true)
    (hParam : input.counterParam = none) :
    (expected input).verdict = .reject := by
  simp [expected, hTx, hOwner, hParam]

theorem other_tx_accepts_without_state_change (input : Input)
    (hTx : input.txKind = .other) :
    expected input = { verdict := .accept, counterState := input.counterState } := by
  simp [expected, hTx]
-- @@end theorems

-- @@start pytest-cases
example :
    expected {
      txKind := .payment,
      owner := false,
      counterState := none,
      counterParam := none
    } = { verdict := .accept, counterState := some 1 } := by
  native_decide

example :
    expected {
      txKind := .payment,
      owner := false,
      counterState := some 5,
      counterParam := none
    } = { verdict := .accept, counterState := some 6 } := by
  native_decide

example :
    expected {
      txKind := .invoke,
      owner := true,
      counterState := some 5,
      counterParam := some 42
    } = { verdict := .accept, counterState := some 42 } := by
  native_decide

example :
    (expected {
      txKind := .invoke,
      owner := false,
      counterState := none,
      counterParam := none
    }).verdict = .reject := by
  native_decide

example :
    (expected {
      txKind := .invoke,
      owner := true,
      counterState := none,
      counterParam := none
    }).verdict = .reject := by
  native_decide

example :
    expected {
      txKind := .other,
      owner := false,
      counterState := some 7,
      counterParam := none
    } = { verdict := .accept, counterState := some 7 } := by
  native_decide
-- @@end pytest-cases

end Hookz.Contracts.StateCounter
