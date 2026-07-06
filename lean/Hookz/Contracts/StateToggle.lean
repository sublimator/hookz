import Hookz.Contracts.Common

namespace Hookz.Contracts.StateToggle

open Hookz.Contracts

structure Input where
  txKind : TxKind
  owner : Bool
  toggleState : Option Bool
  toggleParam : Option Bool
  deriving DecidableEq, Repr

structure Outcome where
  verdict : Verdict
  toggleState : Option Bool
  deriving DecidableEq, Repr

-- @@start model
def expected (input : Input) : Outcome :=
  match input.txKind with
  | .invoke =>
      if input.owner then
        match input.toggleParam with
        | some enabled => { verdict := .accept, toggleState := some enabled }
        | none => { verdict := .reject, toggleState := input.toggleState }
      else
        { verdict := .reject, toggleState := input.toggleState }
  | .payment =>
      { verdict := .accept, toggleState := input.toggleState }
  | .other =>
      { verdict := .accept, toggleState := input.toggleState }
-- @@end model

-- @@start theorems
theorem owner_invoke_sets_toggle (input : Input) (enabled : Bool)
    (hTx : input.txKind = .invoke)
    (hOwner : input.owner = true)
    (hParam : input.toggleParam = some enabled) :
    expected input = { verdict := .accept, toggleState := some enabled } := by
  simp [expected, hTx, hOwner, hParam]

theorem non_owner_invoke_rejects (input : Input)
    (hTx : input.txKind = .invoke)
    (hOwner : input.owner = false) :
    (expected input).verdict = .reject := by
  simp [expected, hTx, hOwner]

theorem owner_invoke_without_param_rejects (input : Input)
    (hTx : input.txKind = .invoke)
    (hOwner : input.owner = true)
    (hParam : input.toggleParam = none) :
    (expected input).verdict = .reject := by
  simp [expected, hTx, hOwner, hParam]

theorem payment_accepts_without_state_change (input : Input)
    (hTx : input.txKind = .payment) :
    expected input = { verdict := .accept, toggleState := input.toggleState } := by
  simp [expected, hTx]

theorem other_tx_accepts_without_state_change (input : Input)
    (hTx : input.txKind = .other) :
    expected input = { verdict := .accept, toggleState := input.toggleState } := by
  simp [expected, hTx]
-- @@end theorems

-- @@start pytest-cases
example :
    expected {
      txKind := .invoke,
      owner := true,
      toggleState := none,
      toggleParam := some true
    } = { verdict := .accept, toggleState := some true } := by
  native_decide

example :
    expected {
      txKind := .invoke,
      owner := true,
      toggleState := none,
      toggleParam := some false
    } = { verdict := .accept, toggleState := some false } := by
  native_decide

example :
    (expected {
      txKind := .invoke,
      owner := false,
      toggleState := none,
      toggleParam := some true
    }).verdict = .reject := by
  native_decide

example :
    expected {
      txKind := .payment,
      owner := false,
      toggleState := some true,
      toggleParam := none
    } = { verdict := .accept, toggleState := some true } := by
  native_decide

example :
    expected {
      txKind := .payment,
      owner := false,
      toggleState := some false,
      toggleParam := none
    } = { verdict := .accept, toggleState := some false } := by
  native_decide
-- @@end pytest-cases

end Hookz.Contracts.StateToggle
