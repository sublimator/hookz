import Hookz.Contracts.Common

namespace Hookz.Contracts.MultiInvokeEmit

open Hookz.Contracts

inductive ConfigAction where
  | noParams
  | reset
  | setDestinations (dst1 dst2 dst3 : Bool)
  deriving DecidableEq, Repr

structure Input where
  txKind : TxKind
  owner : Bool
  destinations : List Bool
  configAction : ConfigAction
  deriving DecidableEq, Repr

structure Outcome where
  verdict : Verdict
  destinations : List Bool
  emittedCount : Nat
  deriving DecidableEq, Repr

def countEnabled : List Bool -> Nat
  | [] => 0
  | enabled :: rest =>
      if enabled then 1 + countEnabled rest else countEnabled rest

def actionDestinations : ConfigAction -> Option (List Bool)
  | .noParams => none
  | .reset => some []
  | .setDestinations dst1 dst2 dst3 => some [dst1, dst2, dst3]

-- @@start model
def expected (input : Input) : Outcome :=
  match input.txKind with
  | .invoke =>
      if input.owner then
        match actionDestinations input.configAction with
        | none =>
            { verdict := .reject, destinations := input.destinations, emittedCount := 0 }
        | some destinations =>
            { verdict := .accept, destinations := destinations, emittedCount := 0 }
      else
        { verdict := .reject, destinations := input.destinations, emittedCount := 0 }
  | .payment =>
      let emitted := countEnabled input.destinations
      if emitted = 0 then
        { verdict := .reject, destinations := input.destinations, emittedCount := 0 }
      else
        { verdict := .accept, destinations := input.destinations, emittedCount := emitted }
  | .other =>
      { verdict := .accept, destinations := input.destinations, emittedCount := 0 }
-- @@end model

-- @@start theorems
theorem owner_reset_clears_destinations (input : Input)
    (hTx : input.txKind = .invoke)
    (hOwner : input.owner = true)
    (hAction : input.configAction = .reset) :
    expected input = { verdict := .accept, destinations := [], emittedCount := 0 } := by
  simp [expected, hTx, hOwner, hAction, actionDestinations]

theorem owner_no_params_rejects (input : Input)
    (hTx : input.txKind = .invoke)
    (hOwner : input.owner = true)
    (hAction : input.configAction = .noParams) :
    (expected input).verdict = .reject := by
  simp [expected, hTx, hOwner, hAction, actionDestinations]

theorem non_owner_invoke_rejects (input : Input)
    (hTx : input.txKind = .invoke)
    (hOwner : input.owner = false) :
    (expected input).verdict = .reject := by
  simp [expected, hTx, hOwner]

theorem payment_without_destinations_rejects (input : Input)
    (hTx : input.txKind = .payment)
    (hEmpty : countEnabled input.destinations = 0) :
    (expected input).verdict = .reject := by
  simp [expected, hTx, hEmpty]

theorem payment_emits_enabled_destinations (input : Input) (n : Nat)
    (hTx : input.txKind = .payment)
    (hCount : countEnabled input.destinations = n)
    (hNonzero : ¬ n = 0) :
    expected input =
      { verdict := .accept, destinations := input.destinations, emittedCount := n } := by
  simp [expected, hTx, hCount, hNonzero]

theorem other_tx_accepts_without_emit (input : Input)
    (hTx : input.txKind = .other) :
    expected input =
      { verdict := .accept, destinations := input.destinations, emittedCount := 0 } := by
  simp [expected, hTx]
-- @@end theorems

-- @@start pytest-cases
example :
    expected {
      txKind := .invoke,
      owner := true,
      destinations := [],
      configAction := .setDestinations true false false
    } = { verdict := .accept, destinations := [true, false, false], emittedCount := 0 } := by
  native_decide

example :
    expected {
      txKind := .invoke,
      owner := true,
      destinations := [true, true, true],
      configAction := .reset
    } = { verdict := .accept, destinations := [], emittedCount := 0 } := by
  native_decide

example :
    (expected {
      txKind := .invoke,
      owner := false,
      destinations := [],
      configAction := .setDestinations true false false
    }).verdict = .reject := by
  native_decide

example :
    (expected {
      txKind := .invoke,
      owner := true,
      destinations := [],
      configAction := .noParams
    }).verdict = .reject := by
  native_decide

example :
    expected {
      txKind := .payment,
      owner := false,
      destinations := [true, false, false],
      configAction := .noParams
    } = { verdict := .accept, destinations := [true, false, false], emittedCount := 1 } := by
  native_decide

example :
    expected {
      txKind := .payment,
      owner := false,
      destinations := [true, true, true],
      configAction := .noParams
    } = { verdict := .accept, destinations := [true, true, true], emittedCount := 3 } := by
  native_decide

example :
    expected {
      txKind := .payment,
      owner := false,
      destinations := [true, false, true],
      configAction := .noParams
    } = { verdict := .accept, destinations := [true, false, true], emittedCount := 2 } := by
  native_decide

example :
    (expected {
      txKind := .payment,
      owner := false,
      destinations := [],
      configAction := .noParams
    }).verdict = .reject := by
  native_decide

example :
    expected {
      txKind := .other,
      owner := false,
      destinations := [true],
      configAction := .noParams
    } = { verdict := .accept, destinations := [true], emittedCount := 0 } := by
  native_decide
-- @@end pytest-cases

end Hookz.Contracts.MultiInvokeEmit
