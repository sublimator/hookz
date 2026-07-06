import Hookz.Contracts.Common

namespace Hookz.Contracts.Mint

open Hookz.Contracts

structure Input where
  hasBlob : Bool
  deriving DecidableEq, Repr

structure Outcome where
  verdict : Verdict
  emittedCount : Nat
  deriving DecidableEq, Repr

-- @@start model
def expected (input : Input) : Outcome :=
  if input.hasBlob then
    { verdict := .accept, emittedCount := 1 }
  else
    { verdict := .reject, emittedCount := 0 }
-- @@end model

-- @@start theorems
theorem missing_blob_rejects (input : Input) (hBlob : input.hasBlob = false) :
    expected input = { verdict := .reject, emittedCount := 0 } := by
  simp [expected, hBlob]

theorem blob_emits_one (input : Input) (hBlob : input.hasBlob = true) :
    expected input = { verdict := .accept, emittedCount := 1 } := by
  simp [expected, hBlob]
-- @@end theorems

-- @@start pytest-cases
example :
    expected { hasBlob := false } = { verdict := .reject, emittedCount := 0 } := by
  native_decide

example :
    expected { hasBlob := true } = { verdict := .accept, emittedCount := 1 } := by
  native_decide
-- @@end pytest-cases

end Hookz.Contracts.Mint
