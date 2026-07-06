namespace Hookz.Contracts

inductive Verdict where
  | accept
  | reject
  deriving DecidableEq, Repr

structure ObservedOutcome where
  accepted : Bool
  rejected : Bool
  emittedCount : Nat := 0
  deriving DecidableEq, Repr

inductive TxKind where
  | payment
  | invoke
  | other
  deriving DecidableEq, Repr

def Verdict.toObserved : Verdict -> ObservedOutcome
  | .accept => { accepted := true, rejected := false }
  | .reject => { accepted := false, rejected := true }

def Verdict.matches (expected : Verdict) (observed : ObservedOutcome) : Prop :=
  observed.accepted = expected.toObserved.accepted ∧
    observed.rejected = expected.toObserved.rejected

theorem Verdict.matches_self (expected : Verdict) :
    expected.matches expected.toObserved := by
  cases expected <;> simp [Verdict.matches, Verdict.toObserved]

end Hookz.Contracts
