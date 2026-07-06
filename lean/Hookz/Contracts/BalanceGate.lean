import Hookz.Contracts.Common

namespace Hookz.Contracts.BalanceGate

open Hookz.Contracts

structure Input where
  outgoing : Bool
  senderBalanceDrops : Option Int
  minBalanceDrops : Int
  deriving DecidableEq, Repr

def defaultMinBalanceDrops : Int := 10000000

-- @@start model
def expected (input : Input) : Verdict :=
  if input.outgoing then
    .accept
  else
    match input.senderBalanceDrops with
    | none => .reject
    | some balance =>
        if balance < input.minBalanceDrops then .reject else .accept
-- @@end model

-- @@start theorems
theorem outgoing_accepts (input : Input) (hOutgoing : input.outgoing = true) :
    expected input = .accept := by
  simp [expected, hOutgoing]

theorem missing_sender_rejects
    (input : Input)
    (hIncoming : input.outgoing = false)
    (hMissing : input.senderBalanceDrops = none) :
    expected input = .reject := by
  simp [expected, hIncoming, hMissing]

theorem below_minimum_rejects
    (input : Input)
    (balance : Int)
    (hIncoming : input.outgoing = false)
    (hBalance : input.senderBalanceDrops = some balance)
    (hBelow : balance < input.minBalanceDrops) :
    expected input = .reject := by
  simp [expected, hIncoming, hBalance, hBelow]

theorem not_below_minimum_accepts
    (input : Input)
    (balance : Int)
    (hIncoming : input.outgoing = false)
    (hBalance : input.senderBalanceDrops = some balance)
    (hNotBelow : ¬ balance < input.minBalanceDrops) :
    expected input = .accept := by
  simp [expected, hIncoming, hBalance, hNotBelow]
-- @@end theorems

-- @@start pytest-cases
example :
    expected {
      outgoing := true,
      senderBalanceDrops := none,
      minBalanceDrops := defaultMinBalanceDrops
    } = .accept := by
  native_decide

example :
    expected {
      outgoing := false,
      senderBalanceDrops := some 50000000,
      minBalanceDrops := defaultMinBalanceDrops
    } = .accept := by
  native_decide

example :
    expected {
      outgoing := false,
      senderBalanceDrops := some 10000000,
      minBalanceDrops := defaultMinBalanceDrops
    } = .accept := by
  native_decide

example :
    expected {
      outgoing := false,
      senderBalanceDrops := some 5000000,
      minBalanceDrops := defaultMinBalanceDrops
    } = .reject := by
  native_decide

example :
    expected {
      outgoing := false,
      senderBalanceDrops := none,
      minBalanceDrops := defaultMinBalanceDrops
    } = .reject := by
  native_decide

example :
    expected {
      outgoing := false,
      senderBalanceDrops := some 50000000,
      minBalanceDrops := 100000000
    } = .reject := by
  native_decide

example :
    expected {
      outgoing := false,
      senderBalanceDrops := some 5000000,
      minBalanceDrops := 1000000
    } = .accept := by
  native_decide
-- @@end pytest-cases

end Hookz.Contracts.BalanceGate
