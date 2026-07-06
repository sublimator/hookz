import Hookz.Contracts.Common

namespace Hookz.Contracts.BasicNative

open Hookz.Contracts

inductive AmountKind where
  | xah
  | iou
  | unknown
  deriving DecidableEq, Repr

structure Input where
  outgoing : Bool
  amountKind : AmountKind
  deriving DecidableEq, Repr

namespace AcceptIncomingXah

-- @@start model
def expected (input : Input) : Verdict :=
  if input.outgoing then
    .accept
  else
    match input.amountKind with
    | .xah => .accept
    | .iou => .reject
    | .unknown => .reject
-- @@end model

-- @@start theorems
theorem outgoing_accepts (input : Input) (hOutgoing : input.outgoing = true) :
    expected input = .accept := by
  simp [expected, hOutgoing]

theorem incoming_xah_accepts (input : Input)
    (hIncoming : input.outgoing = false)
    (hAmount : input.amountKind = .xah) :
    expected input = .accept := by
  simp [expected, hIncoming, hAmount]

theorem incoming_iou_rejects (input : Input)
    (hIncoming : input.outgoing = false)
    (hAmount : input.amountKind = .iou) :
    expected input = .reject := by
  simp [expected, hIncoming, hAmount]
-- @@end theorems

-- @@start pytest-cases
example :
    expected { outgoing := true, amountKind := .unknown } = .accept := by
  native_decide

example :
    expected { outgoing := false, amountKind := .xah } = .accept := by
  native_decide

example :
    expected { outgoing := false, amountKind := .iou } = .reject := by
  native_decide
-- @@end pytest-cases

end AcceptIncomingXah

namespace RejectIncomingXah

-- @@start model
def expected (input : Input) : Verdict :=
  if input.outgoing then
    .reject
  else
    match input.amountKind with
    | .xah => .reject
    | .iou => .accept
    | .unknown => .accept
-- @@end model

-- @@start theorems
theorem outgoing_rejects (input : Input) (hOutgoing : input.outgoing = true) :
    expected input = .reject := by
  simp [expected, hOutgoing]

theorem incoming_xah_rejects (input : Input)
    (hIncoming : input.outgoing = false)
    (hAmount : input.amountKind = .xah) :
    expected input = .reject := by
  simp [expected, hIncoming, hAmount]

theorem incoming_iou_accepts (input : Input)
    (hIncoming : input.outgoing = false)
    (hAmount : input.amountKind = .iou) :
    expected input = .accept := by
  simp [expected, hIncoming, hAmount]
-- @@end theorems

-- @@start pytest-cases
example :
    expected { outgoing := true, amountKind := .unknown } = .reject := by
  native_decide

example :
    expected { outgoing := false, amountKind := .xah } = .reject := by
  native_decide

example :
    expected { outgoing := false, amountKind := .iou } = .accept := by
  native_decide
-- @@end pytest-cases

end RejectIncomingXah

end Hookz.Contracts.BasicNative
