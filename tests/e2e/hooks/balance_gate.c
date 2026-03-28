/**
 * balance_gate.c — Reject payments from accounts below a minimum XAH balance.
 *
 * Exercises: util_keylet, slot_set, slot_subfield, slot_float, float_compare
 *
 * The minimum balance (in drops) is read from hook parameter "MIN_BAL".
 * If not set, defaults to 10,000,000 drops (10 XAH).
 */
#include <stdint.h>
#include "hookapi.h"

#define DONE(msg) accept(msg, sizeof(msg), 0)
#define NOPE(msg) rollback(msg, sizeof(msg), __LINE__)

int64_t hook(uint32_t reserved)
{
    _g(1, 1);

    // Pass outgoing transactions
    uint8_t hook_acc[20];
    hook_account(SBUF(hook_acc));

    uint8_t otxn_acc[20];
    otxn_field(SBUF(otxn_acc), sfAccount);

    int equal = 0;
    for (int i = 0; GUARD(20), i < 20; ++i)
        if (hook_acc[i] != otxn_acc[i])
        {
            equal = 0;
            break;
        }
        else
            equal = 1;

    if (equal)
        DONE("balance_gate: outgoing — pass.");

    // Read minimum balance from parameter (default 10 XAH = 10M drops)
    int64_t min_balance = float_set(-6, 10); // 10 * 10^-6 ... no wait
    // Actually: 10 XAH = 10,000,000 drops. In XFL that's float_set(0, 10000000)
    // But hooks work in drops for XAH. Let's use float_set(7, 1) = 10,000,000
    min_balance = float_set(7, 1); // 1 * 10^7 = 10,000,000

    uint8_t min_buf[8];
    if (hook_param(SBUF(min_buf), "MIN_BAL", 7) == 8)
    {
        // Parameter is an 8-byte XFL
        min_balance = *((int64_t*)min_buf);
    }

    // Look up sender's AccountRoot
    uint8_t kl[34];
    if (util_keylet(SBUF(kl), KEYLET_ACCOUNT, SBUF(otxn_acc), 0, 0, 0, 0) != 34)
        NOPE("balance_gate: keylet failed.");

    if (slot_set(SBUF(kl), 1) != 1)
        NOPE("balance_gate: could not load account.");

    // Navigate to Balance field
    if (slot_subfield(1, sfBalance, 2) != 2)
        NOPE("balance_gate: no balance field.");

    // Read balance as XFL
    int64_t balance = slot_float(2);
    if (balance < 0)
        NOPE("balance_gate: could not read balance.");

    trace_float((uint32_t)"bal", 3, balance);
    trace_float((uint32_t)"min", 3, min_balance);

    // Compare: balance >= min_balance
    if (float_compare(balance, min_balance, COMPARE_LESS))
        NOPE("balance_gate: sender balance too low.");

    DONE("balance_gate: pass.");
}

int64_t cbak(uint32_t reserved)
{
    return 0;
}
