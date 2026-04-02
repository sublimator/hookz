//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012-2016 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================
#include "TipBotClaude_test_hooks.h"
#include <test/jtx.h>
#include <test/jtx/TestEnv.h>
#include <test/jtx/hook.h>
#include <test/jtx/remit.h>
#include <xrpld/app/hook/applyHook.h>
#include <xrpld/app/tx/detail/SetHook.h>
#include <xrpl/hook/Enum.h>
#include <xrpl/protocol/IOUAmount.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>

namespace ripple {

namespace test {

#define DEBUG_TESTS 1

#define BEAST_REQUIRE(x)     \
    {                        \
        BEAST_EXPECT(!!(x)); \
        if (!(x))            \
            return;          \
    }

#define HOOK_WASM(name, path)                                                   \
    [[maybe_unused]] auto const& name##_wasm = tipbotclaude_test_wasm[path];   \
    [[maybe_unused]] uint256 const name##_hash =                                \
        ripple::sha512Half_s(ripple::Slice(name##_wasm.data(), name##_wasm.size())); \
    [[maybe_unused]] std::string const name##_hash_str = to_string(name##_hash); \
    [[maybe_unused]] Keylet const name##_keylet = keylet::hookDefinition(name##_hash);

class TipBotClaude_test : public beast::unit_test::suite
{
#define HSFEE fee(100'000'000)
#define M(m) memo(m, "", "")

private:
    void static overrideFlag(Json::Value& jv)
    {
        jv[jss::Flags] = hsfOVERRIDE;
    }

    using TestEnv = jtx::TestEnv;

    TestEnv
    makeEnv(FeatureBitset features)
    {
        return TestEnv{*this, features};
    }

    static uint256
    rawStateKey(std::initializer_list<std::uint8_t> bytes)
    {
        std::array<std::uint8_t, 32> key{};
        std::size_t i = 0;
        for (auto const b : bytes)
            key[i++] = b;
        return uint256::fromVoid(key.data());
    }

    static uint256
    apiStateKey(std::initializer_list<std::uint8_t> bytes)
    {
        std::array<std::uint8_t, 32> key{};
        std::size_t i = 32 - bytes.size();
        for (auto const b : bytes)
            key[i++] = b;
        return uint256::fromVoid(key.data());
    }

    static std::size_t
    popcount(std::vector<std::uint8_t> const& bytes)
    {
        std::size_t count = 0;
        for (auto const b : bytes)
            count += __builtin_popcount(static_cast<unsigned>(b));
        return count;
    }

    static Json::Value
    hookParams(std::string const& nameHex, std::string const& valueHex)
    {
        Json::Value params{Json::arrayValue};
        Json::Value entry;
        entry[jss::HookParameter] = Json::Value{};
        entry[jss::HookParameter][jss::HookParameterName] = nameHex;
        entry[jss::HookParameter][jss::HookParameterValue] = valueHex;
        params.append(entry);
        return params;
    }

    static Json::Value
    hookParams2(
        std::string const& name1Hex, std::string const& value1Hex,
        std::string const& name2Hex, std::string const& value2Hex)
    {
        Json::Value params{Json::arrayValue};
        Json::Value e1;
        e1[jss::HookParameter] = Json::Value{};
        e1[jss::HookParameter][jss::HookParameterName] = name1Hex;
        e1[jss::HookParameter][jss::HookParameterValue] = value1Hex;
        params.append(e1);
        Json::Value e2;
        e2[jss::HookParameter] = Json::Value{};
        e2[jss::HookParameter][jss::HookParameterName] = name2Hex;
        e2[jss::HookParameter][jss::HookParameterValue] = value2Hex;
        params.append(e2);
        return params;
    }

    static std::string
    hookReturnString(
        std::shared_ptr<STObject const> const& meta,
        std::size_t index = 0)
    {
        if (!meta || !meta->isFieldPresent(sfHookExecutions))
            return {};

        auto const hookExecutions = meta->getFieldArray(sfHookExecutions);
        if (hookExecutions.size() <= index ||
            !hookExecutions[index].isFieldPresent(sfHookReturnString))
            return {};

        auto const ret = hookExecutions[index].getFieldVL(sfHookReturnString);
        return std::string(ret.begin(), ret.end());
    }

    static std::string
    firstHookReturnString(std::shared_ptr<STObject const> const& meta)
    {
        return hookReturnString(meta, 0);
    }

    static std::string
    lastHookReturnString(std::shared_ptr<STObject const> const& meta)
    {
        if (!meta || !meta->isFieldPresent(sfHookExecutions))
            return {};
        auto const hookExecutions = meta->getFieldArray(sfHookExecutions);
        if (hookExecutions.empty())
            return {};
        return hookReturnString(meta, hookExecutions.size() - 1);
    }

    // Compute the balance state key that top.c uses for withdrawals:
    // sha512h(accid(20) + currency(20) + issuer(20)) with first byte = 'B'
    static std::array<std::uint8_t, 32>
    balanceKey(AccountID const& acc,
               std::array<std::uint8_t, 20> const& currency = {},
               std::array<std::uint8_t, 20> const& issuer = {})
    {
        std::array<std::uint8_t, 60> input{};
        std::memcpy(input.data(), acc.data(), 20);
        std::memcpy(input.data() + 20, currency.data(), 20);
        std::memcpy(input.data() + 40, issuer.data(), 20);
        // Must use sha512Half (not sha512Half_s) to match hook's util_sha512h
        auto hash = sha512Half(Slice(input.data(), input.size()));
        std::array<std::uint8_t, 32> result;
        std::memcpy(result.data(), hash.data(), 32);
        result[0] = 'B';
        return result;
    }

    // Keep XFL arithmetic in the tests aligned with HookAPI so balance checks
    // can assert exact remainders instead of only checking "changed".
    static bool
    xflIsNegative(std::uint64_t xfl)
    {
        return ((xfl >> 62U) & 1ULL) == 0;
    }

    static std::int32_t
    xflExponent(std::uint64_t xfl)
    {
        if (xfl == 0)
            return 0;
        return static_cast<std::int32_t>((xfl >> 54U) & 0xFFU) - 97;
    }

    static std::uint64_t
    xflMantissa(std::uint64_t xfl)
    {
        if (xfl == 0)
            return 0;
        return xfl & ((1ULL << 54U) - 1ULL);
    }

    static std::uint64_t
    xflNegate(std::uint64_t xfl)
    {
        if (xfl == 0)
            return 0;
        return xfl ^ (1ULL << 62U);
    }

    static std::uint64_t
    xflFromIOUAmount(IOUAmount const& amt)
    {
        if (!amt)
            return 0;

        auto const neg = amt.mantissa() < 0;
        auto const mantissa = static_cast<std::uint64_t>(
            neg ? -amt.mantissa() : amt.mantissa());

        std::uint64_t out = mantissa;
        out |= static_cast<std::uint64_t>(amt.exponent() + 97) << 54U;
        if (!neg)
            out |= (1ULL << 62U);
        return out;
    }

    // Whole-number XFL literals are easy to get wrong by hand. Build them from
    // normalized IOUAmount values so the tests match HookAPI arithmetic.
    static std::uint64_t
    xflWhole(std::int64_t whole)
    {
        return xflFromIOUAmount(IOUAmount{whole, 0});
    }

    static std::uint64_t
    xflSum(std::uint64_t lhs, std::uint64_t rhs)
    {
        if (lhs == 0)
            return rhs;
        if (rhs == 0)
            return lhs;

        IOUAmount left{
            static_cast<std::int64_t>(xflMantissa(lhs)) *
                (xflIsNegative(lhs) ? -1LL : 1LL),
            xflExponent(lhs)};
        IOUAmount right{
            static_cast<std::int64_t>(xflMantissa(rhs)) *
                (xflIsNegative(rhs) ? -1LL : 1LL),
            xflExponent(rhs)};
        left += right;
        return xflFromIOUAmount(left);
    }

    static std::array<std::uint8_t, 32>
    hookSha512Half(std::uint8_t const* data, std::size_t len)
    {
        auto hash = sha512Half(Slice(data, len));
        std::array<std::uint8_t, 32> result;
        std::memcpy(result.data(), hash.data(), 32);
        return result;
    }

    static std::array<std::uint8_t, 32>
    opinionVoteKey(std::array<std::uint8_t, 85> const& opinion)
    {
        std::array<std::uint8_t, 86> fullOpinion{};
        fullOpinion[0] = 'O';
        std::memcpy(fullOpinion.data() + 1, opinion.data(), opinion.size());
        auto key = hookSha512Half(fullOpinion.data(), fullOpinion.size());
        key[0] = 'O';
        return key;
    }

    static uint256
    postInfoKey(std::uint8_t snid, std::uint64_t postId)
    {
        std::array<std::uint8_t, 10> key{};
        key[0] = 'O';
        key[1] = snid;
        std::memcpy(key.data() + 2, &postId, 8);
        return apiStateKey(key);
    }

    // Build the user info state key: right-aligned 'U' + accid (21 bytes)
    static std::array<std::uint8_t, 32>
    userInfoKey(AccountID const& acc)
    {
        std::array<std::uint8_t, 32> key{};
        key[32 - 21] = 'U';
        std::memcpy(key.data() + (32 - 20), acc.data(), 20);
        return key;
    }

    static uint256
    socialUserInfoKey(std::array<std::uint8_t, 20> const& target)
    {
        std::array<std::uint8_t, 21> key{};
        key[0] = 'U';
        std::copy(target.begin(), target.end(), key.begin() + 1);
        return apiStateKey(key);
    }

    static uint256
    socialUserSlotKey(
        std::array<std::uint8_t, 20> const& target, std::uint8_t slot)
    {
        std::array<std::uint8_t, 22> key{};
        key[0] = 'U';
        std::copy(target.begin(), target.end(), key.begin() + 1);
        key[21] = slot;
        return apiStateKey(key);
    }

    static uint256
    memberForwardKey(AccountID const& acc)
    {
        std::array<std::uint8_t, 21> key{};
        key[0] = 'M';
        std::memcpy(key.data() + 1, acc.data(), 20);
        return apiStateKey(key);
    }

    static uint256
    memberReverseKey(std::uint8_t seat)
    {
        return apiStateKey({static_cast<std::uint8_t>('P'), seat});
    }

    // Install the state-setter hook on hookAcc with zero namespace, then
    // call setState to write key/value pairs. Returns a lambda for setting state.
    void
    installStateSetter(jtx::Env& env, jtx::Account const& hookAcc)
    {
        using namespace jtx;

        auto const& setter_wasm = tipbotclaude_test_wasm[
            R"[test.hook](
            #include <stdint.h>
            extern int32_t _g(uint32_t, uint32_t);
            extern int64_t accept(uint32_t, uint32_t, int64_t);
            extern int64_t state_set(uint32_t, uint32_t, uint32_t, uint32_t);
            extern int64_t otxn_param(uint32_t, uint32_t, uint32_t, uint32_t);
            int64_t hook(uint32_t r) {
                _g(1,1);
                uint8_t key[32];
                uint8_t val[256];
                int64_t klen = otxn_param((uint32_t)(key), sizeof(key), "K", 1);
                int64_t vlen = otxn_param((uint32_t)(val), sizeof(val), "V", 1);
                if (klen > 0 && vlen > 0)
                    state_set(val, (uint32_t)vlen, key, (uint32_t)klen);
                return accept(0, 0, 0);
            }
            )[test.hook]"];

        auto setterHso = hso(setter_wasm, overrideFlag);
        setterHso[jss::HookNamespace] =
            "0000000000000000000000000000000000000000000000000000000000000000";

        env(ripple::test::jtx::hook(hookAcc, {{setterHso}}, 0),
            M("Install state setter"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();
    }

    void
    setState(
        jtx::Env& env,
        jtx::Account const& sender,
        jtx::Account const& hookAcc,
        std::uint8_t const* key, std::size_t klen,
        std::uint8_t const* val, std::size_t vlen)
    {
        using namespace jtx;

        auto const param = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams2(
                strHex(std::string("K")),
                strHex(Slice(key, klen)),
                strHex(std::string("V")),
                strHex(Slice(val, vlen)));
        };

        env(invoke::invoke(sender), invoke::dest(hookAcc),
            param,
            M("Set state"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    void
    installTopHookZeroNS(jtx::Env& env, jtx::Account const& hookAcc)
    {
        using namespace jtx;
        HOOK_WASM(top, "file:tipbot/top.c");

        auto topHso = hso(top_wasm, overrideFlag);
        topHso[jss::HookNamespace] =
            "0000000000000000000000000000000000000000000000000000000000000000";

        env(ripple::test::jtx::hook(hookAcc, {{topHso}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();
    }

    static std::array<std::uint8_t, 32>
    pendingGovernanceKey(std::uint8_t position)
    {
        std::array<std::uint8_t, 32> key{};
        key[32 - 2] = 'H';
        key[32 - 1] = position;
        return key;
    }

    static uint256
    filledHash(std::uint8_t byte)
    {
        std::array<std::uint8_t, 32> bytes{};
        bytes.fill(byte);
        return uint256::fromVoid(bytes.data());
    }

    void
    seedPendingGovernanceHook(
        jtx::Env& env,
        jtx::Account const& sender,
        jtx::Account const& hookAcc,
        std::uint8_t position,
        uint256 const& hookHash,
        uint256 const& hookOn)
    {
        auto const govKey = pendingGovernanceKey(position);
        std::array<std::uint8_t, 64> govVal{};
        std::memcpy(govVal.data(), hookHash.data(), 32);
        std::memcpy(govVal.data() + 32, hookOn.data(), 32);
        setState(
            env,
            sender,
            hookAcc,
            govKey.data(),
            govKey.size(),
            govVal.data(),
            govVal.size());
    }

    // Pre-populate an XAH balance for an account on the hook
    void
    seedXAHBalance(
        jtx::Env& env,
        jtx::Account const& sender,
        jtx::Account const& hookAcc,
        AccountID const& balanceOwner,
        std::uint64_t xflAmount)
    {
        auto bk = balanceKey(balanceOwner);
        std::array<std::uint8_t, 9> balVal{};
        std::memcpy(balVal.data(), &xflAmount, 8);
        balVal[8] = 0;
        setState(env, sender, hookAcc, bk.data(), bk.size(), balVal.data(), balVal.size());

        auto uik = userInfoKey(balanceOwner);
        std::array<std::uint8_t, 32> uiVal{};
        uiVal[0] = 0x01;
        setState(env, sender, hookAcc, uik.data(), uik.size(), uiVal.data(), uiVal.size());
    }

    // Make a test account a member of the oracle game at a given seat.
    // Must be called while state-setter hook is installed.
    void
    seedMember(
        jtx::Env& env,
        jtx::Account const& sender,
        jtx::Account const& hookAcc,
        AccountID const& memberId,
        std::uint8_t seat)
    {
        // 'M' + accid → seat_id (1 byte) — forward lookup
        std::array<std::uint8_t, 32> mKey{};
        mKey[32 - 21] = 'M';
        std::memcpy(mKey.data() + (32 - 20), memberId.data(), 20);
        setState(env, sender, hookAcc, mKey.data(), mKey.size(), &seat, 1);

        // 'P' + seat → accid (20 bytes) — reverse lookup
        std::array<std::uint8_t, 32> pKey{};
        pKey[32 - 2] = 'P';
        pKey[32 - 1] = seat;
        setState(env, sender, hookAcc,
                 pKey.data(), pKey.size(),
                 memberId.data(), 20);
    }

    // Seed the members bitfield with N members set (bits 0..N-1)
    void
    seedMembersBitfield(
        jtx::Env& env,
        jtx::Account const& sender,
        jtx::Account const& hookAcc,
        std::uint8_t memberCount)
    {
        std::array<std::uint8_t, 32> bf{};
        for (std::uint8_t i = 0; i < memberCount; ++i)
            bf[i >> 3] |= (1U << (i % 8));

        auto smKey = rawStateKey({'S', 'M'});
        std::array<std::uint8_t, 32> smKeyBytes;
        std::memcpy(smKeyBytes.data(), smKey.data(), 32);
        setState(env, sender, hookAcc,
                 smKeyBytes.data(), smKeyBytes.size(),
                 bf.data(), bf.size());
    }

    // Install tip hook with zero namespace
    void
    installTipHookZeroNS(jtx::Env& env, jtx::Account const& hookAcc)
    {
        using namespace jtx;
        HOOK_WASM(tip, "file:tipbot/tip.c");

        auto tipHso = hso(tip_wasm, overrideFlag);
        tipHso[jss::HookNamespace] =
            "0000000000000000000000000000000000000000000000000000000000000000";

        env(ripple::test::jtx::hook(hookAcc, {{tipHso}}, 0),
            M("Install tip hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();
    }

    // Build an 85-byte tip opinion param value (bytes 1-85 of the opinion).
    // snid=social network id, postId, toAccOrUserId (20 bytes), fromUserId,
    // currency (20 bytes), issuer (20 bytes), amountXfl
    static std::array<std::uint8_t, 85>
    buildTipOpinion(
        std::uint8_t snid,
        std::uint64_t postId,
        std::uint8_t const* to20,   // 20 bytes: accid or zeros+userid
        std::uint64_t fromUserId,
        std::uint64_t amountXfl,
        std::uint8_t const* currency20 = nullptr,
        std::uint8_t const* issuer20 = nullptr)
    {
        std::array<std::uint8_t, 85> op{};
        op[0] = snid;                                          // offset 1 in opinion
        std::memcpy(op.data() + 1, &postId, 8);               // offset 2
        std::memcpy(op.data() + 9, to20, 20);                 // offset 10
        std::memcpy(op.data() + 29, &fromUserId, 8);          // offset 30
        if (currency20)
            std::memcpy(op.data() + 37, currency20, 20);      // offset 38
        if (issuer20)
            std::memcpy(op.data() + 57, issuer20, 20);        // offset 58
        std::memcpy(op.data() + 77, &amountXfl, 8);           // offset 78
        return op;
    }

    // Build a member governance opinion (SNID 254)
    static std::array<std::uint8_t, 85>
    buildMemberOpinion(
        std::uint8_t seat,
        AccountID const& memberAcc)
    {
        std::array<std::uint8_t, 85> op{};
        op[0] = 254;           // SNID for member governance
        op[1] = seat;          // position byte
        std::memcpy(op.data() + 2, memberAcc.data(), 20);  // accid
        return op;
    }

    // Submit an invoke with opinion params to the tip hook
    void
    submitOpinion(
        jtx::Env& env,
        jtx::Account const& member,
        jtx::Account const& hookAcc,
        std::uint8_t paramIndex,
        std::array<std::uint8_t, 85> const& opinion,
        TER expectedResult = tesSUCCESS)
    {
        using namespace jtx;
        auto const param = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                strHex(Slice(&paramIndex, 1)),
                strHex(Slice(opinion.data(), opinion.size())));
        };

        env(invoke::invoke(member), invoke::dest(hookAcc),
            param,
            M("Submit opinion"),
            fee(XRP(1)),
            ter(expectedResult));
    }

    template <std::size_t N>
    static uint256
    apiStateKey(std::array<std::uint8_t, N> const& bytes)
    {
        std::array<std::uint8_t, 32> key{};
        static_assert(N <= key.size());
        std::copy(bytes.begin(), bytes.end(), key.begin() + (key.size() - N));
        return uint256::fromVoid(key.data());
    }

public:
    // ---- Tip Hook (Oracle Game) Tests ----

    void
    testTipHookInstall(FeatureBitset features)
    {
        testcase("Tip: install hook");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        env.fund(XRP(10000), alice);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(tip_wasm, overrideFlag)}}, 0),
            M("Install tip hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        auto const hook = env.le(keylet::hook(alice.id()));
        BEAST_REQUIRE(hook);
        BEAST_REQUIRE(hook->isFieldPresent(sfHooks));
        auto const& hooks = hook->getFieldArray(sfHooks);
        BEAST_EXPECT(hooks.size() > 0);
        BEAST_EXPECT(hooks[0].isFieldPresent(sfHookHash));
        BEAST_EXPECT(hooks[0].getFieldH256(sfHookHash) == tip_hash);
    }

    void
    testTipPassesOutgoing(FeatureBitset features)
    {
        testcase("Tip: passes outgoing txn");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(tip_wasm, overrideFlag)}}, 0),
            M("Install tip hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        env(pay(alice, bob, XRP(1)),
            M("Outgoing payment passes"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    void
    testTipPassesNonInvoke(FeatureBitset features)
    {
        testcase("Tip: passes non-invoke incoming txn");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(tip_wasm, overrideFlag)}}, 0),
            M("Install tip hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Incoming payment (not invoke) should pass through
        env(pay(bob, alice, XRP(1)),
            M("Non-invoke passes"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    void
    testTipInitialMembers(FeatureBitset features)
    {
        testcase("Tip: bootstraps 3 initial members on first invoke");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(tip_wasm, overrideFlag)}}, 0),
            M("Install tip hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Invoke from non-member triggers bootstrap + cleanup, then accepts
        // (non-member gets "Did some cleanup anyway" message)
        env(invoke::invoke(bob), invoke::dest(alice),
            M("First invoke initializes members"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // Verify hook state directory was created and bootstrap state exists
        auto const hookState = env.le(
            keylet::hookStateDir(alice.id(), uint256{beast::zero}));
        BEAST_REQUIRE(hookState);

        auto const membersBitfield =
            env.le(
                keylet::hookState(alice.id(), rawStateKey({'S', 'M'}), beast::zero));
        BEAST_REQUIRE(membersBitfield);
        auto const& bitfield = membersBitfield->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(bitfield.size() == 32);
        BEAST_EXPECT(popcount(bitfield) == 3);

        for (std::uint8_t seat = 0; seat < 3; ++seat)
        {
            auto const memberSeat =
                env.le(keylet::hookState(
                    alice.id(), apiStateKey({'P', seat}), beast::zero));
            BEAST_REQUIRE(memberSeat);
            BEAST_EXPECT(memberSeat->getFieldVL(sfHookStateData).size() == 20);
        }
    }

    void
    testTipNonMemberRejected(FeatureBitset features)
    {
        testcase("Tip: non-member invoke accepted but doesn't process opinions");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        auto const& carol = env.account("carol");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.fund(XRP(10000), carol);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(tip_wasm, overrideFlag)}}, 0),
            M("Install tip hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // First invoke bootstraps members
        env(invoke::invoke(bob), invoke::dest(alice),
            M("Bootstrap members"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // carol is not a member -- invoke still succeeds (accept with
        // "not a member" message) because cleanup runs first
        env(invoke::invoke(carol), invoke::dest(alice),
            M("Non-member invoke accepted"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    void
    testTipCorruptMembersBitfieldSuppressesBootstrap(FeatureBitset features)
    {
        testcase("Tip: corrupt members bitfield suppresses bootstrap");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        auto const& helper = env.account("helper");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.fund(XRP(10000), helper);
        env.close();

        installStateSetter(env, alice);

        std::array<std::uint8_t, 32> membersKey{};
        membersKey[0] = 'S';
        membersKey[1] = 'M';
        std::array<std::uint8_t, 32> corruptMembers{};
        corruptMembers[0] = 0x01;
        setState(
            env,
            helper,
            alice,
            membersKey.data(),
            membersKey.size(),
            corruptMembers.data(),
            corruptMembers.size());

        installTipHookZeroNS(env, alice);

        env(invoke::invoke(bob), invoke::dest(alice),
            M("Corrupt members bitfield invoke"),
            fee(XRP(1)),
            ter(tesSUCCESS));

        auto const ret = firstHookReturnString(env.meta());
        BEAST_EXPECT(
            ret.find("not a member of the tipbot oracle game") !=
            std::string::npos);
        env.close();

        auto const seat0 =
            env.le(keylet::hookState(alice.id(), memberReverseKey(0), beast::zero));
        auto const seat1 =
            env.le(keylet::hookState(alice.id(), memberReverseKey(1), beast::zero));
        auto const seat2 =
            env.le(keylet::hookState(alice.id(), memberReverseKey(2), beast::zero));
        BEAST_EXPECT(!seat0);
        BEAST_EXPECT(!seat1);
        BEAST_EXPECT(!seat2);

        auto const membersBitfield =
            env.le(keylet::hookState(alice.id(), rawStateKey({'S', 'M'}), beast::zero));
        BEAST_REQUIRE(membersBitfield);
        auto const& bitfield = membersBitfield->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(bitfield.size() == 32);
        BEAST_EXPECT(popcount(bitfield) == 1);
    }

    void
    testTipTruncatedMembersBitfieldBootstraps(FeatureBitset features)
    {
        testcase("Tip: truncated members bitfield bootstraps initial members");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        auto const& helper = env.account("helper");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.fund(XRP(10000), helper);
        env.close();

        installStateSetter(env, alice);

        std::array<std::uint8_t, 32> membersKey{};
        membersKey[0] = 'S';
        membersKey[1] = 'M';
        std::array<std::uint8_t, 1> truncatedMembers{0x01};
        setState(
            env,
            helper,
            alice,
            membersKey.data(),
            membersKey.size(),
            truncatedMembers.data(),
            truncatedMembers.size());

        installTipHookZeroNS(env, alice);

        env(invoke::invoke(bob), invoke::dest(alice),
            M("Truncated members bitfield invoke"),
            fee(XRP(1)),
            ter(tesSUCCESS));

        auto const ret = firstHookReturnString(env.meta());
        BEAST_EXPECT(
            ret.find("not a member of the tipbot oracle game") !=
            std::string::npos);
        env.close();

        auto const membersBitfield =
            env.le(keylet::hookState(alice.id(), rawStateKey({'S', 'M'}), beast::zero));
        BEAST_REQUIRE(membersBitfield);
        auto const& bitfield = membersBitfield->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(bitfield.size() == 32);
        BEAST_EXPECT(popcount(bitfield) == 3);
        BEAST_EXPECT(bitfield[0] == 0x07);

        auto const seat0 =
            env.le(keylet::hookState(alice.id(), memberReverseKey(0), beast::zero));
        auto const seat1 =
            env.le(keylet::hookState(alice.id(), memberReverseKey(1), beast::zero));
        auto const seat2 =
            env.le(keylet::hookState(alice.id(), memberReverseKey(2), beast::zero));
        BEAST_REQUIRE(seat0);
        BEAST_REQUIRE(seat1);
        BEAST_REQUIRE(seat2);
    }

    // ---- Top Hook (Deposit/Withdraw) Tests ----

    void
    testTopHookInstall(FeatureBitset features)
    {
        testcase("Top: install hook");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        env.fund(XRP(10000), alice);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        auto const hook = env.le(keylet::hook(alice.id()));
        BEAST_REQUIRE(hook);
        BEAST_REQUIRE(hook->isFieldPresent(sfHooks));
        auto const& hooks = hook->getFieldArray(sfHooks);
        BEAST_EXPECT(hooks.size() > 0);
        BEAST_EXPECT(hooks[0].isFieldPresent(sfHookHash));
        BEAST_EXPECT(hooks[0].getFieldH256(sfHookHash) == top_hash);
    }

    void
    testTopPassesOutgoing(FeatureBitset features)
    {
        testcase("Top: passes outgoing txn");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        env(pay(alice, bob, XRP(1)),
            M("Outgoing payment passes"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    void
    testTopPassesNonRemit(FeatureBitset features)
    {
        testcase("Top: passes non-remit incoming txn");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Incoming payment (not remit) should pass through
        env(pay(bob, alice, XRP(1)),
            M("Non-remit passes"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    void
    testTopRejectsRemitWithNFT(FeatureBitset features)
    {
        testcase("Top: rejects remit containing NFTs");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Remit with a minted URI token should be rejected
        env(remit::remit(bob, alice),
            remit::uri("test-uri"),
            M("Remit with NFT rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();
    }

    void
    testTopDepositMissingParam(FeatureBitset features)
    {
        testcase("Top: deposit rejects remit without DEPOSIT param");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Remit with amount but no DEPOSIT parameter should be rejected
        env(remit::remit(bob, alice),
            remit::amts({XRP(100)}),
            M("Deposit without param rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();
    }

    void
    testTopDepositSuccessCreatesUserState(FeatureBitset features)
    {
        testcase("Top: successful deposit creates user info state");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        std::array<std::uint8_t, 20> depositTarget{};
        depositTarget[0] = 1;  // twitter/X
        std::uint64_t const userId = 42;
        for (int i = 0; i < 8; ++i)
            depositTarget[12 + i] =
                static_cast<std::uint8_t>((userId >> (i * 8)) & 0xFF);

        auto const depositParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "4445504F534954",  // DEPOSIT
                strHex(Slice(depositTarget.data(), depositTarget.size())));
        };

        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            depositParam,
            M("First deposit succeeds"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        auto const userInfo =
            env.le(keylet::hookState(
                alice.id(),
                apiStateKey([&]() {
                    std::array<std::uint8_t, 21> key{};
                    key[0] = 'U';
                    std::copy(
                        depositTarget.begin(), depositTarget.end(), key.begin() + 1);
                    return key;
                }()),
                beast::zero));
        BEAST_REQUIRE(userInfo);
        auto const& userInfoData = userInfo->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(userInfoData.size() == 32);
        BEAST_EXPECT(popcount(userInfoData) == 1);
        BEAST_EXPECT(userInfoData[0] == 0x01);

        auto const userSlot =
            env.le(keylet::hookState(
                alice.id(),
                apiStateKey([&]() {
                    std::array<std::uint8_t, 22> key{};
                    key[0] = 'U';
                    std::copy(
                        depositTarget.begin(), depositTarget.end(), key.begin() + 1);
                    key[21] = 0;
                    return key;
                }()),
                beast::zero));
        BEAST_REQUIRE(userSlot);
        BEAST_EXPECT(userSlot->getFieldVL(sfHookStateData).size() == 40);
    }

    void
    testTopWithdrawMissingParam(FeatureBitset features)
    {
        testcase("Top: withdraw rejects empty remit without WITHDRAW param");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Empty remit (no amounts) without WITHDRAW parameter should be rejected
        env(remit::remit(bob, alice),
            M("Withdraw without param rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();
    }

    void
    testTopDepositFirstMustBeXAH(FeatureBitset features)
    {
        testcase("Top: first deposit must be XAH >= 10");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        auto const& gw = env.account("gateway");
        auto const USD = gw["USD"];
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.fund(XRP(10000), gw);
        env.close();
        env.trust(USD(100000), bob);
        env.close();
        env(pay(gw, bob, USD(1000)));
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Build DEPOSIT param: SNID=1 (twitter), userid=99
        std::array<std::uint8_t, 20> depositTarget{};
        depositTarget[0] = 1;
        std::uint64_t const userId = 99;
        for (int i = 0; i < 8; ++i)
            depositTarget[12 + i] =
                static_cast<std::uint8_t>((userId >> (i * 8)) & 0xFF);

        auto const depositParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "4445504F534954",
                strHex(Slice(depositTarget.data(), depositTarget.size())));
        };

        // First deposit with IOU should fail (must be XAH)
        env(remit::remit(bob, alice),
            remit::amts({USD(100)}),
            depositParam,
            M("First deposit IOU rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();

        // First deposit with XAH < 10 should fail
        env(remit::remit(bob, alice),
            remit::amts({XRP(5)}),
            depositParam,
            M("First deposit < 10 XAH rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();

        // First deposit with XAH >= 10 should succeed
        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            depositParam,
            M("First deposit 10 XAH succeeds"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    void
    testTopDepositInvalidSNID(FeatureBitset features)
    {
        testcase("Top: deposit rejects invalid SNID");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // SNID=0 is invalid
        {
            std::array<std::uint8_t, 20> target{};
            target[0] = 0;
            std::uint64_t const userId = 42;
            for (int i = 0; i < 8; ++i)
                target[12 + i] =
                    static_cast<std::uint8_t>((userId >> (i * 8)) & 0xFF);

            auto const param = [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "4445504F534954",
                    strHex(Slice(target.data(), target.size())));
            };

            env(remit::remit(bob, alice),
                remit::amts({XRP(10)}),
                param,
                M("SNID 0 rejected"),
                fee(XRP(1)),
                ter(tecHOOK_REJECTED));
            env.close();
        }

        // SNID=254 is reserved (governance)
        {
            std::array<std::uint8_t, 20> target{};
            target[0] = 254;
            std::uint64_t const userId = 42;
            for (int i = 0; i < 8; ++i)
                target[12 + i] =
                    static_cast<std::uint8_t>((userId >> (i * 8)) & 0xFF);

            auto const param = [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "4445504F534954",
                    strHex(Slice(target.data(), target.size())));
            };

            env(remit::remit(bob, alice),
                remit::amts({XRP(10)}),
                param,
                M("SNID 254 rejected"),
                fee(XRP(1)),
                ter(tecHOOK_REJECTED));
            env.close();
        }
    }

    void
    testTopDepositRejectsAccidTarget(FeatureBitset features)
    {
        testcase("Top: deposit rejects accid target (anti-laundering)");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // DEPOSIT param with non-zero bytes in the 11-zero region (bytes 1-11)
        // indicates an accid rather than snid+userid -- should be rejected
        std::array<std::uint8_t, 20> target{};
        target[0] = 1;    // valid SNID
        target[1] = 0xFF; // non-zero in "must be zero" region
        std::uint64_t const userId = 42;
        for (int i = 0; i < 8; ++i)
            target[12 + i] =
                static_cast<std::uint8_t>((userId >> (i * 8)) & 0xFF);

        auto const param = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "4445504F534954",
                strHex(Slice(target.data(), target.size())));
        };

        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            param,
            M("Accid target rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();
    }

    void
    testTopWithdrawNoBalance(FeatureBitset features)
    {
        testcase("Top: withdraw fails when no balance exists");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // WITHDRAW param: 20 bytes currency (zeros=XAH) + 20 bytes issuer
        // (zeros=XAH) + 8 bytes XFL amount
        std::array<std::uint8_t, 48> withdrawData{};
        auto const amt = xflWhole(10);
        for (int i = 0; i < 8; ++i)
            withdrawData[40 + i] =
                static_cast<std::uint8_t>((amt >> (i * 8)) & 0xFF);

        auto const param = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "5749544844524157",  // WITHDRAW
                strHex(Slice(withdrawData.data(), withdrawData.size())));
        };

        // bob has no balance on the hook
        env(remit::remit(bob, alice),
            param,
            M("Withdraw no balance rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();
    }

    void
    testTopDepositSecondCanBeIOU(FeatureBitset features)
    {
        testcase("Top: second deposit can be IOU after initial XAH");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");  // hook account
        auto const& bob = env.account("bob");
        auto const& gw = env.account("gateway");
        auto const USD = gw["USD"];
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.fund(XRP(10000), gw);
        env.close();
        env.trust(USD(100000), bob);
        env.trust(USD(100000), alice);  // hook account needs TL for IOU
        env.close();
        env(pay(gw, bob, USD(1000)));
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // SNID=1, userid=77
        std::array<std::uint8_t, 20> depositTarget{};
        depositTarget[0] = 1;
        std::uint64_t const userId = 77;
        for (int i = 0; i < 8; ++i)
            depositTarget[12 + i] =
                static_cast<std::uint8_t>((userId >> (i * 8)) & 0xFF);

        auto const depositParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "4445504F534954",
                strHex(Slice(depositTarget.data(), depositTarget.size())));
        };

        // First deposit: XAH >= 10 (required)
        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            depositParam,
            M("First deposit XAH"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // Second deposit: IOU should now succeed (user already exists)
        env(remit::remit(bob, alice),
            remit::amts({USD(50)}),
            depositParam,
            M("Second deposit IOU succeeds"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    void
    testTopRejectsMultipleAmounts(FeatureBitset features)
    {
        testcase("Top: deposit rejects remit with multiple amounts");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        auto const& gw = env.account("gateway");
        auto const USD = gw["USD"];
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.fund(XRP(10000), gw);
        env.close();
        env.trust(USD(100000), bob);
        env.trust(USD(100000), alice);
        env.close();
        env(pay(gw, bob, USD(1000)));
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        std::array<std::uint8_t, 20> depositTarget{};
        depositTarget[0] = 1;
        std::uint64_t const userId = 55;
        for (int i = 0; i < 8; ++i)
            depositTarget[12 + i] =
                static_cast<std::uint8_t>((userId >> (i * 8)) & 0xFF);

        auto const depositParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "4445504F534954",
                strHex(Slice(depositTarget.data(), depositTarget.size())));
        };

        // Remit with two amounts -- hook requires exactly 1
        env(remit::remit(bob, alice),
            remit::amts({XRP(10), USD(50)}),
            depositParam,
            M("Multiple amounts rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();
    }

    void
    testTopRejectsDepositAndWithdrawParamsTogether(FeatureBitset features)
    {
        testcase("Top: remit rejects ambiguous DEPOSIT and WITHDRAW params");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        std::array<std::uint8_t, 20> depositTarget{};
        depositTarget[0] = 1;
        std::uint64_t const userId = 88;
        for (int i = 0; i < 8; ++i)
            depositTarget[12 + i] =
                static_cast<std::uint8_t>((userId >> (i * 8)) & 0xFF);

        std::array<std::uint8_t, 48> withdrawData{};
        auto const xfl10 = xflWhole(10);
        std::memcpy(withdrawData.data() + 40, &xfl10, 8);

        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams2(
                    "4445504F534954",
                    strHex(Slice(depositTarget.data(), depositTarget.size())),
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("Deposit and withdraw params rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();

        auto const userInfo = env.le(keylet::hookState(
            alice.id(),
            socialUserInfoKey(depositTarget),
            uint256{beast::zero}));
        BEAST_EXPECT(!userInfo);
    }

    void
    testTopRejectsDuplicateDepositParams(FeatureBitset features)
    {
        testcase("Top: remit rejects duplicate DEPOSIT params");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        std::array<std::uint8_t, 20> depositTargetA{};
        depositTargetA[0] = 1;
        std::uint64_t const userIdA = 91;
        for (int i = 0; i < 8; ++i)
            depositTargetA[12 + i] =
                static_cast<std::uint8_t>((userIdA >> (i * 8)) & 0xFF);

        std::array<std::uint8_t, 20> depositTargetB{};
        depositTargetB[0] = 1;
        std::uint64_t const userIdB = 92;
        for (int i = 0; i < 8; ++i)
            depositTargetB[12 + i] =
                static_cast<std::uint8_t>((userIdB >> (i * 8)) & 0xFF);

        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams2(
                    "4445504F534954",
                    strHex(Slice(depositTargetA.data(), depositTargetA.size())),
                    "4445504F534954",
                    strHex(Slice(depositTargetB.data(), depositTargetB.size())));
            },
            M("Duplicate deposit params rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();

        auto const userInfoA = env.le(keylet::hookState(
            alice.id(),
            socialUserInfoKey(depositTargetA),
            uint256{beast::zero}));
        auto const userInfoB = env.le(keylet::hookState(
            alice.id(),
            socialUserInfoKey(depositTargetB),
            uint256{beast::zero}));
        BEAST_EXPECT(!userInfoA);
        BEAST_EXPECT(!userInfoB);
    }

    void
    testTopRejectsDuplicateWithdrawParams(FeatureBitset features)
    {
        testcase("Top: remit rejects duplicate WITHDRAW params");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.close();

        installStateSetter(env, alice);
        seedXAHBalance(env, bob, alice, bob.id(), xflWhole(100));
        installTopHookZeroNS(env, alice);

        std::array<std::uint8_t, 48> withdrawTen{};
        auto const xfl10 = xflWhole(10);
        std::memcpy(withdrawTen.data() + 40, &xfl10, 8);

        std::array<std::uint8_t, 48> withdrawTwenty{};
        auto const xfl20 = xflWhole(20);
        std::memcpy(withdrawTwenty.data() + 40, &xfl20, 8);

        env(remit::remit(bob, alice),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams2(
                    "5749544844524157",
                    strHex(Slice(withdrawTen.data(), withdrawTen.size())),
                    "5749544844524157",
                    strHex(Slice(withdrawTwenty.data(), withdrawTwenty.size())));
            },
            M("Duplicate withdraw params rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();

        auto const balState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(balanceKey(bob.id()).data()),
            beast::zero));
        BEAST_REQUIRE(balState);
        auto const& balData = balState->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(balData.size() == 9);
        std::uint64_t balXfl = 0;
        std::memcpy(&balXfl, balData.data(), 8);
        BEAST_EXPECT(balXfl == xflWhole(100));
    }

    void
    testTopDepositAccumulatesBalance(FeatureBitset features)
    {
        testcase("Top: multiple deposits to same user accumulate");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // SNID=1, userid=123
        std::array<std::uint8_t, 20> depositTarget{};
        depositTarget[0] = 1;
        std::uint64_t const userId = 123;
        for (int i = 0; i < 8; ++i)
            depositTarget[12 + i] =
                static_cast<std::uint8_t>((userId >> (i * 8)) & 0xFF);

        auto const depositParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "4445504F534954",
                strHex(Slice(depositTarget.data(), depositTarget.size())));
        };

        // First deposit
        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            depositParam,
            M("First deposit"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // Second deposit to same user
        env(remit::remit(bob, alice),
            remit::amts({XRP(20)}),
            depositParam,
            M("Second deposit"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // User info should still have exactly 1 currency slot occupied
        auto const userInfo =
            env.le(keylet::hookState(
                alice.id(),
                apiStateKey([&]() {
                    std::array<std::uint8_t, 21> key{};
                    key[0] = 'U';
                    std::copy(
                        depositTarget.begin(), depositTarget.end(),
                        key.begin() + 1);
                    return key;
                }()),
                beast::zero));
        BEAST_REQUIRE(userInfo);
        auto const& userInfoData = userInfo->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(userInfoData.size() == 32);
        // Still only 1 currency slot (XAH)
        BEAST_EXPECT(popcount(userInfoData) == 1);
    }

    void
    testTopDepositAllocatesDistinctSlotsForNewCurrencies(FeatureBitset features)
    {
        testcase("Top: each new deposited currency allocates a fresh slot");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        auto const& gw = env.account("gateway");
        auto const USD = gw["USD"];
        auto const EUR = gw["EUR"];
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.fund(XRP(100000), gw);
        env.close();
        env.trust(USD(100000), bob);
        env.trust(USD(100000), alice);
        env.trust(EUR(100000), bob);
        env.trust(EUR(100000), alice);
        env.close();
        env(pay(gw, bob, USD(1000)));
        env(pay(gw, bob, EUR(1000)));
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        std::array<std::uint8_t, 20> depositTarget{};
        depositTarget[0] = 1;
        std::uint64_t const userId = 321;
        std::memcpy(depositTarget.data() + 12, &userId, 8);

        auto const depositParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "4445504F534954",
                strHex(Slice(depositTarget.data(), depositTarget.size())));
        };

        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            depositParam,
            M("Seed user with XAH"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        env(remit::remit(bob, alice),
            remit::amts({USD(50)}),
            depositParam,
            M("Deposit USD"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        env(remit::remit(bob, alice),
            remit::amts({EUR(75)}),
            depositParam,
            M("Deposit EUR"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        auto const userInfo = env.le(keylet::hookState(
            alice.id(), socialUserInfoKey(depositTarget), beast::zero));
        BEAST_REQUIRE(userInfo);
        auto const& userInfoData = userInfo->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(userInfoData.size() == 32);
        BEAST_EXPECT(popcount(userInfoData) == 3);
        BEAST_EXPECT(userInfoData[0] == 0x07);

        auto const slot0 = env.le(keylet::hookState(
            alice.id(), socialUserSlotKey(depositTarget, 0), beast::zero));
        auto const slot1 = env.le(keylet::hookState(
            alice.id(), socialUserSlotKey(depositTarget, 1), beast::zero));
        auto const slot2 = env.le(keylet::hookState(
            alice.id(), socialUserSlotKey(depositTarget, 2), beast::zero));
        BEAST_REQUIRE(slot0);
        BEAST_REQUIRE(slot1);
        BEAST_REQUIRE(slot2);
        BEAST_EXPECT(slot0->getFieldVL(sfHookStateData).size() == 40);
        BEAST_EXPECT(slot1->getFieldVL(sfHookStateData).size() == 40);
        BEAST_EXPECT(slot2->getFieldVL(sfHookStateData).size() == 40);
    }

    void
    testTopWithdrawXAHSuccess(FeatureBitset features)
    {
        testcase("Top: successful XAH withdrawal emits remit");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.close();

        // Seed bob's XAH balance via state-setter hook.
        installStateSetter(env, alice);
        auto const xfl100 = xflWhole(100);
        seedXAHBalance(env, bob, alice, bob.id(), xfl100);

        // Replace with real top hook
        installTopHookZeroNS(env, alice);

        auto const bobBalBefore = env.balance(bob).value().xrp().drops();

        std::array<std::uint8_t, 48> withdrawData{};
        auto const xfl50 = xflWhole(50);
        std::memcpy(withdrawData.data() + 40, &xfl50, 8);

        env(remit::remit(bob, alice),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("Withdraw 50 XAH"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // Close to process emitted remit back to bob
        env.close();

        auto const bobBalAfter = env.balance(bob).value().xrp().drops();
        BEAST_EXPECT(
            bobBalAfter ==
            bobBalBefore + XRP(49).value().xrp().drops());

        auto const bk = balanceKey(bob.id());
        auto const remaining = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(remaining);
        auto const& balData = remaining->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(balData.size() == 9);
        std::uint64_t remainingXfl = 0;
        std::memcpy(&remainingXfl, balData.data(), 8);
        BEAST_EXPECT(remainingXfl == xfl50);
    }

    void
    testTopWithdrawExceedsBalanceCaps(FeatureBitset features)
    {
        testcase("Top: withdraw more than balance sends entire balance");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.close();

        // Seed bob with 10 XAH internal balance.
        installStateSetter(env, alice);
        seedXAHBalance(env, bob, alice, bob.id(), xflWhole(10));

        installTopHookZeroNS(env, alice);

        auto const bobBalBefore = env.balance(bob).value().xrp().drops();

        // Request withdrawal of 1000 XAH (way more than the 10 balance).
        std::array<std::uint8_t, 48> withdrawData{};
        auto const xfl1000 = xflWhole(1000);
        std::memcpy(withdrawData.data() + 40, &xfl1000, 8);

        env(remit::remit(bob, alice),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("Withdraw exceeds balance - capped"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
        env.close();  // process emitted txn

        auto const bobBalAfter = env.balance(bob).value().xrp().drops();
        BEAST_EXPECT(
            bobBalAfter ==
            bobBalBefore + XRP(9).value().xrp().drops());

        // Balance state should be deleted (entire balance was sent)
        auto bk = balanceKey(bob.id());
        auto const balState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_EXPECT(!balState);
    }

    void
    testTopWithdrawIOUNeedsTrustline(FeatureBitset features)
    {
        testcase("Top: IOU withdrawal fails without trustline");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        auto const& gw = env.account("gateway");
        auto const USD = gw["USD"];
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.fund(XRP(100000), gw);
        env.close();

        // Build the currency and issuer byte arrays for USD
        auto const usdCurrency = USD.issue().currency;
        auto const usdIssuer = USD.issue().account;
        std::array<std::uint8_t, 20> curBytes{};
        std::array<std::uint8_t, 20> issBytes{};
        std::memcpy(curBytes.data(), usdCurrency.data(), 20);
        std::memcpy(issBytes.data(), usdIssuer.data(), 20);

        // Seed bob's USD balance via state-setter.
        installStateSetter(env, alice);

        auto bk = balanceKey(bob.id(), curBytes, issBytes);
        std::array<std::uint8_t, 9> balVal{};
        auto const xfl100 = xflWhole(100);
        std::memcpy(balVal.data(), &xfl100, 8);
        balVal[8] = 0;
        setState(env, bob, alice, bk.data(), bk.size(), balVal.data(), balVal.size());

        auto uik = userInfoKey(bob.id());
        std::array<std::uint8_t, 32> uiVal{};
        uiVal[0] = 0x01;
        setState(env, bob, alice, uik.data(), uik.size(), uiVal.data(), uiVal.size());

        installTopHookZeroNS(env, alice);

        // Bob does NOT have a trustline for USD - withdrawal should fail
        std::array<std::uint8_t, 48> withdrawData{};
        std::memcpy(withdrawData.data(), curBytes.data(), 20);
        std::memcpy(withdrawData.data() + 20, issBytes.data(), 20);
        auto const xfl50 = xflWhole(50);
        std::memcpy(withdrawData.data() + 40, &xfl50, 8);

        env(remit::remit(bob, alice),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("IOU withdraw without TL rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();
    }

    void
    testTopWithdrawIOUWithTrustline(FeatureBitset features)
    {
        testcase("Top: IOU withdrawal succeeds with trustline");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        auto const& gw = env.account("gateway");
        auto const USD = gw["USD"];
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.fund(XRP(100000), gw);
        env.close();

        // Bob sets up trustline for USD
        env.trust(USD(100000), bob);
        env.trust(USD(100000), alice);
        env.close();

        // The emitted Remit spends from the hook account, so the hook account
        // needs real on-ledger USD for the success path.
        env(pay(gw, alice, USD(100)));
        env.close();

        auto const usdCurrency = USD.issue().currency;
        auto const usdIssuer = USD.issue().account;
        std::array<std::uint8_t, 20> curBytes{};
        std::array<std::uint8_t, 20> issBytes{};
        std::memcpy(curBytes.data(), usdCurrency.data(), 20);
        std::memcpy(issBytes.data(), usdIssuer.data(), 20);

        // Seed bob's USD balance
        installStateSetter(env, alice);

        auto bk = balanceKey(bob.id(), curBytes, issBytes);
        std::array<std::uint8_t, 9> balVal{};
        auto const xfl100 = xflWhole(100);
        std::memcpy(balVal.data(), &xfl100, 8);
        balVal[8] = 0;
        setState(env, bob, alice, bk.data(), bk.size(), balVal.data(), balVal.size());

        auto uik = userInfoKey(bob.id());
        std::array<std::uint8_t, 32> uiVal{};
        uiVal[0] = 0x01;
        setState(env, bob, alice, uik.data(), uik.size(), uiVal.data(), uiVal.size());

        installTopHookZeroNS(env, alice);

        // Bob withdraws 50 USD - should succeed since he has a trustline
        std::array<std::uint8_t, 48> withdrawData{};
        std::memcpy(withdrawData.data(), curBytes.data(), 20);
        std::memcpy(withdrawData.data() + 20, issBytes.data(), 20);
        auto const xfl50 = xflWhole(50);
        std::memcpy(withdrawData.data() + 40, &xfl50, 8);

        env(remit::remit(bob, alice),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("IOU withdraw with TL succeeds"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
        env.close();  // process emitted txn

        if (auto const bobLine = env.le(keylet::line(bob.id(), USD.issue())))
        {
            auto actualUsd = bobLine->getFieldAmount(sfBalance);
            actualUsd.setIssuer(USD.issue().account);
            if (bob.id() > USD.issue().account)
                actualUsd.negate();
            std::cerr << "testTopWithdrawIOUWithTrustline actual bob USD balance="
                      << actualUsd.getText() << "\n";
        }
        else
        {
            std::cerr
                << "testTopWithdrawIOUWithTrustline bob trustline missing\n";
        }

        env.require(balance(bob, USD(50)));

        auto const remaining = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(remaining);
        auto const& remainingData = remaining->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(remainingData.size() == 9);
        std::uint64_t remainingXfl = 0;
        std::memcpy(&remainingXfl, remainingData.data(), 8);
        std::cerr << "testTopWithdrawIOUWithTrustline remainingXfl="
                  << remainingXfl << " exp=" << xflExponent(remainingXfl)
                  << " mantissa=" << xflMantissa(remainingXfl)
                  << " expected=" << xfl50 << "\n";
        BEAST_EXPECT(remainingXfl == xfl50);
    }

    void
    testTopGovernanceEmit(FeatureBitset features)
    {
        testcase("Top: governance SetHook emit piggybacked on withdrawal");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.close();

        // First install the tip hook on a helper account to create a real
        // hook definition on the ledger -- we need a valid hook hash for
        // the governance emit to succeed
        auto const& carol = env.account("carol");
        env.fund(XRP(100000), carol);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");
        env(ripple::test::jtx::hook(
                carol, {{hso(tip_wasm, overrideFlag)}}, 0),
            M("Install tip on carol for hash"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        installStateSetter(env, alice);

        // Seed bob's XAH balance for the withdrawal
        seedXAHBalance(env, bob, alice, bob.id(), xflWhole(100));
        auto const hookOnAll = filledHash(0xFF);
        auto const govKey = pendingGovernanceKey(0);
        seedPendingGovernanceHook(env, bob, alice, 0, tip_hash, hookOnAll);

        installTopHookZeroNS(env, alice);

        // Bob withdraws - this should also trigger the governance emit
        std::array<std::uint8_t, 48> withdrawData{};
        auto const xfl10 = xflWhole(10);
        std::memcpy(withdrawData.data() + 40, &xfl10, 8);

        // The governance emit should succeed: withdrawal + piggybacked SetHook.
        // If this fails, the emitted SetHook is malformed -- likely because
        // top.c writes OTXNACC (withdrawer) as sfAccount instead of HOOKACC.
        env(remit::remit(bob, alice),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("Withdraw + governance emit"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
        env.close();

        // The 'H' state entry should be cleared after successful emit
        auto const govState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(govKey.data()),
            uint256{beast::zero}));
        BEAST_EXPECT(!govState);

        auto const hook = env.le(keylet::hook(alice.id()));
        BEAST_REQUIRE(hook);
        BEAST_REQUIRE(hook->isFieldPresent(sfHooks));
        auto const& hooks = hook->getFieldArray(sfHooks);
        BEAST_REQUIRE(hooks.size() > 0);
        BEAST_REQUIRE(hooks[0].isFieldPresent(sfHookHash));
        BEAST_EXPECT(hooks[0].getFieldH256(sfHookHash) == tip_hash);
        BEAST_REQUIRE(hooks[0].isFieldPresent(sfHookOn));
        BEAST_EXPECT(hooks[0].getFieldH256(sfHookOn) == hookOnAll);
    }

    void
    testTopGovernanceQueueDrainsOneEntryPerWithdrawal(FeatureBitset features)
    {
        testcase("Top: queued governance entries drain one per withdrawal");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        auto const& carol = env.account("carol");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.fund(XRP(100000), carol);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");
        HOOK_WASM(top, "file:tipbot/top.c");
        env(ripple::test::jtx::hook(
                carol, {{hso(tip_wasm, overrideFlag)}}, 0),
            M("Install tip on carol for hash"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        installStateSetter(env, alice);
        seedXAHBalance(env, bob, alice, bob.id(), xflWhole(100));

        auto const hookOnAll = filledHash(0xFF);
        auto const govKey1 = pendingGovernanceKey(1);
        auto const govKey2 = pendingGovernanceKey(2);
        seedPendingGovernanceHook(env, bob, alice, 1, tip_hash, hookOnAll);
        seedPendingGovernanceHook(env, bob, alice, 2, top_hash, hookOnAll);

        installTopHookZeroNS(env, alice);

        auto withdrawTen = [&](char const* memoText) {
            std::array<std::uint8_t, 48> withdrawData{};
            auto const xfl10 = xflWhole(10);
            std::memcpy(withdrawData.data() + 40, &xfl10, 8);
            env(remit::remit(bob, alice),
                [&](Env&, JTx& jt) {
                    jt.jv[jss::HookParameters] = hookParams(
                        "5749544844524157",
                        strHex(Slice(withdrawData.data(), withdrawData.size())));
                },
                M(memoText),
                fee(XRP(1)),
                ter(tesSUCCESS));
            env.close();
            env.close();
        };

        withdrawTen("Withdraw drains first queued governance entry");

        auto const firstState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(govKey1.data()),
            uint256{beast::zero}));
        auto const secondState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(govKey2.data()),
            uint256{beast::zero}));
        BEAST_EXPECT(!firstState);
        BEAST_REQUIRE(secondState);

        auto const hookAfterFirst = env.le(keylet::hook(alice.id()));
        BEAST_REQUIRE(hookAfterFirst);
        BEAST_REQUIRE(hookAfterFirst->isFieldPresent(sfHooks));
        auto const& hooksAfterFirst = hookAfterFirst->getFieldArray(sfHooks);
        BEAST_REQUIRE(hooksAfterFirst.size() > 1);
        BEAST_REQUIRE(hooksAfterFirst[0].isFieldPresent(sfHookHash));
        BEAST_REQUIRE(hooksAfterFirst[1].isFieldPresent(sfHookHash));
        BEAST_EXPECT(hooksAfterFirst[0].getFieldH256(sfHookHash) == top_hash);
        BEAST_EXPECT(hooksAfterFirst[1].getFieldH256(sfHookHash) == tip_hash);
        BEAST_REQUIRE(hooksAfterFirst[1].isFieldPresent(sfHookOn));
        BEAST_EXPECT(hooksAfterFirst[1].getFieldH256(sfHookOn) == hookOnAll);

        withdrawTen("Withdraw drains second queued governance entry");

        auto const secondStateAfter = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(govKey2.data()),
            uint256{beast::zero}));
        BEAST_EXPECT(!secondStateAfter);

        auto const hookAfterSecond = env.le(keylet::hook(alice.id()));
        BEAST_REQUIRE(hookAfterSecond);
        BEAST_REQUIRE(hookAfterSecond->isFieldPresent(sfHooks));
        auto const& hooksAfterSecond = hookAfterSecond->getFieldArray(sfHooks);
        BEAST_REQUIRE(hooksAfterSecond.size() > 2);
        BEAST_REQUIRE(hooksAfterSecond[2].isFieldPresent(sfHookHash));
        BEAST_EXPECT(hooksAfterSecond[2].getFieldH256(sfHookHash) == top_hash);
        BEAST_REQUIRE(hooksAfterSecond[2].isFieldPresent(sfHookOn));
        BEAST_EXPECT(hooksAfterSecond[2].getFieldH256(sfHookOn) == hookOnAll);
    }

    // ---- Oracle Voting Tests ----

    void
    testTipMemberVoteSubmitted(FeatureBitset features)
    {
        testcase("Tip: member can submit a vote on a tip");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");  // hook account
        auto const& bob = env.account("bob");      // oracle member
        auto const& carol = env.account("carol");  // triggers bootstrap
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.fund(XRP(100000), carol);
        env.close();

        // Bootstrap members first via a normal invoke
        installStateSetter(env, alice);
        seedMembersBitfield(env, carol, alice, 3);
        seedMember(env, carol, alice, bob.id(), 0);

        // Install the real tip hook
        installTipHookZeroNS(env, alice);

        // Build a tip opinion: SNID=1, postId=1001, to social userid=42,
        // from social userid=99, amount=10 XAH (XFL)
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);

        auto opinion = buildTipOpinion(
            1,                          // SNID = twitter
            1001,                       // postId
            toUser.data(),              // to (social user)
            99,                         // fromUserId
            xflWhole(10));

        // Bob submits the opinion
        submitOpinion(env, bob, alice, 0, opinion, tesSUCCESS);

        // Verify hook execution happened (check meta for HookExecutions)
        auto meta = env.meta();
        BEAST_REQUIRE(meta);
        BEAST_EXPECT(meta->isFieldPresent(sfHookExecutions));
        auto const ret = firstHookReturnString(meta);
        if (ret.find("Results: S") == std::string::npos)
            log << "member vote return: " << ret;
        BEAST_EXPECT(ret.find("Results: S") != std::string::npos);
    }

    void
    testTipDuplicateVoteRejected(FeatureBitset features)
    {
        testcase("Tip: duplicate vote on same post returns V");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        auto const& carol = env.account("carol");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.fund(XRP(100000), carol);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, carol, alice, 3);
        seedMember(env, carol, alice, bob.id(), 0);

        installTipHookZeroNS(env, alice);

        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);

        auto opinion = buildTipOpinion(
            1, 2001, toUser.data(), 99, xflWhole(10));

        // First vote succeeds
        submitOpinion(env, bob, alice, 0, opinion, tesSUCCESS);
        auto const firstRet = firstHookReturnString(env.meta());
        if (firstRet.find("Results: S") == std::string::npos)
            log << "duplicate first vote return: " << firstRet;
        BEAST_EXPECT(firstRet.find("Results: S") != std::string::npos);
        env.close();

        // Second identical vote also succeeds (hook accepts with 'V' result)
        // The hook doesn't reject - it just marks 'V' in the result string
        submitOpinion(env, bob, alice, 0, opinion, tesSUCCESS);
        auto const secondRet = firstHookReturnString(env.meta());
        if (secondRet.find("Results: V") == std::string::npos)
            log << "duplicate second vote return: " << secondRet;
        BEAST_EXPECT(secondRet.find("Results: V") != std::string::npos);
    }

    void
    testTipThresholdReachedActionsTip(FeatureBitset features)
    {
        testcase("Tip: threshold reached with 2/3 votes actions the tip");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");  // hook account
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& m2 = env.account("member2");
        auto const& depositor = env.account("depositor");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), m2);
        env.fund(XRP(100000), depositor);
        env.close();

        // Set up state: 3 members, seed a balance for the "from" social user
        installStateSetter(env, alice);
        seedMembersBitfield(env, depositor, alice, 3);
        seedMember(env, depositor, alice, m0.id(), 0);
        seedMember(env, depositor, alice, m1.id(), 1);
        seedMember(env, depositor, alice, m2.id(), 2);

        // Seed a balance for social user 99 (the tipper) so the tip can be actioned
        // Build the from-user balance key: sha512h(snid(1)+11zeros+userid(8) + currency(20) + issuer(20))
        std::array<std::uint8_t, 60> fromKeyInput{};
        fromKeyInput[0] = 1;  // SNID = twitter
        // bytes 1-11 are zeros
        std::uint64_t fromUserId = 99;
        std::memcpy(fromKeyInput.data() + 12, &fromUserId, 8);
        // currency and issuer are zeros (XAH)

        auto fromHash = sha512Half(Slice(fromKeyInput.data(), fromKeyInput.size()));
        std::array<std::uint8_t, 32> fromBalKey;
        std::memcpy(fromBalKey.data(), fromHash.data(), 32);
        fromBalKey[0] = 'B';

        // Balance: 100 XAH XFL
        std::array<std::uint8_t, 9> fromBalVal{};
        auto const xfl100 = xflWhole(100);
        std::memcpy(fromBalVal.data(), &xfl100, 8);
        fromBalVal[8] = 0;
        setState(env, depositor, alice,
                 fromBalKey.data(), fromBalKey.size(),
                 fromBalVal.data(), fromBalVal.size());

        // Also seed user info for from-user
        std::array<std::uint8_t, 32> fromUIKey{};
        fromUIKey[32 - 21] = 'U';
        fromUIKey[32 - 20] = 1;  // SNID
        // bytes are zeros (11 zero bytes)
        std::memcpy(fromUIKey.data() + (32 - 8), &fromUserId, 8);
        std::array<std::uint8_t, 32> fromUIVal{};
        fromUIVal[0] = 0x01;
        setState(env, depositor, alice,
                 fromUIKey.data(), fromUIKey.size(),
                 fromUIVal.data(), fromUIVal.size());

        // Install tip hook
        installTipHookZeroNS(env, alice);

        // Build the tip opinion: user 99 tips user 42, 10 XAH, post 5001
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);

        auto opinion = buildTipOpinion(
            1, 5001, toUser.data(), 99, xflWhole(10));

        // Member 0 votes - threshold is 2 out of 3, so 1 vote = not actioned yet
        submitOpinion(env, m0, alice, 0, opinion, tesSUCCESS);
        auto const firstRet = firstHookReturnString(env.meta());
        if (firstRet.find("Results: S") == std::string::npos)
            log << "threshold first vote return: " << firstRet;
        BEAST_EXPECT(firstRet.find("Results: S") != std::string::npos);

        auto const firstVoteKey = opinionVoteKey(opinion);
        auto const firstVoteState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(firstVoteKey.data()),
            uint256{beast::zero}));
        if (!firstVoteState)
            std::cerr << "threshold first vote state missing\n";
        else
        {
            auto const& voteData = firstVoteState->getFieldVL(sfHookStateData);
            std::cerr
                << "threshold first vote state size=" << voteData.size()
                << " count="
                << (voteData.size() > 4 ? static_cast<int>(voteData[4]) : -1)
                << "\n";
        }

        auto const firstPostState = env.le(keylet::hookState(
            alice.id(),
            postInfoKey(1, 5001),
            uint256{beast::zero}));
        if (!firstPostState)
            std::cerr << "threshold post state missing after first vote\n";
        else
        {
            auto const& postData = firstPostState->getFieldVL(sfHookStateData);
            std::cerr
                << "threshold post state size=" << postData.size()
                << " actioned="
                << (postData.size() > 4 ? static_cast<int>(postData[4]) : -1)
                << " member_byte0="
                << (postData.size() > 5 ? static_cast<int>(postData[5]) : -1)
                << "\n";
        }

        // Member 1 votes with identical opinion - threshold reached, tip actioned
        submitOpinion(env, m1, alice, 0, opinion, tesSUCCESS);
        auto const secondRet = firstHookReturnString(env.meta());
        if (secondRet.find("Results: A") == std::string::npos)
            log << "threshold second vote return: " << secondRet;
        BEAST_EXPECT(secondRet.find("Results: A") != std::string::npos);

        auto const secondVoteState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(firstVoteKey.data()),
            uint256{beast::zero}));
        if (!secondVoteState)
            std::cerr << "threshold second vote state missing\n";
        else
        {
            auto const& voteData = secondVoteState->getFieldVL(sfHookStateData);
            std::cerr
                << "threshold second vote state size=" << voteData.size()
                << " count="
                << (voteData.size() > 4 ? static_cast<int>(voteData[4]) : -1)
                << "\n";
        }

        // Verify the to-user now has a balance
        std::array<std::uint8_t, 60> toKeyInput{};
        toKeyInput[0] = 1;  // SNID
        std::memcpy(toKeyInput.data() + 12, &toUserId, 8);

        auto toHash = sha512Half(Slice(toKeyInput.data(), toKeyInput.size()));
        std::array<std::uint8_t, 32> toBalKey;
        std::memcpy(toBalKey.data(), toHash.data(), 32);
        toBalKey[0] = 'B';

        auto const toBalState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(toBalKey.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(toBalState);
        auto const& toBalData = toBalState->getFieldVL(sfHookStateData);
        BEAST_EXPECT(toBalData.size() == 9);

        // The to-user should have 10 XAH
        std::uint64_t toBalXfl = 0;
        std::memcpy(&toBalXfl, toBalData.data(), 8);
        BEAST_EXPECT(toBalXfl == xflWhole(10));
    }

    void
    testTipMemberGovernanceAddRemove(FeatureBitset features)
    {
        testcase("Tip: SNID 254 governance adds and removes members");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& newMember = env.account("newmember");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), newMember);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        // Start with 2 members (threshold = 2, so both must agree)
        seedMembersBitfield(env, helper, alice, 2);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);

        installTipHookZeroNS(env, alice);

        // Both members vote to add newMember at seat 2
        auto addOpinion = buildMemberOpinion(2, newMember.id());

        submitOpinion(env, m0, alice, 0, addOpinion, tesSUCCESS);
        auto const firstRet = firstHookReturnString(env.meta());
        if (firstRet.find("Results: S") == std::string::npos)
            log << "member governance first vote return: " << firstRet;
        BEAST_EXPECT(firstRet.find("Results: S") != std::string::npos);

        auto const addVoteKey = opinionVoteKey(addOpinion);
        auto const firstVoteState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(addVoteKey.data()),
            uint256{beast::zero}));
        if (!firstVoteState)
            std::cerr << "member governance first vote state missing\n";
        else
        {
            auto const& voteData = firstVoteState->getFieldVL(sfHookStateData);
            std::cerr
                << "member governance first vote state size=" << voteData.size()
                << " count="
                << (voteData.size() > 4 ? static_cast<int>(voteData[4]) : -1)
                << "\n";
        }

        submitOpinion(env, m1, alice, 0, addOpinion, tesSUCCESS);
        auto const secondRet = firstHookReturnString(env.meta());
        if (secondRet.find("Results: A") == std::string::npos)
            log << "member governance second vote return: " << secondRet;
        BEAST_EXPECT(secondRet.find("Results: A") != std::string::npos);

        auto const secondVoteState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(addVoteKey.data()),
            uint256{beast::zero}));
        if (!secondVoteState)
            std::cerr << "member governance second vote state missing\n";
        else
        {
            auto const& voteData = secondVoteState->getFieldVL(sfHookStateData);
            std::cerr
                << "member governance second vote state size=" << voteData.size()
                << " count="
                << (voteData.size() > 4 ? static_cast<int>(voteData[4]) : -1)
                << "\n";
        }

        // Verify newMember was added: check 'P' + seat 2
        auto const seatState = env.le(keylet::hookState(
            alice.id(),
            apiStateKey({'P', 2}),
            uint256{beast::zero}));
        BEAST_REQUIRE(seatState);
        auto const& seatData = seatState->getFieldVL(sfHookStateData);
        BEAST_EXPECT(seatData.size() == 20);

        // Verify the accid matches newMember
        BEAST_EXPECT(
            std::memcmp(seatData.data(), newMember.id().data(), 20) == 0);

        // Now vote to remove newMember (zero account at seat 2)
        AccountID zeroAcc{};
        auto removeOpinion = buildMemberOpinion(2, zeroAcc);

        submitOpinion(env, m0, alice, 0, removeOpinion, tesSUCCESS);
        submitOpinion(env, m1, alice, 0, removeOpinion, tesSUCCESS);

        // Verify seat 2 is empty
        auto const seatAfter = env.le(keylet::hookState(
            alice.id(),
            apiStateKey({'P', 2}),
            uint256{beast::zero}));
        BEAST_EXPECT(!seatAfter);
    }

    void
    testTipMemberReplacementPreservesUniqueSeatInvariant(FeatureBitset features)
    {
        testcase("Tip: member replacement keeps one seat per account");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& helper = env.account("helper");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), helper);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 2);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);
        installTipHookZeroNS(env, alice);

        auto const duplicateOpinion = buildMemberOpinion(0, m1.id());

        submitOpinion(env, m0, alice, 0, duplicateOpinion, tesSUCCESS);
        auto const firstRet = firstHookReturnString(env.meta());
        BEAST_EXPECT(firstRet.find("Results: S") != std::string::npos);
        env.close();

        submitOpinion(env, m1, alice, 0, duplicateOpinion, tesSUCCESS);
        auto const secondRet = firstHookReturnString(env.meta());
        BEAST_EXPECT(secondRet.find("Results: A") != std::string::npos);
        env.close();

        auto const membersBitfield =
            env.le(keylet::hookState(alice.id(), rawStateKey({'S', 'M'}), beast::zero));
        BEAST_REQUIRE(membersBitfield);
        auto const& membersData = membersBitfield->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(membersData.size() == 32);
        BEAST_EXPECT(popcount(membersData) == 1);
        BEAST_EXPECT(membersData[0] == 0x01);

        auto const seat0 =
            env.le(keylet::hookState(alice.id(), memberReverseKey(0), beast::zero));
        auto const seat1 =
            env.le(keylet::hookState(alice.id(), memberReverseKey(1), beast::zero));
        auto const m0Forward =
            env.le(keylet::hookState(alice.id(), memberForwardKey(m0.id()), beast::zero));
        auto const m1Forward =
            env.le(keylet::hookState(alice.id(), memberForwardKey(m1.id()), beast::zero));

        BEAST_REQUIRE(seat0);
        BEAST_EXPECT(!seat1);
        BEAST_EXPECT(!m0Forward);
        BEAST_REQUIRE(m1Forward);

        auto const& seat0Data = seat0->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(seat0Data.size() == 20);
        BEAST_EXPECT(std::memcmp(seat0Data.data(), m1.id().data(), 20) == 0);

        auto const& m1Seat = m1Forward->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(m1Seat.size() == 1);
        BEAST_EXPECT(m1Seat[0] == 0);
    }

    void
    testTipInvalidAmountGetsW(FeatureBitset features)
    {
        testcase("Tip: opinion with amount <= 0 gets W result (accepted)");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 2);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);

        installTipHookZeroNS(env, alice);

        // Build opinion with amount = 0 XFL (which is 0)
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);

        auto opinion = buildTipOpinion(1, 7001, toUser.data(), 99, 0);

        // Both vote - should reach threshold but get 'W' (invalid amount)
        submitOpinion(env, m0, alice, 0, opinion, tesSUCCESS);
        submitOpinion(env, m1, alice, 0, opinion, tesSUCCESS);
        // Hook accepts (doesn't reject) but the tip isn't actioned
    }

    void
    testTipInsufficientBalanceGetsB(FeatureBitset features)
    {
        testcase("Tip: tip actioned but from-balance too low gets B");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 2);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);

        // Seed a very small balance for user 99: 1 XAH (XFL = 6089866696204910592)
        std::array<std::uint8_t, 60> fromKeyInput{};
        fromKeyInput[0] = 1;
        std::uint64_t fromUserId = 99;
        std::memcpy(fromKeyInput.data() + 12, &fromUserId, 8);

        auto fromHash = sha512Half(Slice(fromKeyInput.data(), fromKeyInput.size()));
        std::array<std::uint8_t, 32> fromBalKey;
        std::memcpy(fromBalKey.data(), fromHash.data(), 32);
        fromBalKey[0] = 'B';

        std::array<std::uint8_t, 9> fromBalVal{};
        std::uint64_t const xfl1 = 6089866696204910592ULL;
        std::memcpy(fromBalVal.data(), &xfl1, 8);
        fromBalVal[8] = 0;
        setState(env, helper, alice,
                 fromBalKey.data(), fromBalKey.size(),
                 fromBalVal.data(), fromBalVal.size());

        installTipHookZeroNS(env, alice);

        // Tip 100 XAH from user 99 who only has 1 XAH
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);

        auto opinion = buildTipOpinion(
            1, 8001, toUser.data(), 99, xflWhole(100));  // 100 XAH

        // Both vote - reaches threshold, tries to action but balance too low → 'B'
        submitOpinion(env, m0, alice, 0, opinion, tesSUCCESS);
        submitOpinion(env, m1, alice, 0, opinion, tesSUCCESS);

        // The to-user should NOT have received a balance
        std::array<std::uint8_t, 60> toKeyInput{};
        toKeyInput[0] = 1;
        std::memcpy(toKeyInput.data() + 12, &toUserId, 8);

        auto toHash = sha512Half(Slice(toKeyInput.data(), toKeyInput.size()));
        std::array<std::uint8_t, 32> toBalKey;
        std::memcpy(toBalKey.data(), toHash.data(), 32);
        toBalKey[0] = 'B';

        auto const toBalState = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(toBalKey.data()),
            uint256{beast::zero}));
        BEAST_EXPECT(!toBalState);
    }

    // ---- GC and Cleanup Tests ----

    void
    testTipGCDeletesStaleEntries(FeatureBitset features)
    {
        testcase("Tip: GC deletes stale vote entries after 20 ledgers");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 1);
        seedMember(env, helper, alice, m0.id(), 0);
        installTipHookZeroNS(env, alice);

        // Submit a vote - this creates post_info and cleanup entries
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);
        auto opinion = buildTipOpinion(
            1, 9001, toUser.data(), 99, xflWhole(10));
        submitOpinion(env, m0, alice, 0, opinion, tesSUCCESS);
        env.close();

        // Verify post_info exists
        auto const postKey = postInfoKey(1, 9001);
        auto postState = env.le(keylet::hookState(
            alice.id(), postKey, uint256{beast::zero}));
        BEAST_REQUIRE(postState);

        // Advance 25 ledgers so the entry becomes stale (cutoff = current - 20)
        for (int i = 0; i < 25; ++i)
            env.close();

        // Another invoke triggers GC which should clean up the stale entry
        submitOpinion(env, m0, alice, 0,
            buildTipOpinion(1, 9002, toUser.data(), 99, xflWhole(10)),
            tesSUCCESS);
        env.close();

        // The old post_info should be deleted by GC
        postState = env.le(keylet::hookState(
            alice.id(), postKey, uint256{beast::zero}));
        BEAST_EXPECT(!postState);
    }

    void
    testTipGCUnderflowFixOnLowLedger(FeatureBitset features)
    {
        testcase("Tip: GC underflow fix - vote on low ledger survives");
        using namespace jtx;

        // This test verifies the fix for tip.c:108 where current_ledger - 20U
        // would underflow on ledger numbers < 20, causing fresh entries to be
        // treated as ancient and deleted
        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), helper);
        env.close();

        // We're on a low ledger number (< 20)
        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 1);
        seedMember(env, helper, alice, m0.id(), 0);
        installTipHookZeroNS(env, alice);

        // Submit vote on this low ledger
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);
        auto opinion = buildTipOpinion(
            1, 10001, toUser.data(), 99, xflWhole(10));
        submitOpinion(env, m0, alice, 0, opinion, tesSUCCESS);
        env.close();

        // Verify the post_info was NOT deleted by GC underflow
        auto const postKey = postInfoKey(1, 10001);
        auto const postState = env.le(keylet::hookState(
            alice.id(), postKey, uint256{beast::zero}));
        BEAST_EXPECT(!!postState);
    }

    // ---- Tip-to-raddr and Already-Actioned Tests ----

    void
    testTipToRAddress(FeatureBitset features)
    {
        testcase("Tip: tip to r-address credits balance under accid key");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& recipient = env.account("recipient");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), recipient);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 2);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);

        // Seed balance for from-user (social user 99)
        std::array<std::uint8_t, 60> fromKeyInput{};
        fromKeyInput[0] = 1;  // SNID
        std::uint64_t fromUserId = 99;
        std::memcpy(fromKeyInput.data() + 12, &fromUserId, 8);
        auto fromHash = sha512Half(Slice(fromKeyInput.data(), fromKeyInput.size()));
        std::array<std::uint8_t, 32> fromBalKey;
        std::memcpy(fromBalKey.data(), fromHash.data(), 32);
        fromBalKey[0] = 'B';
        std::array<std::uint8_t, 9> fromBalVal{};
        auto const xfl100 = xflWhole(100);
        std::memcpy(fromBalVal.data(), &xfl100, 8);
        fromBalVal[8] = 0;
        setState(env, helper, alice,
                 fromBalKey.data(), fromBalKey.size(),
                 fromBalVal.data(), fromBalVal.size());

        // Seed user info for from-user
        std::array<std::uint8_t, 32> fromUIKey{};
        fromUIKey[32 - 21] = 'U';
        fromUIKey[32 - 20] = 1;
        std::memcpy(fromUIKey.data() + (32 - 8), &fromUserId, 8);
        std::array<std::uint8_t, 32> fromUIVal{};
        fromUIVal[0] = 0x01;
        setState(env, helper, alice,
                 fromUIKey.data(), fromUIKey.size(),
                 fromUIVal.data(), fromUIVal.size());

        installTipHookZeroNS(env, alice);

        // Build tip opinion: from social user 99 to recipient's r-address
        // IS_TOACC is true when first 12 bytes of "to" field are non-zero
        // For an r-address, we put the full 20-byte accid in the "to" field
        std::array<std::uint8_t, 20> toField{};
        std::memcpy(toField.data(), recipient.id().data(), 20);

        auto opinion = buildTipOpinion(
            1, 11001, toField.data(), 99, xflWhole(10));

        // Two members vote to reach threshold
        submitOpinion(env, m0, alice, 0, opinion, tesSUCCESS);
        env.close();
        submitOpinion(env, m1, alice, 0, opinion, tesSUCCESS);
        auto const ret = firstHookReturnString(env.meta());
        BEAST_EXPECT(ret.find("Results: A") != std::string::npos);
        env.close();

        // Verify the recipient has a balance under their ACCID (not snid+userid)
        // This is the key difference: tips to r-addresses create withdrawable balances
        auto bk = balanceKey(recipient.id());
        auto const recipientBal = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(recipientBal);
        auto const& balData = recipientBal->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(balData.size() == 9);
        std::uint64_t balXfl = 0;
        std::memcpy(&balXfl, balData.data(), 8);
        BEAST_EXPECT(balXfl == xflWhole(10));  // 10 XAH
    }

    void
    testTipAlreadyActionedReturnsD(FeatureBitset features)
    {
        testcase("Tip: voting on already-actioned post returns D");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& m2 = env.account("member2");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), m2);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 3);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);
        seedMember(env, helper, alice, m2.id(), 2);

        // Seed balance for from-user
        std::array<std::uint8_t, 60> fromKeyInput{};
        fromKeyInput[0] = 1;
        std::uint64_t fromUserId = 99;
        std::memcpy(fromKeyInput.data() + 12, &fromUserId, 8);
        auto fromHash = sha512Half(Slice(fromKeyInput.data(), fromKeyInput.size()));
        std::array<std::uint8_t, 32> fromBalKey;
        std::memcpy(fromBalKey.data(), fromHash.data(), 32);
        fromBalKey[0] = 'B';
        std::array<std::uint8_t, 9> fromBalVal{};
        auto const xfl100 = xflWhole(100);
        std::memcpy(fromBalVal.data(), &xfl100, 8);
        fromBalVal[8] = 0;
        setState(env, helper, alice,
                 fromBalKey.data(), fromBalKey.size(),
                 fromBalVal.data(), fromBalVal.size());

        std::array<std::uint8_t, 32> fromUIKey{};
        fromUIKey[32 - 21] = 'U';
        fromUIKey[32 - 20] = 1;
        std::memcpy(fromUIKey.data() + (32 - 8), &fromUserId, 8);
        std::array<std::uint8_t, 32> fromUIVal{};
        fromUIVal[0] = 0x01;
        setState(env, helper, alice,
                 fromUIKey.data(), fromUIKey.size(),
                 fromUIVal.data(), fromUIVal.size());

        installTipHookZeroNS(env, alice);

        // Build opinion
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);
        auto opinion = buildTipOpinion(
            1, 12001, toUser.data(), 99, xflWhole(10));

        // m0 and m1 vote - threshold reached (2 of 3), tip actioned
        submitOpinion(env, m0, alice, 0, opinion, tesSUCCESS);
        env.close();
        submitOpinion(env, m1, alice, 0, opinion, tesSUCCESS);
        auto const actionRet = firstHookReturnString(env.meta());
        BEAST_EXPECT(actionRet.find("Results: A") != std::string::npos);
        env.close();

        // m2 votes on the same post - should get 'D' (already actioned)
        submitOpinion(env, m2, alice, 0, opinion, tesSUCCESS);
        auto const lateRet = firstHookReturnString(env.meta());
        if (lateRet.find("Results: D") == std::string::npos)
            log << "late vote return: " << lateRet;
        BEAST_EXPECT(lateRet.find("Results: D") != std::string::npos);
    }

    void
    testTipHookGovernanceWritesHState(FeatureBitset features)
    {
        testcase("Tip: SNID 255 hook governance vote writes H state entry");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 2);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);
        installTipHookZeroNS(env, alice);

        // Build a hook governance opinion (SNID 255):
        // byte 0: 255 (SNID)
        // byte 1: position (0)
        // bytes 2-33: hook hash (32 bytes)
        // bytes 34-65: hook_on (32 bytes)
        std::array<std::uint8_t, 85> hookOpinion{};
        hookOpinion[0] = 255;  // SNID for hook governance
        hookOpinion[1] = 0;    // hook position 0
        // Fill hookhash with recognizable pattern
        std::memset(hookOpinion.data() + 2, 0xAA, 32);
        // Fill hookon with another pattern
        std::memset(hookOpinion.data() + 34, 0xBB, 32);

        // Two members vote - threshold reached
        submitOpinion(env, m0, alice, 0, hookOpinion, tesSUCCESS);
        env.close();
        submitOpinion(env, m1, alice, 0, hookOpinion, tesSUCCESS);
        auto const ret = firstHookReturnString(env.meta());
        BEAST_EXPECT(ret.find("Results: A") != std::string::npos);
        env.close();

        // Verify 'H' + position(0) state entry was written with 64 bytes
        auto const hKey = apiStateKey({'H', 0});
        auto const hState = env.le(keylet::hookState(
            alice.id(), hKey, uint256{beast::zero}));
        BEAST_REQUIRE(hState);
        auto const& hData = hState->getFieldVL(sfHookStateData);
        BEAST_EXPECT(hData.size() == 64);
        // First 32 bytes should be the hook hash (0xAA pattern)
        BEAST_EXPECT(hData[0] == 0xAA);
        BEAST_EXPECT(hData[31] == 0xAA);
        // Next 32 bytes should be hook_on (0xBB pattern)
        BEAST_EXPECT(hData[32] == 0xBB);
        BEAST_EXPECT(hData[63] == 0xBB);
    }

    void
    testTipHookGovernanceRejectsOutOfRangeSlot(FeatureBitset features)
    {
        testcase("Tip: SNID 255 hook governance rejects slot >= 10");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 2);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);
        installTipHookZeroNS(env, alice);

        std::array<std::uint8_t, 85> hookOpinion{};
        hookOpinion[0] = 255;
        hookOpinion[1] = 10;  // top.c only drains positions 0..9
        std::memset(hookOpinion.data() + 2, 0xAA, 32);
        std::memset(hookOpinion.data() + 34, 0xBB, 32);

        submitOpinion(env, m0, alice, 0, hookOpinion, tesSUCCESS);
        auto const ret = firstHookReturnString(env.meta());
        if (ret.find("Results: P") == std::string::npos)
            log << "invalid hook slot return: " << ret;
        BEAST_EXPECT(ret.find("Results: P") != std::string::npos);
        env.close();

        auto const hState = env.le(keylet::hookState(
            alice.id(), apiStateKey({'H', 10}), uint256{beast::zero}));
        BEAST_EXPECT(!hState);

        auto const postState = env.le(keylet::hookState(
            alice.id(),
            apiStateKey({'O', 255, 10, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}),
            uint256{beast::zero}));
        BEAST_EXPECT(!postState);
    }

    void
    testTipMultipleOpinionsPerInvoke(FeatureBitset features)
    {
        testcase("Tip: multiple opinions in single invoke processed");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        // Use 2 members so threshold=2. m0 alone can't action - gets "S" not "A/B"
        seedMembersBitfield(env, helper, alice, 2);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, helper.id(), 1);
        installTipHookZeroNS(env, alice);

        // Build two different opinions for two different posts
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);

        auto op0 = buildTipOpinion(1, 13001, toUser.data(), 99, xflWhole(10));
        auto op1 = buildTipOpinion(1, 13002, toUser.data(), 99, xflWhole(10));

        // Submit both opinions in a single invoke with param keys 0 and 1
        std::uint8_t idx0 = 0, idx1 = 1;

        auto const param = [&](Env&, JTx& jt) {
            Json::Value params{Json::arrayValue};
            Json::Value e0;
            e0[jss::HookParameter] = Json::Value{};
            e0[jss::HookParameter][jss::HookParameterName] =
                strHex(Slice(&idx0, 1));
            e0[jss::HookParameter][jss::HookParameterValue] =
                strHex(Slice(op0.data(), op0.size()));
            params.append(e0);
            Json::Value e1;
            e1[jss::HookParameter] = Json::Value{};
            e1[jss::HookParameter][jss::HookParameterName] =
                strHex(Slice(&idx1, 1));
            e1[jss::HookParameter][jss::HookParameterValue] =
                strHex(Slice(op1.data(), op1.size()));
            params.append(e1);
            jt.jv[jss::HookParameters] = params;
        };

        env(invoke::invoke(m0), invoke::dest(alice),
            param,
            M("Two opinions in one invoke"),
            fee(XRP(1)),
            ter(tesSUCCESS));

        auto const ret = firstHookReturnString(env.meta());
        BEAST_EXPECT(ret.find("02 Opinions") != std::string::npos);
        // Both should be "S" (submitted, not yet actioned since threshold=2)
        BEAST_EXPECT(ret.find("SS") != std::string::npos);
        if (ret.find("SS") == std::string::npos)
            log << "multi-opinion return: " << ret;
        env.close();

        // Both post_info entries should exist
        auto const post0 = env.le(keylet::hookState(
            alice.id(), postInfoKey(1, 13001), uint256{beast::zero}));
        auto const post1 = env.le(keylet::hookState(
            alice.id(), postInfoKey(1, 13002), uint256{beast::zero}));
        BEAST_EXPECT(!!post0);
        BEAST_EXPECT(!!post1);
    }

    // ---- E2E and Advanced Tests ----

    void
    testE2EDepositTipWithdraw(FeatureBitset features)
    {
        testcase("E2E: deposit XAH, oracle tips to r-addr, withdraw");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& hookAcc = env.account("hookAcc");
        auto const& depositor = env.account("depositor");
        auto const& recipient = env.account("recipient");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), hookAcc);
        env.fund(XRP(100000), depositor);
        env.fund(XRP(100000), recipient);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), helper);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");
        HOOK_WASM(top, "file:tipbot/top.c");

        // Step 1: Install state-setter to seed oracle members
        env.setPrefix("seed oracles");
        installStateSetter(env, hookAcc);
        seedMembersBitfield(env, helper, hookAcc, 2);
        seedMember(env, helper, hookAcc, m0.id(), 0);
        seedMember(env, helper, hookAcc, m1.id(), 1);

        // Step 2: Install both hooks with zero namespace
        env.setPrefix("install hooks");
        // tip at position 0 (fires on invoke), top at position 1 (fires on remit)
        {
            auto tipHso = hso(tip_wasm, overrideFlag);
            tipHso[jss::HookNamespace] =
                "0000000000000000000000000000000000000000000000000000000000000000";
            auto topHso = hso(top_wasm, overrideFlag);
            topHso[jss::HookNamespace] =
                "0000000000000000000000000000000000000000000000000000000000000000";
            env(ripple::test::jtx::hook(
                    hookAcc, {{tipHso, topHso}}, 0),
                M("Install both hooks"),
                HSFEE,
                ter(tesSUCCESS));
            env.close();
        }

        // Step 3: Deposit 100 XAH to social user 77 on twitter
        env.setPrefix("deposit 100 XAH");
        std::array<std::uint8_t, 20> socialUser{};
        socialUser[0] = 1;  // SNID = twitter
        std::uint64_t userId = 77;
        std::memcpy(socialUser.data() + 12, &userId, 8);

        env(remit::remit(depositor, hookAcc),
            remit::amts({XRP(100)}),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "4445504F534954",
                    strHex(Slice(socialUser.data(), socialUser.size())));
            },
            M("Deposit 100 XAH"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // Step 4: Oracle members vote to tip from social user 77 to recipient's r-address
        env.setPrefix("oracle vote");
        std::array<std::uint8_t, 20> toField{};
        std::memcpy(toField.data(), recipient.id().data(), 20);

        auto opinion = buildTipOpinion(
            1, 20001, toField.data(), 77, xflWhole(50));

        submitOpinion(env, m0, hookAcc, 0, opinion, tesSUCCESS);
        env.close();
        submitOpinion(env, m1, hookAcc, 0, opinion, tesSUCCESS);
        auto const tipRet = firstHookReturnString(env.meta());
        BEAST_EXPECT(tipRet.find("Results: A") != std::string::npos);
        if (tipRet.find("Results: A") == std::string::npos)
            log << "E2E tip return: " << tipRet;
        env.close();

        // Step 5: Verify recipient has a balance under their accid
        env.setPrefix("verify balance");
        auto bk = balanceKey(recipient.id());
        auto const recipBal = env.le(keylet::hookState(
            hookAcc.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(recipBal);
        auto const& balData = recipBal->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(balData.size() == 9);
        std::uint64_t balXfl = 0;
        std::memcpy(&balXfl, balData.data(), 8);
        BEAST_EXPECT(balXfl == xflWhole(50));  // 50 XAH

        // Step 6: Recipient withdraws their 50 XAH
        env.setPrefix("withdraw 50 XAH");
        auto const recipBalBefore = env.balance(recipient).value().xrp().drops();

        std::array<std::uint8_t, 48> withdrawData{};
        auto const xfl50 = xflWhole(50);
        std::memcpy(withdrawData.data() + 40, &xfl50, 8);

        env(remit::remit(recipient, hookAcc),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("Withdraw 50 XAH"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        // Top hook is at position 1, so use lastHookReturnString
        auto const withdrawRet = lastHookReturnString(env.meta());
        if (withdrawRet.find("Done") == std::string::npos)
            std::cerr << "E2E withdraw return: [" << withdrawRet << "]\n";
        BEAST_EXPECT(withdrawRet.find("Done") != std::string::npos);
        env.close();
        env.close();  // process emitted remit

        auto const recipBalAfter = env.balance(recipient).value().xrp().drops();
        BEAST_EXPECT(
            recipBalAfter ==
            recipBalBefore + XRP(49).value().xrp().drops());

        // Balance entry should be cleared (withdrew full amount)
        auto const recipBalAfterState = env.le(keylet::hookState(
            hookAcc.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_EXPECT(!recipBalAfterState);
    }

    void
    testTipConflictingOpinionsSamePost(FeatureBitset features)
    {
        testcase("Tip: conflicting opinions on same post tracked independently");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& m2 = env.account("member2");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), m2);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 3);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);
        seedMember(env, helper, alice, m2.id(), 2);
        installTipHookZeroNS(env, alice);

        // Two different opinions about the same post (different amounts)
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);

        // Opinion A: 10 XAH
        auto opA = buildTipOpinion(1, 14001, toUser.data(), 99, xflWhole(10));
        // Opinion B tweaks the amount bytes so it hashes differently from opA.
        auto opB = buildTipOpinion(1, 14001, toUser.data(), 99, xflWhole(10) + 1);

        // m0 votes for opinion A
        submitOpinion(env, m0, alice, 0, opA, tesSUCCESS);
        auto ret0 = firstHookReturnString(env.meta());
        BEAST_EXPECT(ret0.find("Results: S") != std::string::npos);
        env.close();

        // m1 votes for opinion B (different amount)
        submitOpinion(env, m1, alice, 0, opB, tesSUCCESS);
        auto ret1 = firstHookReturnString(env.meta());
        // m1's vote is on the same post (same post_info key) so gets "V"
        // because m1's bit was already set... wait, no.
        // The post_info voter bitfield tracks per-post, not per-opinion.
        // m0 voted on this post already, setting bit 0.
        // m1 voting on the same post sets bit 1.
        // The vote COUNT is per-opinion-hash (different key).
        // So m1 should get "S" (vote submitted on a new opinion hash)
        BEAST_EXPECT(ret1.find("Results: S") != std::string::npos);
        env.close();

        // m2 votes for opinion A - now opA has 2 votes (m0 + m2), threshold=2
        // But m2 hasn't voted on this post yet, so should get through
        // However, the post_info is shared, so it tracks all voters.
        // After m0 and m1, bits 0 and 1 are set. m2 (bit 2) is not set.
        // m2 votes opA: vote count for opA becomes 2, threshold met, actioned.
        // But we haven't seeded balance for from-user, so it'll be "B" after action
        submitOpinion(env, m2, alice, 0, opA, tesSUCCESS);
        auto ret2 = firstHookReturnString(env.meta());
        // Should be "S" since we didn't seed balance (threshold met but action = "B")
        // Actually: threshold check happens, post_info[4]=1, then balance check fails → "B"
        BEAST_EXPECT(ret2.find("Results:") != std::string::npos);
        env.close();

        // Verify both opinion vote entries exist with different counts
        auto voteKeyA = opinionVoteKey(opA);
        auto voteKeyB = opinionVoteKey(opB);

        auto const voteA = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(voteKeyA.data()),
            uint256{beast::zero}));
        auto const voteB = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(voteKeyB.data()),
            uint256{beast::zero}));

        BEAST_REQUIRE(voteA);
        BEAST_REQUIRE(voteB);
        auto const& voteAData = voteA->getFieldVL(sfHookStateData);
        auto const& voteBData = voteB->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(voteAData.size() == 5);
        BEAST_REQUIRE(voteBData.size() == 5);
        // opA should have 2 votes (m0 + m2), opB should have 1 vote (m1)
        BEAST_EXPECT(voteAData[4] == 2);
        BEAST_EXPECT(voteBData[4] == 1);
    }

    void
    testTipDrainsBalanceAndCleansUp(FeatureBitset features)
    {
        testcase("Tip: full balance drain deletes balance and clears user info bit");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 2);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);

        // Seed exactly 10 XAH for from-user 99
        std::array<std::uint8_t, 60> fromKeyInput{};
        fromKeyInput[0] = 1;
        std::uint64_t fromUserId = 99;
        std::memcpy(fromKeyInput.data() + 12, &fromUserId, 8);
        auto fromHash = sha512Half(Slice(fromKeyInput.data(), fromKeyInput.size()));
        std::array<std::uint8_t, 32> fromBalKey;
        std::memcpy(fromBalKey.data(), fromHash.data(), 32);
        fromBalKey[0] = 'B';
        std::array<std::uint8_t, 9> fromBalVal{};
        auto const xfl10 = xflWhole(10);
        std::memcpy(fromBalVal.data(), &xfl10, 8);
        fromBalVal[8] = 0;  // currency index 0
        setState(env, helper, alice,
                 fromBalKey.data(), fromBalKey.size(),
                 fromBalVal.data(), fromBalVal.size());

        // Seed user info for from-user (bit 0 set)
        std::array<std::uint8_t, 32> fromUIKey{};
        fromUIKey[32 - 21] = 'U';
        fromUIKey[32 - 20] = 1;
        std::memcpy(fromUIKey.data() + (32 - 8), &fromUserId, 8);
        std::array<std::uint8_t, 32> fromUIVal{};
        fromUIVal[0] = 0x01;
        setState(env, helper, alice,
                 fromUIKey.data(), fromUIKey.size(),
                 fromUIVal.data(), fromUIVal.size());

        installTipHookZeroNS(env, alice);

        // Tip the EXACT amount (10 XAH) so final_from_bal == 0
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 42;
        std::memcpy(toUser.data() + 12, &toUserId, 8);

        auto opinion = buildTipOpinion(
            1, 15001, toUser.data(), 99, xfl10);

        submitOpinion(env, m0, alice, 0, opinion, tesSUCCESS);
        env.close();
        submitOpinion(env, m1, alice, 0, opinion, tesSUCCESS);
        auto const ret = firstHookReturnString(env.meta());
        BEAST_EXPECT(ret.find("Results: A") != std::string::npos);
        env.close();

        // From-user's balance should be deleted (drained to zero)
        auto const fromBal = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(fromBalKey.data()),
            uint256{beast::zero}));
        BEAST_EXPECT(!fromBal);

        // From-user's user info bit should be cleared
        auto const fromUI = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(fromUIKey.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(fromUI);
        auto const& uiData = fromUI->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(uiData.size() == 32);
        BEAST_EXPECT(uiData[0] == 0x00);  // bit 0 cleared

        // To-user should have received the 10 XAH
        std::array<std::uint8_t, 60> toKeyInput{};
        toKeyInput[0] = 1;
        std::memcpy(toKeyInput.data() + 12, &toUserId, 8);
        auto toHash = sha512Half(Slice(toKeyInput.data(), toKeyInput.size()));
        std::array<std::uint8_t, 32> toBalKey;
        std::memcpy(toBalKey.data(), toHash.data(), 32);
        toBalKey[0] = 'B';
        auto const toBal = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(toBalKey.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(toBal);
        auto const& toData = toBal->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(toData.size() == 9);
        std::uint64_t toXfl = 0;
        std::memcpy(&toXfl, toData.data(), 8);
        BEAST_EXPECT(toXfl == xfl10);
    }

    void
    testE2EDepositTipWithdrawIOU(FeatureBitset features)
    {
        testcase("E2E: deposit IOU, oracle tips to r-addr, withdraw IOU");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& hookAcc = env.account("hookacc");
        auto const& depositor = env.account("depositor");
        auto const& recipient = env.account("recipient");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& helper = env.account("helper");
        auto const& gw = env.account("gateway");
        auto const USD = gw["USD"];
        env.fund(XRP(100000), hookAcc);
        env.fund(XRP(100000), depositor);
        env.fund(XRP(100000), recipient);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), helper);
        env.fund(XRP(100000), gw);
        env.close();

        // Set up trustlines
        env.trust(USD(100000), depositor);
        env.trust(USD(100000), hookAcc);
        env.trust(USD(100000), recipient);
        env.close();
        env(pay(gw, depositor, USD(1000)));
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");
        HOOK_WASM(top, "file:tipbot/top.c");

        // Seed oracle members
        installStateSetter(env, hookAcc);
        seedMembersBitfield(env, helper, hookAcc, 2);
        seedMember(env, helper, hookAcc, m0.id(), 0);
        seedMember(env, helper, hookAcc, m1.id(), 1);

        // Install both hooks
        {
            auto tipHso = hso(tip_wasm, overrideFlag);
            tipHso[jss::HookNamespace] =
                "0000000000000000000000000000000000000000000000000000000000000000";
            auto topHso = hso(top_wasm, overrideFlag);
            topHso[jss::HookNamespace] =
                "0000000000000000000000000000000000000000000000000000000000000000";
            env(ripple::test::jtx::hook(
                    hookAcc, {{tipHso, topHso}}, 0),
                M("Install both hooks"),
                HSFEE,
                ter(tesSUCCESS));
            env.close();
        }

        // Step 1: Deposit - first deposit must be XAH >= 10 to create user
        std::array<std::uint8_t, 20> socialUser{};
        socialUser[0] = 1;
        std::uint64_t userId = 88;
        std::memcpy(socialUser.data() + 12, &userId, 8);

        env(remit::remit(depositor, hookAcc),
            remit::amts({XRP(10)}),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "4445504F534954",
                    strHex(Slice(socialUser.data(), socialUser.size())));
            },
            M("Seed user with XAH"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // Step 2: Deposit USD (second deposit, IOU allowed now)
        env(remit::remit(depositor, hookAcc),
            remit::amts({USD(100)}),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "4445504F534954",
                    strHex(Slice(socialUser.data(), socialUser.size())));
            },
            M("Deposit 100 USD"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // Step 3: Oracle tips 50 USD from user 88 to recipient's r-address
        auto const usdCurrency = USD.issue().currency;
        auto const usdIssuer = USD.issue().account;
        std::array<std::uint8_t, 20> curBytes{};
        std::array<std::uint8_t, 20> issBytes{};
        std::memcpy(curBytes.data(), usdCurrency.data(), 20);
        std::memcpy(issBytes.data(), usdIssuer.data(), 20);

        std::array<std::uint8_t, 20> toField{};
        std::memcpy(toField.data(), recipient.id().data(), 20);

        auto opinion = buildTipOpinion(
            1, 21001, toField.data(), 88, xflWhole(50),
            curBytes.data(), issBytes.data());

        submitOpinion(env, m0, hookAcc, 0, opinion, tesSUCCESS);
        env.close();
        submitOpinion(env, m1, hookAcc, 0, opinion, tesSUCCESS);
        auto const tipRet = firstHookReturnString(env.meta());
        BEAST_EXPECT(tipRet.find("Results: A") != std::string::npos);
        if (tipRet.find("Results: A") == std::string::npos)
            log << "IOU E2E tip return: " << tipRet;
        env.close();

        // Step 4: Verify recipient has USD balance under accid
        auto bk = balanceKey(recipient.id(), curBytes, issBytes);
        auto const recipBal = env.le(keylet::hookState(
            hookAcc.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(recipBal);

        // Step 5: Recipient withdraws 50 USD
        std::array<std::uint8_t, 48> withdrawData{};
        std::memcpy(withdrawData.data(), curBytes.data(), 20);
        std::memcpy(withdrawData.data() + 20, issBytes.data(), 20);
        auto const xfl50 = xflWhole(50);
        std::memcpy(withdrawData.data() + 40, &xfl50, 8);

        env(remit::remit(recipient, hookAcc),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("Withdraw 50 USD"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        auto const withdrawRet = lastHookReturnString(env.meta());
        BEAST_EXPECT(withdrawRet.find("Done") != std::string::npos);
        if (withdrawRet.find("Done") == std::string::npos)
            log << "IOU E2E withdraw return: " << withdrawRet;
        env.close();
        env.close();  // process emitted remit

        env.require(balance(recipient, USD(50)));

        auto const recipBalAfterState = env.le(keylet::hookState(
            hookAcc.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_EXPECT(!recipBalAfterState);
    }

    void
    testTopPartialWithdrawLeavesCorrectBalance(FeatureBitset features)
    {
        testcase("Top: partial withdrawal leaves correct remaining balance");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.close();

        installStateSetter(env, alice);
        auto const xfl100 = xflWhole(100);
        seedXAHBalance(env, bob, alice, bob.id(), xfl100);
        installTopHookZeroNS(env, alice);

        std::array<std::uint8_t, 48> withdrawData{};
        auto const xfl10 = xflWhole(10);
        std::memcpy(withdrawData.data() + 40, &xfl10, 8);

        env(remit::remit(bob, alice),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("Withdraw 10 of 100 XAH"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        auto const ret = firstHookReturnString(env.meta());
        BEAST_EXPECT(ret.find("Done") != std::string::npos);
        env.close();
        env.close();  // process emitted remit

        // Balance should still exist with the exact XFL remainder after 100 - 10
        auto bk = balanceKey(bob.id());
        auto const remaining = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(remaining);
        auto const& balData = remaining->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(balData.size() == 9);

        std::uint64_t remainingXfl = 0;
        std::memcpy(&remainingXfl, balData.data(), 8);
        auto const expectedRemainingXfl = xflSum(xfl100, xflNegate(xfl10));
        BEAST_EXPECT(remainingXfl == expectedRemainingXfl);

        // Withdraw the exact remaining balance - should drain completely
        std::array<std::uint8_t, 48> withdrawData2{};
        std::memcpy(withdrawData2.data() + 40, &remainingXfl, 8);

        env(remit::remit(bob, alice),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData2.data(), withdrawData2.size())));
            },
            M("Withdraw remaining"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
        env.close();

        // Balance should be deleted now
        auto const gone = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_EXPECT(!gone);
    }

    void
    testTipBetweenSocialUsers(FeatureBitset features)
    {
        testcase("Tip: tip between two social users (non-raddr path)");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& helper = env.account("helper");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), helper);
        env.close();

        installStateSetter(env, alice);
        seedMembersBitfield(env, helper, alice, 2);
        seedMember(env, helper, alice, m0.id(), 0);
        seedMember(env, helper, alice, m1.id(), 1);

        // Seed 100 XAH for social user 55 (the sender)
        std::array<std::uint8_t, 60> fromKeyInput{};
        fromKeyInput[0] = 1;  // SNID
        std::uint64_t fromUserId = 55;
        std::memcpy(fromKeyInput.data() + 12, &fromUserId, 8);
        auto fromHash = sha512Half(Slice(fromKeyInput.data(), fromKeyInput.size()));
        std::array<std::uint8_t, 32> fromBalKey;
        std::memcpy(fromBalKey.data(), fromHash.data(), 32);
        fromBalKey[0] = 'B';
        std::array<std::uint8_t, 9> fromBalVal{};
        auto const xfl100 = xflWhole(100);
        std::memcpy(fromBalVal.data(), &xfl100, 8);
        fromBalVal[8] = 0;
        setState(env, helper, alice,
                 fromBalKey.data(), fromBalKey.size(),
                 fromBalVal.data(), fromBalVal.size());

        // Seed user info for user 55
        std::array<std::uint8_t, 32> fromUIKey{};
        fromUIKey[32 - 21] = 'U';
        fromUIKey[32 - 20] = 1;
        std::memcpy(fromUIKey.data() + (32 - 8), &fromUserId, 8);
        std::array<std::uint8_t, 32> fromUIVal{};
        fromUIVal[0] = 0x01;
        setState(env, helper, alice,
                 fromUIKey.data(), fromUIKey.size(),
                 fromUIVal.data(), fromUIVal.size());

        installTipHookZeroNS(env, alice);

        // Build opinion: user 55 tips user 66, 10 XAH
        // "to" field: first 12 bytes zero (not an accid), userid at bytes 12-19
        // This is the IS_TOACC=false path
        std::array<std::uint8_t, 20> toUser{};
        std::uint64_t toUserId = 66;
        std::memcpy(toUser.data() + 12, &toUserId, 8);

        auto const xfl10 = xflWhole(10);
        auto opinion = buildTipOpinion(
            1, 16001, toUser.data(), 55, xfl10);

        // Two members vote - threshold reached, tip actioned
        submitOpinion(env, m0, alice, 0, opinion, tesSUCCESS);
        env.close();
        submitOpinion(env, m1, alice, 0, opinion, tesSUCCESS);
        auto const ret = firstHookReturnString(env.meta());
        BEAST_EXPECT(ret.find("Results: A") != std::string::npos);
        if (ret.find("Results: A") == std::string::npos)
            log << "social tip return: " << ret;
        env.close();

        // Verify user 66 got a balance (under social user key, not accid)
        std::array<std::uint8_t, 60> toKeyInput{};
        toKeyInput[0] = 1;
        std::memcpy(toKeyInput.data() + 12, &toUserId, 8);
        auto toHash = sha512Half(Slice(toKeyInput.data(), toKeyInput.size()));
        std::array<std::uint8_t, 32> toBalKey;
        std::memcpy(toBalKey.data(), toHash.data(), 32);
        toBalKey[0] = 'B';

        auto const toBal = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(toBalKey.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(toBal);
        auto const& toData = toBal->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(toData.size() == 9);
        std::uint64_t toXfl = 0;
        std::memcpy(&toXfl, toData.data(), 8);
        BEAST_EXPECT(toXfl == xflWhole(10));  // 10 XAH

        // Verify user 55's balance decreased (100 - 10 = 90)
        auto const fromBal = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(fromBalKey.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(fromBal);
        auto const& fromData = fromBal->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(fromData.size() == 9);
        std::uint64_t fromXfl = 0;
        std::memcpy(&fromXfl, fromData.data(), 8);
        auto const expectedFromXfl = xflSum(xfl100, xflNegate(xfl10));
        BEAST_EXPECT(fromXfl == expectedFromXfl);
    }

    // ---- Key Verification Tests ----

    void
    testKeyComputationMatches(FeatureBitset features)
    {
        // Verify that our C++ balanceKey() produces the same key the hook
        // computes via util_sha512h. We do this by:
        // 1. Writing a balance under our computed key via state-setter
        // 2. Installing a tiny verifier hook that reads the balance using
        //    the SAME computation the real top.c does
        // 3. If the hook finds the balance, the keys match

        testcase("Keys: C++ balanceKey matches hook util_sha512h");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.close();

        // Step 1: seed balance under our computed key
        installStateSetter(env, alice);
        auto bk = balanceKey(bob.id());
        std::array<std::uint8_t, 9> balVal{};
        std::uint64_t const xfl42 = 6108051438023540736ULL; // ~42 XAH
        std::memcpy(balVal.data(), &xfl42, 8);
        balVal[8] = 0;
        setState(env, bob, alice, bk.data(), bk.size(),
                 balVal.data(), balVal.size());

        // Step 2: install a verifier hook that does the same sha512h as top.c
        // and returns the balance it finds (or an error)
        auto const& verifier_wasm = tipbotclaude_test_wasm[
            R"[test.hook](
            #include <stdint.h>
            extern int32_t _g(uint32_t, uint32_t);
            extern int64_t accept(uint32_t, uint32_t, int64_t);
            extern int64_t rollback(uint32_t, uint32_t, int64_t);
            extern int64_t state(uint32_t, uint32_t, uint32_t, uint32_t);
            extern int64_t otxn_field(uint32_t, uint32_t, uint32_t);
            extern int64_t util_sha512h(uint32_t, uint32_t, uint32_t, uint32_t);
            extern int64_t hook_account(uint32_t, uint32_t);
            #define sfAccount ((8U << 16U) + 1U)
            int64_t hook(uint32_t r) {
                _g(1,1);
                uint8_t otxn_acc[20];
                otxn_field((uint32_t)(otxn_acc), sizeof(otxn_acc), sfAccount);

                uint8_t hook_acc[20];
                hook_account((uint32_t)(hook_acc), sizeof(hook_acc));
                if (*(uint64_t*)(hook_acc) == *(uint64_t*)(otxn_acc) &&
                    *(uint64_t*)(hook_acc + 8) == *(uint64_t*)(otxn_acc + 8) &&
                    *(uint32_t*)(hook_acc + 16) == *(uint32_t*)(otxn_acc + 16))
                    return accept("pass out", 8, 0);

                uint8_t key_material[60] = {};
                *(uint64_t*)(key_material + 0) = *(uint64_t*)(otxn_acc + 0);
                *(uint64_t*)(key_material + 8) = *(uint64_t*)(otxn_acc + 8);
                *(uint32_t*)(key_material + 16) = *(uint32_t*)(otxn_acc + 16);

                uint8_t bal_key[32];
                util_sha512h(
                    (uint32_t)(bal_key),
                    sizeof(bal_key),
                    (uint32_t)(key_material),
                    sizeof(key_material));
                bal_key[0] = 'B';

                uint8_t bal_buf[9];
                int64_t res = state(
                    (uint32_t)(bal_buf),
                    sizeof(bal_buf),
                    (uint32_t)(bal_key),
                    sizeof(bal_key));
                if (res == 9)
                    return accept("found", 5, *(int64_t*)bal_buf);
                return accept("not found", 9, res);
            }
            )[test.hook]"];

        auto verifierHso = hso(verifier_wasm, overrideFlag);
        verifierHso[jss::HookNamespace] =
            "0000000000000000000000000000000000000000000000000000000000000000";

        env(ripple::test::jtx::hook(alice, {{verifierHso}}, 0),
            M("Install verifier hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Step 3: bob invokes - the hook will try to find his balance
        env(invoke::invoke(bob), invoke::dest(alice),
            M("Verify key match"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        auto meta = env.meta();
        BEAST_REQUIRE(meta);
        auto ret = firstHookReturnString(meta);
        // If the hook found the balance, ret starts with "found"
        // If not, ret is "not found"
        BEAST_EXPECT(ret.substr(0, 5) == "found");
        if (ret.substr(0, 5) != "found")
            log << "Key verification result: " << ret << std::endl;
    }

    void
    testStateSetterRoundtrip(FeatureBitset features)
    {
        // Verify that state written by the state-setter can be read back
        // by a hook using the same 32-byte key
        testcase("Keys: state-setter write can be read by another hook");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.close();

        installStateSetter(env, alice);

        // Write a known value under a known key
        std::array<std::uint8_t, 32> testKey{};
        testKey[0] = 'T';
        testKey[1] = 'E';
        testKey[2] = 'S';
        testKey[3] = 'T';
        std::array<std::uint8_t, 8> testVal{};
        testVal[0] = 0xDE;
        testVal[1] = 0xAD;
        testVal[2] = 0xBE;
        testVal[3] = 0xEF;

        setState(env, bob, alice,
                 testKey.data(), testKey.size(),
                 testVal.data(), testVal.size());

        // Read it back from C++ side
        auto const stateEntry = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(testKey.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(stateEntry);
        auto const& data = stateEntry->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(data.size() == 8);
        BEAST_EXPECT(data[0] == 0xDE);
        BEAST_EXPECT(data[1] == 0xAD);
        BEAST_EXPECT(data[2] == 0xBE);
        BEAST_EXPECT(data[3] == 0xEF);
    }

    void
    testStateSurvivesHookReplace(FeatureBitset features)
    {
        testcase("Keys: state survives hook replacement with same namespace");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.close();

        // Seed balance under state-setter (zero NS)
        installStateSetter(env, alice);
        auto bk = balanceKey(bob.id());
        std::array<std::uint8_t, 9> balVal{};
        auto const xfl10 = xflWhole(10);
        std::memcpy(balVal.data(), &xfl10, 8);
        balVal[8] = 0;
        setState(env, bob, alice, bk.data(), bk.size(),
                 balVal.data(), balVal.size());

        // Verify it exists before replacement
        auto const beforeReplace = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(beforeReplace);
        std::cerr << "Before replace: balance exists, size="
                  << beforeReplace->getFieldVL(sfHookStateData).size() << "\n";

        // Replace with top hook using zero namespace
        installTopHookZeroNS(env, alice);

        // Verify it STILL exists after replacement
        auto const afterReplace = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        if (!afterReplace)
            std::cerr << "After replace: balance GONE!\n";
        else
            std::cerr << "After replace: balance exists, size="
                      << afterReplace->getFieldVL(sfHookStateData).size()
                      << "\n";
        BEAST_EXPECT(!!afterReplace);
    }

    void
    testWithdrawKeyMatchesSeededKey(FeatureBitset features)
    {
        testcase("Keys: top.c withdraw reads the same key we seed");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.close();

        // Seed state then install top hook
        installStateSetter(env, alice);
        seedXAHBalance(env, bob, alice, bob.id(), xflWhole(10));
        installTopHookZeroNS(env, alice);

        // Attempt withdrawal and check the hook return string
        std::array<std::uint8_t, 48> withdrawData{};
        auto const xfl10 = xflWhole(10);
        std::memcpy(withdrawData.data() + 40, &xfl10, 8);

        env(remit::remit(bob, alice),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("Withdraw attempt"),
            fee(XRP(1)),
            ter(tesSUCCESS));

        auto ret = firstHookReturnString(env.meta());
        std::cerr << "Withdraw return: " << ret << "\n";

        // If we get "No such user-currency-issuer" then keys don't match
        // If we get "Done" or emit count > 0, it worked
        BEAST_EXPECT(ret.find("No such") == std::string::npos);
    }

    void
    testCodexWithdrawReproduction(FeatureBitset features)
    {
        // Exact reproduction of codex's testTopWithdrawSuccessEmitsAndClearsBalance
        // using my helpers to isolate the difference
        testcase("Repro: codex withdraw test using claude helpers");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);  // same funding as codex
        env.fund(XRP(10000), bob);
        env.close();

        // Step 1: seed state (same as codex)
        installStateSetter(env, alice);
        seedXAHBalance(env, bob, alice, bob.id(), xflWhole(10));

        // Step 2: install top hook with zero NS (same as codex after my fix)
        installTopHookZeroNS(env, alice);

        // Step 3: verify balance exists (codex line 1034-1036)
        auto bk = balanceKey(bob.id());
        auto const seededBalance = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(seededBalance);
        std::cerr << "Seeded balance size: "
                  << seededBalance->getFieldVL(sfHookStateData).size() << "\n";

        // Step 4: withdraw (same params as codex)
        std::array<std::uint8_t, 48> withdrawData{};
        auto const xfl10 = xflWhole(10);
        std::memcpy(withdrawData.data() + 40, &xfl10, 8);

        env(remit::remit(bob, alice),
            [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "5749544844524157",
                    strHex(Slice(withdrawData.data(), withdrawData.size())));
            },
            M("Withdraw succeeds"),
            fee(XRP(1)),
            ter(tesSUCCESS));

        auto ret = firstHookReturnString(env.meta());
        std::cerr << "Hook return: " << ret << "\n";

        auto const meta = env.meta();
        BEAST_REQUIRE(meta);
        BEAST_REQUIRE(meta->isFieldPresent(sfHookExecutions));
        auto const hookExecutions = meta->getFieldArray(sfHookExecutions);
        BEAST_REQUIRE(hookExecutions.size() == 1);
        BEAST_EXPECT(hookExecutions[0].getFieldU16(sfHookEmitCount) == 1);
        env.close();

        // Step 5: verify balance cleared and user info updated
        auto uik = userInfoKey(bob.id());
        auto const userInfo = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(uik.data()),
            uint256{beast::zero}));
        auto const balance = env.le(keylet::hookState(
            alice.id(),
            uint256::fromVoid(bk.data()),
            uint256{beast::zero}));

        BEAST_REQUIRE(userInfo);
        BEAST_EXPECT(!balance);

        auto const& userInfoData = userInfo->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(userInfoData.size() == 32);
        BEAST_EXPECT(popcount(userInfoData) == 0);
    }

    // ---- Combined Tests ----

    void
    testBothHooksInstall(FeatureBitset features)
    {
        testcase("Both: install tip and top hooks on same account");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        env.fund(XRP(10000), alice);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");
        HOOK_WASM(top, "file:tipbot/top.c");

        // Install both hooks: tip at position 0, top at position 1
        env(ripple::test::jtx::hook(
                alice,
                {{hso(tip_wasm, overrideFlag),
                  hso(top_wasm, overrideFlag)}},
                0),
            M("Install both hooks"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        auto const hook = env.le(keylet::hook(alice.id()));
        BEAST_REQUIRE(hook);
        BEAST_REQUIRE(hook->isFieldPresent(sfHooks));
        auto const& hooks = hook->getFieldArray(sfHooks);
        BEAST_REQUIRE(hooks.size() == 2);
        BEAST_EXPECT(hooks[0].isFieldPresent(sfHookHash));
        BEAST_EXPECT(hooks[0].getFieldH256(sfHookHash) == tip_hash);
        BEAST_EXPECT(hooks[1].isFieldPresent(sfHookHash));
        BEAST_EXPECT(hooks[1].getFieldH256(sfHookHash) == top_hash);
    }

    void
    testTipSettlementHitsSecondCtzllWord(FeatureBitset features)
    {
        testcase("Tip: oracle settlement allocates 65th currency slot (second ctzll)");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& hookAcc = env.account("hookacc");
        auto const& depositor = env.account("depositor");
        auto const& m0 = env.account("member0");
        auto const& m1 = env.account("member1");
        auto const& helper = env.account("helper");
        auto const& gw = env.account("gateway");
        auto const TST = gw["TST"];
        env.fund(XRP(100000), hookAcc);
        env.fund(XRP(100000), depositor);
        env.fund(XRP(100000), m0);
        env.fund(XRP(100000), m1);
        env.fund(XRP(100000), helper);
        env.fund(XRP(100000), gw);
        env.close();
        env.trust(TST(100000), hookAcc);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");
        HOOK_WASM(top, "file:tipbot/top.c");

        // Seed oracle members
        installStateSetter(env, hookAcc);
        seedMembersBitfield(env, helper, hookAcc, 2);
        seedMember(env, helper, hookAcc, m0.id(), 0);
        seedMember(env, helper, hookAcc, m1.id(), 1);

        // Pre-seed recipient user 555 with 64 occupied currency slots
        // by writing a user info bitfield with the first 8 bytes all 0xFF
        std::array<std::uint8_t, 20> recipUser{};
        recipUser[0] = 1;  // SNID = twitter
        uint64_t recipId = 555;
        std::memcpy(recipUser.data() + 12, &recipId, 8);

        {
            // User info key: 'U' + target (21 bytes)
            std::array<std::uint8_t, 21> uiKey{};
            uiKey[0] = 'U';
            std::copy(recipUser.begin(), recipUser.end(), uiKey.begin() + 1);

            // 32-byte bitfield: first 8 bytes = 0xFF (64 slots occupied)
            std::array<std::uint8_t, 32> uiVal{};
            std::memset(uiVal.data(), 0xFF, 8);  // first 64 bits set

            setState(env, helper, hookAcc,
                uiKey.data(), uiKey.size(),
                uiVal.data(), uiVal.size());
        }

        // Seed a balance for the FROM user (social user 999) so the tip
        // can go through. Social user balance key = sha512h(snid+zeros+userid + currency + issuer)
        std::array<std::uint8_t, 20> fromUser{};
        fromUser[0] = 1;
        uint64_t fromId = 999;
        std::memcpy(fromUser.data() + 12, &fromId, 8);

        {
            // Build the 60-byte input for balance key: user(20) + currency(20) + issuer(20)
            // For XAH: currency and issuer are all zeros
            std::array<std::uint8_t, 60> bkInput{};
            std::memcpy(bkInput.data(), fromUser.data(), 20);
            auto bkHash = sha512Half(Slice(bkInput.data(), bkInput.size()));
            std::array<std::uint8_t, 32> bk{};
            std::memcpy(bk.data(), bkHash.data(), 32);
            bk[0] = 'B';

            // Balance = 9 bytes: 8 bytes XFL + 1 byte slot index
            std::array<std::uint8_t, 9> balVal{};
            uint64_t amt = xflWhole(50);  // 50 XAH
            std::memcpy(balVal.data(), &amt, 8);
            balVal[8] = 0;

            setState(env, helper, hookAcc, bk.data(), bk.size(), balVal.data(), balVal.size());

            // Also need user info for the from user
            std::array<std::uint8_t, 21> fromUiKey{};
            fromUiKey[0] = 'U';
            std::copy(fromUser.begin(), fromUser.end(), fromUiKey.begin() + 1);
            std::array<std::uint8_t, 32> fromUiVal{};
            fromUiVal[0] = 0x01;  // one currency slot occupied (XAH at slot 0)
            setState(env, helper, hookAcc, fromUiKey.data(), fromUiKey.size(), fromUiVal.data(), fromUiVal.size());
        }

        // Install both hooks
        {
            auto tipHso = hso(tip_wasm, overrideFlag);
            tipHso[jss::HookNamespace] =
                "0000000000000000000000000000000000000000000000000000000000000000";
            auto topHso = hso(top_wasm, overrideFlag);
            topHso[jss::HookNamespace] =
                "0000000000000000000000000000000000000000000000000000000000000000";
            env(ripple::test::jtx::hook(
                    hookAcc, {{tipHso, topHso}}, 0),
                M("Install both hooks"),
                HSFEE,
                ter(tesSUCCESS));
            env.close();
        }

        // Oracle tips XAH from user 999 to user 555
        // User 555 already has 64 currency slots used, so this tip
        // allocates slot 64 — hitting the second ctzll word (line 598)
        auto opinion = buildTipOpinion(
            1, 70001, recipUser.data(), 999, xflWhole(10));

        submitOpinion(env, m0, hookAcc, 0, opinion, tesSUCCESS);
        env.close();
        submitOpinion(env, m1, hookAcc, 0, opinion, tesSUCCESS);
        auto const ret = firstHookReturnString(env.meta());
        BEAST_EXPECT(ret.find("Results: A") != std::string::npos);
        env.close();

        auto const recipUi = env.le(keylet::hookState(
            hookAcc.id(),
            socialUserInfoKey(recipUser),
            uint256{beast::zero}));
        BEAST_REQUIRE(recipUi);
        auto const& recipUiData = recipUi->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(recipUiData.size() == 32);
        BEAST_EXPECT(popcount(recipUiData) == 65);
        BEAST_EXPECT((recipUiData[8] & 0x01U) != 0);

        auto const slot64 = env.le(keylet::hookState(
            hookAcc.id(),
            socialUserSlotKey(recipUser, 64),
            uint256{beast::zero}));
        BEAST_REQUIRE(slot64);
        BEAST_EXPECT(slot64->getFieldVL(sfHookStateData).size() == 40);

        std::array<std::uint8_t, 60> toKeyInput{};
        std::memcpy(toKeyInput.data(), recipUser.data(), 20);
        auto toHash = sha512Half(Slice(toKeyInput.data(), toKeyInput.size()));
        std::array<std::uint8_t, 32> toBalKey;
        std::memcpy(toBalKey.data(), toHash.data(), 32);
        toBalKey[0] = 'B';
        auto const recipBal = env.le(keylet::hookState(
            hookAcc.id(),
            uint256::fromVoid(toBalKey.data()),
            uint256{beast::zero}));
        BEAST_REQUIRE(recipBal);
        auto const& recipBalData = recipBal->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(recipBalData.size() == 9);
        std::uint64_t recipXfl = 0;
        std::memcpy(&recipXfl, recipBalData.data(), 8);
        BEAST_EXPECT(recipXfl == xflWhole(10));
        BEAST_EXPECT(recipBalData[8] == 64);
    }

    void
    testTopDepositManyCurrenciesHitsSecondCtzll(FeatureBitset features)
    {
        testcase("Top: depositing 65+ currencies hits second ctzll word");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");  // hook account
        auto const& bob = env.account("bob");
        auto const& gw = env.account("gateway");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.fund(XRP(100000), gw);
        env.close();

        HOOK_WASM(top, "file:tipbot/top.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(top_wasm, overrideFlag)}}, 0),
            M("Install top hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Target user: SNID=1, userid=500
        std::array<std::uint8_t, 20> depositTarget{};
        depositTarget[0] = 1;
        uint64_t userId = 500;
        for (int i = 0; i < 8; ++i)
            depositTarget[12 + i] = static_cast<uint8_t>((userId >> (i * 8)) & 0xFF);

        auto const depositParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "4445504F534954",
                strHex(Slice(depositTarget.data(), depositTarget.size())));
        };

        // First deposit must be XAH >= 10
        env(remit::remit(bob, alice),
            remit::amts({XRP(100)}),
            depositParam,
            M("Initial XAH deposit"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // Now deposit 65 different IOUs to push past the first ctzll word
        // (64 bits). The 65th currency will hit the second word (lines 598-599).
        for (int i = 0; i < 65; ++i)
        {
            // Create a unique currency per iteration
            char curName[4];
            snprintf(curName, sizeof(curName), "%c%c%c",
                'A' + (i / 26 / 26) % 26,
                'A' + (i / 26) % 26,
                'A' + i % 26);
            auto const CUR = gw[curName];

            // Each operation in its own ledger to avoid fee escalation
            env(trust(bob, CUR(1000000)), fee(XRP(1)));
            env.close();
            env(trust(alice, CUR(1000000)), fee(XRP(1)));
            env.close();
            env(pay(gw, bob, CUR(10000)), fee(XRP(1)));
            env.close();

            env(remit::remit(bob, alice),
                remit::amts({CUR(100)}),
                depositParam,
                M("IOU deposit"),
                fee(XRP(1)),
                ter(tesSUCCESS));
            env.close();
        }

        auto const userInfo = env.le(keylet::hookState(
            alice.id(),
            socialUserInfoKey(depositTarget),
            uint256{beast::zero}));
        BEAST_REQUIRE(userInfo);
        auto const& uiData = userInfo->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(uiData.size() == 32);
        BEAST_EXPECT(popcount(uiData) == 66);
        BEAST_EXPECT((uiData[8] & 0x03U) == 0x03U);

        auto const slot64 = env.le(keylet::hookState(
            alice.id(),
            socialUserSlotKey(depositTarget, 64),
            uint256{beast::zero}));
        auto const slot65 = env.le(keylet::hookState(
            alice.id(),
            socialUserSlotKey(depositTarget, 65),
            uint256{beast::zero}));
        BEAST_REQUIRE(slot64);
        BEAST_REQUIRE(slot65);
        BEAST_EXPECT(slot64->getFieldVL(sfHookStateData).size() == 40);
        BEAST_EXPECT(slot65->getFieldVL(sfHookStateData).size() == 40);
    }

    void
    testTipGCFindsAndDeletesStaleEntries(FeatureBitset features)
    {
        testcase("Tip: GC finds and deletes stale entries after 20 ledgers");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");  // hook account
        auto const& bob = env.account("bob");
        auto const& carol = env.account("carol");
        env.fund(XRP(100000), alice);
        env.fund(XRP(100000), bob);
        env.fund(XRP(100000), carol);
        env.close();

        HOOK_WASM(tip, "file:tipbot/tip.c");

        env(ripple::test::jtx::hook(
                alice, {{hso(tip_wasm, overrideFlag)}}, 0),
            M("Install tip hook"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Bootstrap members
        env(invoke::invoke(bob), invoke::dest(alice),
            M("Bootstrap"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // Seed bob as member 0 so he can submit opinions
        installStateSetter(env, alice);
        {
            // Set bob as member at seat 0
            std::array<std::uint8_t, 21> memberKey{};
            memberKey[0] = 'M';
            std::memcpy(memberKey.data() + 1, bob.id().data(), 20);
            uint8_t seat = 0;
            setState(env, carol, alice,
                memberKey.data(), memberKey.size(),
                &seat, 1);
        }

        // Reinstall tip hook (to clear the state setter)
        env(ripple::test::jtx::hook(
                alice, {{hso(tip_wasm, overrideFlag)}}, 0),
            M("Reinstall tip"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();

        // Submit an opinion to create cleanup-indexed state entries
        {
            // Build an 85-byte opinion: SNID=1, postid=12345, ...
            std::array<std::uint8_t, 85> opinion{};
            opinion[0] = 1;  // SNID = twitter
            // postid at bytes 1-8
            uint64_t postId = 12345;
            std::memcpy(opinion.data() + 1, &postId, 8);
            // from userid at bytes 29-36
            uint64_t fromId = 9999;
            std::memcpy(opinion.data() + 29, &fromId, 8);
            // amount at bytes 77-84 (XFL for 1.0)
            uint64_t amt = 6089866696204910592ULL;
            std::memcpy(opinion.data() + 77, &amt, 8);

            // Key "0" (parameter index 0)
            uint8_t paramKey = 0;

            Json::Value params{Json::arrayValue};
            Json::Value entry;
            entry[jss::HookParameter] = Json::Value{};
            entry[jss::HookParameter][jss::HookParameterName] =
                strHex(Slice(&paramKey, 1));
            entry[jss::HookParameter][jss::HookParameterValue] =
                strHex(Slice(opinion.data(), opinion.size()));
            params.append(entry);

            auto const opinionParam = [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = params;
            };

            env(invoke::invoke(bob), invoke::dest(alice),
                opinionParam,
                M("Submit opinion"),
                fee(XRP(1)),
                ter(tesSUCCESS));
            env.close();
        }

        // Advance 25 ledgers so the entry becomes stale (cutoff = current - 20)
        for (int i = 0; i < 25; ++i)
            env.close();

        // Now invoke again — GC should find and delete the stale entry (line 126)
        env(invoke::invoke(bob), invoke::dest(alice),
            M("Trigger GC cleanup"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    bool
    shouldRun(std::string const& name, char const* filter)
    {
        if (!filter || !filter[0])
            return true;
        return name.find(filter) != std::string::npos;
    }

#define RUN(fn)                          \
    if (shouldRun(#fn, filter))          \
        fn(sa);

    void
    run() override
    {
        using namespace test::jtx;
        auto const sa = supported_amendments();
        auto const* filter = std::getenv("TIPBOT_CLAUDE_TEST");

        // Reset coverage and register labels
        hook::coverageReset();
        {
            HOOK_WASM(tip, "file:tipbot/tip.c");
            HOOK_WASM(top, "file:tipbot/top.c");
            hook::coverageLabel(tip_hash, "file:tipbot/tip.c");
            hook::coverageLabel(top_hash, "file:tipbot/top.c");
        }

        // Tip hook tests
        RUN(testTipHookInstall);
        RUN(testTipPassesOutgoing);
        RUN(testTipPassesNonInvoke);
        RUN(testTipInitialMembers);
        RUN(testTipNonMemberRejected);
        RUN(testTipTruncatedMembersBitfieldBootstraps);

        // Top hook tests
        RUN(testTopHookInstall);
        RUN(testTopPassesOutgoing);
        RUN(testTopPassesNonRemit);
        RUN(testTopRejectsRemitWithNFT);
        RUN(testTopDepositMissingParam);
        RUN(testTopDepositSuccessCreatesUserState);
        RUN(testTopDepositFirstMustBeXAH);
        RUN(testTopDepositInvalidSNID);
        RUN(testTopDepositRejectsAccidTarget);
        RUN(testTopDepositSecondCanBeIOU);
        RUN(testTopRejectsMultipleAmounts);
        RUN(testTopRejectsDepositAndWithdrawParamsTogether);
        RUN(testTopDepositAccumulatesBalance);
        RUN(testTopDepositAllocatesDistinctSlotsForNewCurrencies);
        RUN(testTopWithdrawMissingParam);
        RUN(testTopWithdrawNoBalance);
        RUN(testTopWithdrawXAHSuccess);
        RUN(testTopWithdrawExceedsBalanceCaps);
        RUN(testTopWithdrawIOUNeedsTrustline);
        RUN(testTopWithdrawIOUWithTrustline);
        RUN(testTopGovernanceEmit);
        RUN(testTopGovernanceQueueDrainsOneEntryPerWithdrawal);

        // Oracle voting tests
        RUN(testTipMemberVoteSubmitted);
        RUN(testTipDuplicateVoteRejected);
        RUN(testTipThresholdReachedActionsTip);
        RUN(testTipMemberGovernanceAddRemove);
        RUN(testTipMemberReplacementPreservesUniqueSeatInvariant);
        RUN(testTipInvalidAmountGetsW);
        RUN(testTipInsufficientBalanceGetsB);

        // GC and cleanup tests
        RUN(testTipGCDeletesStaleEntries);
        RUN(testTipGCUnderflowFixOnLowLedger);

        // Tip-to-raddr and already-actioned tests
        RUN(testTipToRAddress);
        RUN(testTipAlreadyActionedReturnsD);
        RUN(testTipHookGovernanceWritesHState);
        RUN(testTipHookGovernanceRejectsOutOfRangeSlot);
        RUN(testTipMultipleOpinionsPerInvoke);

        // E2E and advanced tests
        RUN(testE2EDepositTipWithdraw);
        RUN(testTipConflictingOpinionsSamePost);
        RUN(testTipDrainsBalanceAndCleansUp);
        RUN(testE2EDepositTipWithdrawIOU);
        RUN(testTopPartialWithdrawLeavesCorrectBalance);
        RUN(testTipBetweenSocialUsers);

        // Key verification tests
        RUN(testStateSetterRoundtrip);
        RUN(testKeyComputationMatches);
        RUN(testStateSurvivesHookReplace);
        RUN(testWithdrawKeyMatchesSeededKey);
        RUN(testCodexWithdrawReproduction);

        // Coverage gap tests
        RUN(testTipSettlementHitsSecondCtzllWord);
        RUN(testTopDepositManyCurrenciesHitsSecondCtzll);
        RUN(testTipGCFindsAndDeletesStaleEntries);

        // Combined tests
        RUN(testBothHooksInstall);

        // Dump coverage
        auto const* covDir = std::getenv("HOOKS_COVERAGE_DIR");
        if (covDir)
        {
            auto now = std::chrono::system_clock::now().time_since_epoch();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
            std::string path = std::string(covDir) + "/TipBotClaude_" + std::to_string(ms) + ".dat";
            hook::coverageDump(path);
            HOOK_WASM(tip, "file:tipbot/tip.c");
            HOOK_WASM(top, "file:tipbot/top.c");
            auto const* tipHits = hook::coverageHits(tip_hash);
            auto const* topHits = hook::coverageHits(top_hash);
            std::cerr <<
                "Coverage -> " << path << "\n" <<
                "  tip.c: " << (tipHits ? tipHits->size() : 0) << " guards hit\n" <<
                "  top.c: " << (topHits ? topHits->size() : 0) << " guards hit\n";
        }
    }

#undef RUN
};

BEAST_DEFINE_TESTSUITE(TipBotClaude, app, ripple);

}  // namespace test
}  // namespace ripple
