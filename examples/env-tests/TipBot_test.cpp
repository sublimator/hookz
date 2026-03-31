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
#include "TipBot_test_hooks.h"
#include <test/jtx.h>
#include <test/jtx/TestEnv.h>
#include <test/jtx/hook.h>
#include <test/jtx/remit.h>
#include <xrpld/app/hook/applyHook.h>
#include <xrpld/app/tx/detail/SetHook.h>
#include <xrpl/hook/Enum.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>
#include <algorithm>
#include <array>
#include <cstdlib>

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
    [[maybe_unused]] auto const& name##_wasm = tipbot_test_wasm[path];          \
    [[maybe_unused]] uint256 const name##_hash =                                \
        ripple::sha512Half_s(ripple::Slice(name##_wasm.data(), name##_wasm.size())); \
    [[maybe_unused]] std::string const name##_hash_str = to_string(name##_hash); \
    [[maybe_unused]] Keylet const name##_keylet = keylet::hookDefinition(name##_hash);

class TipBot_test : public beast::unit_test::suite
{
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
        std::string const& name1Hex,
        std::string const& value1Hex,
        std::string const& name2Hex,
        std::string const& value2Hex)
    {
        Json::Value params{Json::arrayValue};
        Json::Value entry1;
        entry1[jss::HookParameter] = Json::Value{};
        entry1[jss::HookParameter][jss::HookParameterName] = name1Hex;
        entry1[jss::HookParameter][jss::HookParameterValue] = value1Hex;
        params.append(entry1);

        Json::Value entry2;
        entry2[jss::HookParameter] = Json::Value{};
        entry2[jss::HookParameter][jss::HookParameterName] = name2Hex;
        entry2[jss::HookParameter][jss::HookParameterValue] = value2Hex;
        params.append(entry2);
        return params;
    }

    static std::array<std::uint8_t, 20>
    socialUserKey(std::uint8_t snid, std::uint64_t userId)
    {
        std::array<std::uint8_t, 20> key{};
        key[0] = snid;
        for (int i = 0; i < 8; ++i)
            key[12 + i] =
                static_cast<std::uint8_t>((userId >> (i * 8)) & 0xFF);
        return key;
    }

    static std::array<std::uint8_t, 48>
    xahWithdrawSpec(std::uint64_t xflAmount)
    {
        std::array<std::uint8_t, 48> spec{};
        for (int i = 0; i < 8; ++i)
            spec[40 + i] =
                static_cast<std::uint8_t>((xflAmount >> (i * 8)) & 0xFF);
        return spec;
    }

    static uint256
    xahBalanceKey(std::array<std::uint8_t, 20> const& userKey)
    {
        std::array<std::uint8_t, 60> keyMaterial{};
        std::copy(userKey.begin(), userKey.end(), keyMaterial.begin());

        auto const hash =
            ripple::sha512Half_s(Slice(keyMaterial.data(), keyMaterial.size()));

        std::array<std::uint8_t, 32> key{};
        std::copy(hash.begin(), hash.end(), key.begin());
        key[0] = 'B';
        return uint256::fromVoid(key.data());
    }

    static std::array<std::uint8_t, 32>
    accountUserInfoKey(std::array<std::uint8_t, 20> const& account)
    {
        std::array<std::uint8_t, 32> key{};
        key[11] = 'U';
        std::copy(account.begin(), account.end(), key.begin() + 12);
        return key;
    }

    void
    installStateSetter(jtx::Env& env, jtx::Account const& hookAcc)
    {
        using namespace jtx;

        auto const& setter_wasm = tipbot_test_wasm[R"[test.hook](
                #include <stdint.h>
                extern int32_t _g(uint32_t, uint32_t);
                extern int64_t accept(uint32_t, uint32_t, int64_t);
                extern int64_t state_set(uint32_t, uint32_t, uint32_t, uint32_t);
                extern int64_t otxn_param(uint32_t, uint32_t, uint32_t, uint32_t);
                #define SBUF(x) (uint32_t)(x), sizeof(x)
                int64_t hook(uint32_t reserved)
                {
                    _g(1,1);

                    uint8_t key[32];
                    uint8_t value[256];
                    int64_t klen = otxn_param(SBUF(key), "K", 1);
                    int64_t vlen = otxn_param(SBUF(value), "V", 1);
                    if (klen > 0 && vlen > 0)
                        state_set(value, (uint32_t)vlen, key, (uint32_t)klen);
                    return accept(0, 0, 0);
                }
            )[test.hook]"];

        auto setterHso = hso(setter_wasm, overrideFlag);
        setterHso[jss::HookNamespace] =
            "0000000000000000000000000000000000000000000000000000000000000000";

        env(ripple::test::jtx::hook(hookAcc, {{setterHso}}, 0),
            memo("Install state setter", "", ""),
            fee(100'000'000),
            ter(tesSUCCESS));
        env.close();
    }

    void
    setState(
        jtx::Env& env,
        jtx::Account const& sender,
        jtx::Account const& hookAcc,
        std::uint8_t const* key,
        std::size_t klen,
        std::uint8_t const* value,
        std::size_t vlen)
    {
        using namespace jtx;

        auto const params = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams2(
                strHex(std::string("K")),
                strHex(Slice(key, klen)),
                strHex(std::string("V")),
                strHex(Slice(value, vlen)));
        };

        env(invoke::invoke(sender),
            invoke::dest(hookAcc),
            params,
            memo("Set state", "", ""),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    void
    seedXAHBalance(
        jtx::Env& env,
        jtx::Account const& sender,
        jtx::Account const& hookAcc,
        std::array<std::uint8_t, 20> const& balanceOwner,
        std::uint64_t xflAmount)
    {
        auto const balanceKey = xahBalanceKey(balanceOwner);
        std::array<std::uint8_t, 32> balanceKeyBytes{};
        std::copy(balanceKey.begin(), balanceKey.end(), balanceKeyBytes.begin());

        std::array<std::uint8_t, 9> balanceValue{};
        for (int i = 0; i < 8; ++i)
            balanceValue[i] =
                static_cast<std::uint8_t>((xflAmount >> (i * 8)) & 0xFF);
        balanceValue[8] = 0;

        setState(
            env,
            sender,
            hookAcc,
            balanceKeyBytes.data(),
            balanceKeyBytes.size(),
            balanceValue.data(),
            balanceValue.size());

        auto const userInfoKey = accountUserInfoKey(balanceOwner);
        std::array<std::uint8_t, 32> userInfoValue{};
        userInfoValue[0] = 0x01;

        setState(
            env,
            sender,
            hookAcc,
            userInfoKey.data(),
            userInfoKey.size(),
            userInfoValue.data(),
            userInfoValue.size());
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
#define HSFEE fee(100'000'000)
#define M(m) memo(m, "", "")

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

        auto const depositTarget = socialUserKey(1, 42);

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

        auto const balance =
            env.le(keylet::hookState(alice.id(), xahBalanceKey(depositTarget), beast::zero));
        BEAST_REQUIRE(balance);
        auto const& balanceData = balance->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(balanceData.size() == 9);
        BEAST_EXPECT(balanceData[8] == 0);
    }

    void
    testTopDepositSecondDepositReusesCurrencySlot(FeatureBitset features)
    {
        testcase("Top: second deposit reuses existing currency slot");
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

        auto const depositTarget = socialUserKey(1, 123);
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

        auto const userInfoKey = apiStateKey([&]() {
            std::array<std::uint8_t, 21> key{};
            key[0] = 'U';
            std::copy(
                depositTarget.begin(), depositTarget.end(), key.begin() + 1);
            return key;
        }());
        auto const balanceKey = xahBalanceKey(depositTarget);

        auto const userInfoBefore =
            env.le(keylet::hookState(alice.id(), userInfoKey, beast::zero));
        auto const balanceBefore =
            env.le(keylet::hookState(alice.id(), balanceKey, beast::zero));
        BEAST_REQUIRE(userInfoBefore);
        BEAST_REQUIRE(balanceBefore);
        auto const balanceDataBefore = balanceBefore->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(balanceDataBefore.size() == 9);
        BEAST_EXPECT(balanceDataBefore[8] == 0);

        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            depositParam,
            M("Second deposit succeeds"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        auto const userInfoAfter =
            env.le(keylet::hookState(alice.id(), userInfoKey, beast::zero));
        auto const balanceAfter =
            env.le(keylet::hookState(alice.id(), balanceKey, beast::zero));
        BEAST_REQUIRE(userInfoAfter);
        BEAST_REQUIRE(balanceAfter);

        auto const& userInfoDataAfter = userInfoAfter->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(userInfoDataAfter.size() == 32);
        BEAST_EXPECT(popcount(userInfoDataAfter) == 1);
        BEAST_EXPECT(userInfoDataAfter[0] == 0x01);

        auto const& balanceDataAfter = balanceAfter->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(balanceDataAfter.size() == 9);
        BEAST_EXPECT(balanceDataAfter[8] == 0);
        BEAST_EXPECT(balanceDataAfter != balanceDataBefore);
    }

    void
    testTopDepositFirstMustBeAtLeastTenXAH(FeatureBitset features)
    {
        testcase("Top: first deposit must be at least 10 XAH");
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

        auto const depositTarget = socialUserKey(1, 99);
        auto const depositParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "4445504F534954",  // DEPOSIT
                strHex(Slice(depositTarget.data(), depositTarget.size())));
        };

        env(remit::remit(bob, alice),
            remit::amts({XRP(5)}),
            depositParam,
            M("First deposit < 10 XAH rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();

        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            depositParam,
            M("First deposit 10 XAH succeeds"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();
    }

    void
    testTopDepositRejectsInvalidSNID(FeatureBitset features)
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

        for (auto const snid : {std::uint8_t{0}, std::uint8_t{254}})
        {
            auto const depositTarget = socialUserKey(snid, 42);
            auto const depositParam = [&](Env&, JTx& jt) {
                jt.jv[jss::HookParameters] = hookParams(
                    "4445504F534954",  // DEPOSIT
                    strHex(Slice(depositTarget.data(), depositTarget.size())));
            };

            env(remit::remit(bob, alice),
                remit::amts({XRP(10)}),
                depositParam,
                M("Invalid SNID rejected"),
                fee(XRP(1)),
                ter(tecHOOK_REJECTED));
            env.close();
        }
    }

    void
    testTopDepositRejectsAccidTarget(FeatureBitset features)
    {
        testcase("Top: deposit rejects accid-style target");
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

        auto depositTarget = socialUserKey(1, 42);
        depositTarget[1] = 0xFF;

        auto const depositParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "4445504F534954",  // DEPOSIT
                strHex(Slice(depositTarget.data(), depositTarget.size())));
        };

        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),
            depositParam,
            M("Accid-style target rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();
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

        auto const withdrawData =
            xahWithdrawSpec(6107881094714392576ULL /* 10.0 XAH in XFL */);
        auto const withdrawParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "5749544844524157",  // WITHDRAW
                strHex(Slice(withdrawData.data(), withdrawData.size())));
        };

        env(remit::remit(bob, alice),
            withdrawParam,
            M("Withdraw no balance rejected"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();
    }

    void
    testTopWithdrawSuccessEmitsAndClearsBalance(FeatureBitset features)
    {
        testcase("Top: withdraw emits remit and clears full balance");
        using namespace jtx;

        auto env = makeEnv(features);

        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice);
        env.fund(XRP(10000), bob);
        env.close();

        std::array<std::uint8_t, 20> bobAcc{};
        std::memcpy(bobAcc.data(), bob.id().data(), 20);
        installStateSetter(env, alice);
        seedXAHBalance(env, bob, alice, bobAcc, 6107881094714392576ULL);

        HOOK_WASM(top, "file:tipbot/top.c");
        auto const balanceKey = xahBalanceKey(bobAcc);


        auto const userInfoKeyBytes = accountUserInfoKey(bobAcc);
        auto const userInfoKey = uint256::fromVoid(userInfoKeyBytes.data());

        {
            auto topHso = hso(top_wasm, overrideFlag);
            topHso[jss::HookNamespace] =
                "0000000000000000000000000000000000000000000000000000000000000000";
            env(ripple::test::jtx::hook(alice, {{topHso}}, 0),
                M("Install top hook"),
                HSFEE,
                ter(tesSUCCESS));
            env.close();
        }

        auto const seededBalance =
            env.le(keylet::hookState(alice.id(), balanceKey, beast::zero));
        BEAST_REQUIRE(seededBalance);

        auto const withdrawData =
            xahWithdrawSpec(6107881094714392576ULL /* 10.0 XAH in XFL */);
        auto const withdrawParam = [&](Env&, JTx& jt) {
            jt.jv[jss::HookParameters] = hookParams(
                "5749544844524157",  // WITHDRAW
                strHex(Slice(withdrawData.data(), withdrawData.size())));
        };

        env(remit::remit(bob, alice),
            withdrawParam,
            M("Withdraw succeeds"),
            fee(XRP(1)),
            ter(tesSUCCESS));

        auto const meta = env.meta();
        BEAST_REQUIRE(meta);
        BEAST_REQUIRE(meta->isFieldPresent(sfHookExecutions));
        auto const hookExecutions = meta->getFieldArray(sfHookExecutions);
        BEAST_REQUIRE(hookExecutions.size() == 1);
        BEAST_EXPECT(hookExecutions[0].getFieldU16(sfHookEmitCount) == 1);
        env.close();

        auto const userInfo =
            env.le(keylet::hookState(alice.id(), userInfoKey, beast::zero));
        auto const balance =
            env.le(keylet::hookState(alice.id(), balanceKey, beast::zero));

        BEAST_REQUIRE(userInfo);
        BEAST_EXPECT(!balance);

        auto const& userInfoData = userInfo->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(userInfoData.size() == 32);
        BEAST_EXPECT(popcount(userInfoData) == 0);
    }

    // ---- Combined Tests ----

    void
    testHooksTraceJournalSmoke(FeatureBitset features)
    {
        testcase("Logs: HooksTrace journal smoke");

        auto env = makeEnv(features);
        auto const j = env.app().journal("HooksTrace");

        JLOG(j.info()) << "TipBot_test HooksTrace info smoke";
        JLOG(j.warn()) << "TipBot_test HooksTrace warn smoke";
        BEAST_EXPECT(true);
    }

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
        auto const* filter = std::getenv("TIPBOT_TEST");

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

        // Top hook tests
        RUN(testTopHookInstall);
        RUN(testTopPassesOutgoing);
        RUN(testTopPassesNonRemit);
        RUN(testTopRejectsRemitWithNFT);
        RUN(testTopDepositMissingParam);
        RUN(testTopDepositSuccessCreatesUserState);
        RUN(testTopDepositSecondDepositReusesCurrencySlot);
        RUN(testTopDepositFirstMustBeAtLeastTenXAH);
        RUN(testTopDepositRejectsInvalidSNID);
        RUN(testTopDepositRejectsAccidTarget);
        RUN(testTopWithdrawMissingParam);
        RUN(testTopWithdrawNoBalance);
        RUN(testTopWithdrawSuccessEmitsAndClearsBalance);

        // Combined tests
        RUN(testHooksTraceJournalSmoke);
        RUN(testBothHooksInstall);

        // Dump coverage for both hooks
        auto const* covPath = std::getenv("HOOKS_COVERAGE_DIR");
        if (covPath)
        {
            // Debug: show what's in the coverage map vs our hashes
            HOOK_WASM(tip, "file:tipbot/tip.c");
            HOOK_WASM(top, "file:tipbot/top.c");

            auto now = std::chrono::system_clock::now().time_since_epoch();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
            std::string path = std::string(covPath) + "/TipBot_" + std::to_string(ms) + ".dat";
            hook::coverageDump(path);
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

BEAST_DEFINE_TESTSUITE(TipBot, app, ripple);

}  // namespace test
}  // namespace ripple
