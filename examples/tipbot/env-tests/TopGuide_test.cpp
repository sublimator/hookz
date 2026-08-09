// Practice env test for the guide: exercises examples/tipbot/hooks/top.c
// deposit path against real xahaud. Written from the `hookz env-test-context`
// skeleton, deliberately NOT copied from TipBot_test.cpp.
#include "TopGuide_test_hooks.h"
#include <test/jtx.h>
#include <test/jtx/TestEnv.h>
#include <test/jtx/hook.h>
#include <test/jtx/remit.h>
#include <xrpld/app/hook/applyHook.h>
#include <xrpld/app/tx/detail/SetHook.h>
#include <xrpl/hook/Enum.h>
#include <xrpl/protocol/jss.h>
#include <algorithm>
#include <array>
#include <cstdlib>

namespace ripple {
namespace test {

#define BEAST_REQUIRE(x)     \
    {                        \
        BEAST_EXPECT(!!(x)); \
        if (!(x))            \
            return;          \
    }
#define HSFEE fee(100'000'000)
#define M(m) memo(m, "", "")

#define HOOK_WASM(name, path)                                                  \
    [[maybe_unused]] auto const& name##_wasm = topguide_test_wasm[path];       \
    [[maybe_unused]] uint256 const name##_hash = ripple::sha512Half_s(         \
        ripple::Slice(name##_wasm.data(), name##_wasm.size()));                \
    [[maybe_unused]] std::string const name##_hash_str =                       \
        to_string(name##_hash);                                                \
    [[maybe_unused]] Keylet const name##_keylet =                              \
        keylet::hookDefinition(name##_hash);

class TopGuide_test : public beast::unit_test::suite
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

    // top.c's DEPOSIT parameter value: snid . 11 zero bytes . userid (le).
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

    // Hook state key for a user's XAH balance:
    // 'B' over sha512h(userKey . 40 zero bytes) — the user key padded to 60.
    static uint256
    xahBalanceKey(std::array<std::uint8_t, 20> const& userKey)
    {
        std::array<std::uint8_t, 60> material{};
        std::copy(userKey.begin(), userKey.end(), material.begin());
        auto const hash =
            ripple::sha512Half_s(Slice(material.data(), material.size()));
        std::array<std::uint8_t, 32> key{};
        std::copy(hash.begin(), hash.end(), key.begin());
        key[0] = 'B';
        return uint256::fromVoid(key.data());
    }

    // 'U' . userKey, right-aligned in 32 bytes as state() stores it.
    static uint256
    userInfoKey(std::array<std::uint8_t, 20> const& userKey)
    {
        std::array<std::uint8_t, 32> key{};
        std::size_t i = 32 - 21;
        key[i++] = 'U';
        for (auto const b : userKey)
            key[i++] = b;
        return uint256::fromVoid(key.data());
    }

    static Json::Value
    depositParam(std::array<std::uint8_t, 20> const& target)
    {
        Json::Value params{Json::arrayValue};
        Json::Value entry;
        entry[jss::HookParameter] = Json::Value{};
        entry[jss::HookParameter][jss::HookParameterName] =
            "4445504F534954";  // "DEPOSIT"
        entry[jss::HookParameter][jss::HookParameterValue] =
            strHex(Slice(target.data(), target.size()));
        params.append(entry);
        return params;
    }

    void
    installTop(TestEnv& env, jtx::Account const& acc)
    {
        using namespace jtx;
        HOOK_WASM(top, "file:tipbot/top.c");
        env(ripple::test::jtx::hook(
                acc, {{hso(top_wasm, overrideFlag)}}, 0),
            M("install top"),
            HSFEE,
            ter(tesSUCCESS));
        env.close();
    }

    void
    testRemitWithoutParamIsRejected(FeatureBitset features)
    {
        testcase("guide: a remit carrying value but no param is rejected");
        using namespace jtx;

        auto env = makeEnv(features);
        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice, bob);
        env.close();

        env.setPrefix("install");
        installTop(env, alice);

        // top.c:198 — "Remit must have exactly one param" is a rollback,
        // and a rollback surfaces to the submitter as tecHOOK_REJECTED.
        env.setPrefix("trigger");
        env(remit::remit(bob, alice),
            remit::amts({XRP(100)}),
            M("no param"),
            fee(XRP(1)),
            ter(tecHOOK_REJECTED));
        env.close();
    }

    void
    testDepositWritesBalanceState(FeatureBitset features)
    {
        testcase("guide: a first deposit writes user-info and balance state");
        using namespace jtx;

        auto env = makeEnv(features);
        auto const& alice = env.account("alice");
        auto const& bob = env.account("bob");
        env.fund(XRP(10000), alice, bob);
        env.close();

        env.setPrefix("install");
        installTop(env, alice);

        auto const target = socialUserKey(1, 4242);

        env.setPrefix("deposit");
        auto const withParam = [&](Env&, jtx::JTx& jt) {
            jt.jv[jss::HookParameters] = depositParam(target);
        };
        env(remit::remit(bob, alice),
            remit::amts({XRP(10)}),  // top.c:293 — first deposit floor is 10 XAH
            withParam,
            M("first deposit"),
            fee(XRP(1)),
            ter(tesSUCCESS));
        env.close();

        // The hook's own state, read back off the closed ledger.
        auto const info = env.le(
            keylet::hookState(alice.id(), userInfoKey(target), beast::zero));
        BEAST_REQUIRE(info);
        auto const& infoData = info->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(infoData.size() == 32);
        BEAST_EXPECT(infoData[0] == 0x01);  // currency slot 0 in use

        auto const balance = env.le(
            keylet::hookState(alice.id(), xahBalanceKey(target), beast::zero));
        BEAST_REQUIRE(balance);
        auto const& balData = balance->getFieldVL(sfHookStateData);
        BEAST_REQUIRE(balData.size() == 9);
        BEAST_EXPECT(balData[8] == 0);  // trailing flag byte: XAH entry
    }

public:
    void
    run() override
    {
        using namespace jtx;
        auto const sa = supported_amendments();

        hook::coverageReset();
        {
            HOOK_WASM(top, "file:tipbot/top.c");
            hook::coverageLabel(top_hash, "file:tipbot/top.c");
        }

        testRemitWithoutParamIsRejected(sa);
        testDepositWritesBalanceState(sa);

        if (auto const* dir = std::getenv("HOOKS_COVERAGE_DIR"))
            hook::coverageDump(std::string(dir) + "/TopGuide.dat");
    }
};

BEAST_DEFINE_TESTSUITE(TopGuide, app, ripple);

}  // namespace test
}  // namespace ripple
