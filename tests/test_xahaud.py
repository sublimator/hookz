"""Test xahaud source extraction."""

import pytest

from hookz.xrpl.xahaud import XahaudRepo
from location_consts import XAHAUD

pytestmark = pytest.mark.skipif(XAHAUD is None, reason="xahaud source not found")


@pytest.fixture(scope="module")
def repo():
    return XahaudRepo(XAHAUD)


class TestParseDefines:
    def test_sfcodes(self, repo):
        sf = repo.parse_defines("hook/sfcodes.h")
        assert sf["sfTransactionType"] == (1 << 16) + 2
        assert sf["sfAccount"] == (8 << 16) + 1
        assert sf["sfAmounts"] == (15 << 16) + 92
        print(f"\nsfcodes: {len(sf)} constants")

    def test_tts(self, repo):
        tt = repo.parse_defines("hook/tts.h")
        assert tt["ttINVOKE"] == 99
        assert tt["ttREMIT"] == 95
        assert tt["ttPAYMENT"] == 0
        print(f"\ntts: {len(tt)} constants")

    def test_error_codes(self, repo):
        err = repo.parse_defines("hook/error.h")
        assert err["SUCCESS"] == 0
        assert err["OUT_OF_BOUNDS"] == -1
        assert err["DOESNT_EXIST"] == -5
        print(f"\nerror: {len(err)} constants")

    def test_hookapi(self, repo):
        ha = repo.parse_defines("hook/hookapi.h")
        assert ha["COMPARE_EQUAL"] == 1
        assert ha["COMPARE_LESS"] == 2
        assert ha["COMPARE_GREATER"] == 4
        print(f"\nhookapi: {len(ha)} constants")


class TestFindHookFunction:
    def test_find_float_sto(self, repo):
        code = repo.find_hook_function("float_sto")
        assert code is not None
        assert "DEFINE_HOOK_FUNCTION" in code
        assert "float_sto" in code
        print(f"\nfloat_sto wrapper: {len(code)} chars, first 200:\n{code[:200]}")

    def test_find_accept(self, repo):
        code = repo.find_hook_function("accept")
        assert code is not None
        assert "accept" in code
        print(f"\naccept wrapper: {len(code)} chars")

    def test_find_state(self, repo):
        code = repo.find_hook_function("state")
        assert code is not None
        print(f"\nstate wrapper: {len(code)} chars, first 200:\n{code[:200]}")

    def test_find_nonexistent(self, repo):
        code = repo.find_hook_function("nonexistent_function_xyz")
        assert code is None


class TestFindApiMethod:
    def test_find_float_sto(self, repo):
        code = repo.find_api_method("float_sto")
        assert code is not None
        assert "HookAPI::float_sto" in code
        assert "is_xrp" in code  # known content
        print(f"\nfloat_sto impl: {len(code)} chars, first 200:\n{code[:200]}")

    def test_find_emit(self, repo):
        code = repo.find_api_method("emit")
        assert code is not None
        assert "EMISSION_FAILURE" in code
        print(f"\nemit impl: {len(code)} chars")

    def test_find_etxn_details(self, repo):
        code = repo.find_api_method("etxn_details")
        assert code is not None
        assert "0xEDU" in code  # known byte
        print(f"\netxn_details impl: {len(code)} chars")

    def test_find_full(self, repo):
        result = repo.find_hook_function_full("float_sto")
        assert result["wrapper"] is not None
        assert result["implementation"] is not None
        print(f"\nfloat_sto full:")
        print(f"  wrapper: {len(result['wrapper'])} chars")
        print(f"  implementation: {len(result['implementation'])} chars")


class TestGenerateConstants:
    def test_generate(self, repo, tmp_path):
        content = repo.generate_hookapi_py(tmp_path / "generated.py")
        assert "sfTransactionType" in content
        assert "ttINVOKE" in content
        assert "DOESNT_EXIST" in content
        assert "COMPARE_EQUAL" in content
        print(f"\nGenerated {len(content)} chars, {content.count(chr(10))} lines")
        # Show a sample
        lines = content.splitlines()
        for l in lines[:20]:
            print(f"  {l}")
