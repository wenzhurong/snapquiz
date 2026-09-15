import os
import unittest

from snapquiz.config import Config, ConfigError, load_config, resolve_api_key
from snapquiz.providers import OPENCODE_GO, PROFILES, ZHIPU, ProviderId

ZHIPU_ENV = {"GLM_API_KEY": "zp-test-key", "SNAPQUIZ_REGION": "10,20,640,480"}
OC_ENV = {
    "SNAPQUIZ_PROVIDER": "opencode_go",
    "OPENCODE_API_KEY": "sk-test-key",
    "SNAPQUIZ_REGION": "10,20,640,480",
}


class ProviderSelectionTest(unittest.TestCase):
    def test_default_provider_is_zhipu(self):
        cfg = load_config(ZHIPU_ENV)
        self.assertIs(cfg.provider, ZHIPU)
        self.assertEqual(cfg.model, ZHIPU.default_model)
        self.assertEqual(cfg.model, "glm-4.6v")

    def test_opencode_provider_selected_by_env(self):
        cfg = load_config(OC_ENV)
        self.assertIs(cfg.provider, OPENCODE_GO)
        self.assertEqual(cfg.model, "mimo-v2.5")
        self.assertEqual(
            cfg.endpoint_url, "https://opencode.ai/zen/go/v1/chat/completions"
        )

    def test_unknown_provider_is_refused(self):
        with self.assertRaises(ConfigError):
            load_config({**ZHIPU_ENV, "SNAPQUIZ_PROVIDER": "openai"})

    def test_each_provider_wants_its_own_key(self):
        """用 opencode 但只给了 GLM 的 key,必须报缺 OPENCODE_API_KEY。"""

        with self.assertRaises(ConfigError) as ctx:
            load_config({**ZHIPU_ENV, "SNAPQUIZ_PROVIDER": "opencode_go"})
        self.assertIn("OPENCODE_API_KEY", str(ctx.exception))

    def test_every_profile_declares_its_default_as_allowed(self):
        for provider_id, profile in PROFILES.items():
            with self.subTest(provider=provider_id):
                self.assertIn(profile.default_model, profile.allowed_models)
                self.assertTrue(profile.base_url.startswith("https://"))
                self.assertTrue(profile.reasoning_models <= profile.allowed_models)


class ModelWhitelistTest(unittest.TestCase):
    def test_cross_provider_model_is_refused(self):
        """mimo 不能配在 zhipu 下,glm 也不能配在 opencode 下。"""

        with self.assertRaises(ConfigError):
            load_config({**ZHIPU_ENV, "SNAPQUIZ_MODEL": "mimo-v2.5"})
        with self.assertRaises(ConfigError):
            load_config({**OC_ENV, "SNAPQUIZ_MODEL": "glm-4.6v"})

    def test_known_alternate_models_are_allowed(self):
        self.assertEqual(
            load_config({**ZHIPU_ENV, "SNAPQUIZ_MODEL": "glm-4v-flash"}).model,
            "glm-4v-flash",
        )
        self.assertEqual(
            load_config({**OC_ENV, "SNAPQUIZ_MODEL": "mimo-v2-omni"}).model,
            "mimo-v2-omni",
        )

    def test_text_only_models_are_not_in_any_whitelist(self):
        """实测拒收图片的模型不得出现在白名单里。"""

        for banned in ("glm-4.5-air", "mimo-v2.5-pro"):
            for profile in PROFILES.values():
                self.assertNotIn(banned, profile.allowed_models)

    def test_legacy_glm_model_env_still_works(self):
        self.assertEqual(
            load_config({**ZHIPU_ENV, "GLM_MODEL": "glm-4v"}).model, "glm-4v"
        )

    def test_reasoning_flag_matches_profile(self):
        # glm-4.6v 与 mimo-v2.5 都是推理模型（实测：思维链分别在
        # reasoning_content / reasoning，content 要等推理结束才出现）。
        self.assertTrue(load_config(ZHIPU_ENV).is_reasoning_model)
        self.assertTrue(load_config(OC_ENV).is_reasoning_model)
        self.assertFalse(
            load_config({**ZHIPU_ENV, "SNAPQUIZ_MODEL": "glm-4v-flash"}).is_reasoning_model
        )

    def test_reasoning_profiles_get_enough_budget_and_time(self):
        """实测教训:推理模型用 1024 tokens / 30 秒会稳定失败。"""

        for profile in PROFILES.values():
            if not profile.reasoning_models:
                continue
            with self.subTest(provider=profile.provider_id):
                self.assertGreaterEqual(profile.max_output_tokens, 1024)
                self.assertGreaterEqual(profile.default_timeout, 30.0)
        # mimo 实测 141 秒、1172 completion tokens,必须给足
        self.assertGreaterEqual(OPENCODE_GO.max_output_tokens, 4096)
        self.assertGreaterEqual(OPENCODE_GO.default_timeout, 180.0)


class ConfigTest(unittest.TestCase):
    def test_config_never_holds_the_secret(self):
        cfg = load_config(ZHIPU_ENV)
        self.assertNotIn("zp-test-key", repr(cfg))
        for value in vars(cfg).values():
            self.assertNotEqual(value, "zp-test-key")

    def test_missing_api_key_fails(self):
        with self.assertRaises(ConfigError):
            load_config({"SNAPQUIZ_REGION": "0,0,10,10"})

    def test_region_is_required_no_fullscreen_fallback(self):
        with self.assertRaises(ConfigError) as ctx:
            load_config({"GLM_API_KEY": "k"})
        self.assertIn("SNAPQUIZ_REGION", str(ctx.exception))

    def test_region_stays_required_for_the_product_entrypoint(self):
        """require_region=False 只给文件输入的冒烟用;产品入口不得放宽。"""

        with self.assertRaises(ConfigError):
            load_config({"GLM_API_KEY": "k"})
        self.assertIsNone(load_config({"GLM_API_KEY": "k"}, require_region=False).region)

    def test_malformed_regions_fail(self):
        for raw in ("1,2,3", "a,b,c,d", "0,0,0,10", "0,0,10,-1", "0,0,99999,10"):
            with self.subTest(raw=raw), self.assertRaises(ConfigError):
                load_config({**ZHIPU_ENV, "SNAPQUIZ_REGION": raw})

    def test_custom_base_url_is_refused(self):
        with self.assertRaises(ConfigError):
            load_config({**ZHIPU_ENV, "SNAPQUIZ_BASE_URL": "https://evil.example/api"})

    def test_matching_base_url_is_tolerated(self):
        cfg = load_config({**ZHIPU_ENV, "SNAPQUIZ_BASE_URL": ZHIPU.base_url})
        self.assertIs(cfg.provider, ZHIPU)

    def test_timeout_bounds(self):
        for raw in ("0", "-5", "601", "abc"):
            with self.subTest(raw=raw), self.assertRaises(ConfigError):
                load_config({**ZHIPU_ENV, "SNAPQUIZ_TIMEOUT": raw})
        self.assertEqual(
            load_config({**ZHIPU_ENV, "SNAPQUIZ_TIMEOUT": "12.5"}).timeout, 12.5
        )

    def test_session_id_is_generated_and_overridable(self):
        generated = load_config(OC_ENV).session_id
        self.assertTrue(generated.startswith("ses_"))
        self.assertNotEqual(generated, load_config(OC_ENV).session_id)
        self.assertEqual(
            load_config({**OC_ENV, "OPENCODE_SESSION": "ses_fixed"}).session_id,
            "ses_fixed",
        )

    def test_resolve_api_key_reads_the_providers_env_var(self):
        cfg = Config(provider=OPENCODE_GO, model="mimo-v2.5")
        self.assertEqual(cfg.api_key_env, "OPENCODE_API_KEY")
        os.environ["OPENCODE_API_KEY"] = "  sk-secret  "
        try:
            self.assertEqual(resolve_api_key(cfg), "sk-secret")
        finally:
            del os.environ["OPENCODE_API_KEY"]
        with self.assertRaises(ConfigError):
            resolve_api_key(cfg)


if __name__ == "__main__":
    unittest.main()
