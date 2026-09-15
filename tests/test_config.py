import unittest

from snapquiz.config import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    Config,
    ConfigError,
    load_config,
    resolve_api_key,
)

BASE_ENV = {"GLM_API_KEY": "zp-test-key", "SNAPQUIZ_REGION": "10,20,640,480"}


class ConfigTest(unittest.TestCase):
    def test_minimal_env_loads(self):
        cfg = load_config(BASE_ENV)
        self.assertEqual(cfg.region, (10, 20, 640, 480))
        self.assertEqual(cfg.model, DEFAULT_MODEL)
        self.assertEqual(
            cfg.endpoint_url, DEFAULT_BASE_URL + "/chat/completions"
        )

    def test_config_never_holds_the_secret(self):
        cfg = load_config(BASE_ENV)
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

    def test_malformed_regions_fail(self):
        for raw in ("1,2,3", "a,b,c,d", "0,0,0,10", "0,0,10,-1", "0,0,99999,10", ""):
            with self.subTest(raw=raw), self.assertRaises(ConfigError):
                load_config({**BASE_ENV, "SNAPQUIZ_REGION": raw})

    def test_custom_base_url_is_refused(self):
        with self.assertRaises(ConfigError):
            load_config({**BASE_ENV, "GLM_BASE_URL": "https://evil.example/api"})

    def test_unknown_model_is_refused(self):
        with self.assertRaises(ConfigError):
            load_config({**BASE_ENV, "GLM_MODEL": "gpt-4o"})

    def test_known_alternate_model_is_allowed(self):
        cfg = load_config({**BASE_ENV, "GLM_MODEL": "glm-4.6v"})
        self.assertEqual(cfg.model, "glm-4.6v")

    def test_timeout_bounds(self):
        for raw in ("0", "-5", "301", "abc"):
            with self.subTest(raw=raw), self.assertRaises(ConfigError):
                load_config({**BASE_ENV, "SNAPQUIZ_TIMEOUT": raw})
        self.assertEqual(load_config({**BASE_ENV, "SNAPQUIZ_TIMEOUT": "12.5"}).timeout, 12.5)

    def test_region_stays_required_for_the_product_entrypoint(self):
        """require_region=False 只给文件输入的冒烟用;产品入口不得放宽。"""

        with self.assertRaises(ConfigError):
            load_config({"GLM_API_KEY": "k"})
        cfg = load_config({"GLM_API_KEY": "k"}, require_region=False)
        self.assertIsNone(cfg.region)

    def test_resolve_api_key_reads_process_env(self):
        import os

        cfg = Config(region=(0, 0, 1, 1), api_key_env="SNAPQUIZ_TEST_KEY")
        os.environ["SNAPQUIZ_TEST_KEY"] = "  secret-value  "
        try:
            self.assertEqual(resolve_api_key(cfg), "secret-value")
        finally:
            del os.environ["SNAPQUIZ_TEST_KEY"]
        with self.assertRaises(ConfigError):
            resolve_api_key(cfg)


if __name__ == "__main__":
    unittest.main()
