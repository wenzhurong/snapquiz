import unittest

from snapquiz.config import Config, ConfigError, load_config


class LoadConfigTest(unittest.TestCase):
    def test_reads_api_key(self):
        cfg = load_config({"GLM_API_KEY": "sk-xyz"})
        self.assertEqual(cfg.api_key, "sk-xyz")

    def test_missing_api_key_raises(self):
        with self.assertRaises(ConfigError):
            load_config({})

    def test_blank_api_key_raises(self):
        with self.assertRaises(ConfigError):
            load_config({"GLM_API_KEY": "   "})

    def test_defaults_base_url_and_model(self):
        cfg = load_config({"GLM_API_KEY": "k"})
        self.assertEqual(cfg.base_url, "https://open.bigmodel.cn/api/paas/v4")
        self.assertEqual(cfg.model, "glm-4.6v-flash")

    def test_overrides_base_url_and_model(self):
        cfg = load_config(
            {"GLM_API_KEY": "k", "GLM_BASE_URL": "https://x/y", "GLM_MODEL": "glm-4.6v"}
        )
        self.assertEqual(cfg.base_url, "https://x/y")
        self.assertEqual(cfg.model, "glm-4.6v")

    def test_region_parsed_from_env(self):
        cfg = load_config({"GLM_API_KEY": "k", "SNAPQUIZ_REGION": "10,20,300,400"})
        self.assertEqual(cfg.region, (10, 20, 300, 400))

    def test_region_absent_is_none(self):
        cfg = load_config({"GLM_API_KEY": "k"})
        self.assertIsNone(cfg.region)

    def test_malformed_region_raises(self):
        with self.assertRaises(ConfigError):
            load_config({"GLM_API_KEY": "k", "SNAPQUIZ_REGION": "10,20,oops"})

    def test_region_wrong_arity_raises(self):
        with self.assertRaises(ConfigError):
            load_config({"GLM_API_KEY": "k", "SNAPQUIZ_REGION": "10,20,30"})

    def test_returns_config_instance(self):
        self.assertIsInstance(load_config({"GLM_API_KEY": "k"}), Config)


if __name__ == "__main__":
    unittest.main()
