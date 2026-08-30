import unittest

from snapquiz.legacy_config import Config, ConfigError, load_config


class LoadConfigTest(unittest.TestCase):
    def valid_env(self, **overrides):
        env = {"GLM_API_KEY": "sk-xyz", "SNAPQUIZ_REGION": "10,20,300,400"}
        env.update(overrides)
        return env

    def test_reads_api_key(self):
        cfg = load_config(self.valid_env())
        self.assertEqual(cfg.api_key, "sk-xyz")

    def test_missing_api_key_raises(self):
        with self.assertRaises(ConfigError):
            load_config({})

    def test_blank_api_key_raises(self):
        with self.assertRaises(ConfigError):
            load_config({"GLM_API_KEY": "   "})

    def test_defaults_base_url_and_model(self):
        cfg = load_config(self.valid_env(GLM_API_KEY="k"))
        self.assertEqual(cfg.base_url, "https://open.bigmodel.cn/api/paas/v4")
        self.assertEqual(cfg.model, "glm-4.6v-flash")

    def test_arbitrary_base_url_is_rejected(self):
        with self.assertRaises(ConfigError):
            load_config(self.valid_env(GLM_BASE_URL="https://x/y"))

    def test_non_default_legacy_model_is_rejected(self):
        with self.assertRaises(ConfigError):
            load_config(self.valid_env(GLM_MODEL="glm-unknown"))

    def test_region_parsed_from_env(self):
        cfg = load_config(self.valid_env(GLM_API_KEY="k"))
        self.assertEqual(cfg.region, (10, 20, 300, 400))

    def test_region_absent_is_rejected(self):
        with self.assertRaises(ConfigError):
            load_config({"GLM_API_KEY": "k"})

    def test_malformed_region_raises(self):
        with self.assertRaises(ConfigError):
            load_config({"GLM_API_KEY": "k", "SNAPQUIZ_REGION": "10,20,oops"})

    def test_region_wrong_arity_raises(self):
        with self.assertRaises(ConfigError):
            load_config({"GLM_API_KEY": "k", "SNAPQUIZ_REGION": "10,20,30"})

    def test_non_positive_region_size_raises(self):
        with self.assertRaises(ConfigError):
            load_config({"GLM_API_KEY": "k", "SNAPQUIZ_REGION": "10,20,0,400"})

    def test_returns_config_instance(self):
        self.assertIsInstance(load_config(self.valid_env(GLM_API_KEY="k")), Config)

    def test_config_repr_does_not_expose_api_key(self):
        cfg = load_config(self.valid_env(GLM_API_KEY="secret-value"))
        self.assertNotIn("secret-value", repr(cfg))


if __name__ == "__main__":
    unittest.main()
