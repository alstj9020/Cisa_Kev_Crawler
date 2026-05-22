from cisa_kev_crawler.config import CrawlerConfig, load_config


def test_load_config_defaults(monkeypatch):
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("REQUEST_TIMEOUT", raising=False)
    config = load_config()
    assert config.output_dir == "output"
    assert config.nvd_api_key is None
    assert config.request_timeout == 30


def test_load_config_from_env(monkeypatch):
    monkeypatch.setenv("OUTPUT_DIR", "/tmp/out")
    monkeypatch.setenv("NVD_API_KEY", "my-secret-key")
    monkeypatch.setenv("REQUEST_TIMEOUT", "60")
    config = load_config()
    assert config.output_dir == "/tmp/out"
    assert config.nvd_api_key == "my-secret-key"
    assert config.request_timeout == 60


def test_crawler_config_is_dataclass():
    config = CrawlerConfig(output_dir="out", nvd_api_key=None, request_timeout=30)
    assert config.output_dir == "out"
