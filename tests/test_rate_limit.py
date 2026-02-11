import time
import pytest
from pathlib import Path
from importlib.machinery import SourceFileLoader
import sys

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "Back-end"

def load_backend(tmp_path):
    # Add backend dir to sys.path so app.model and other imports work
    if str(BACKEND_DIR) not in sys.path:
        sys.path.insert(0, str(BACKEND_DIR))
    
    # Load the module
    module = SourceFileLoader("template_backend_rl", str(BACKEND_DIR / "Template-backend.py")).load_module()
    
    # Mock some paths and settings
    module.DB_PATH = tmp_path / "test_rl.db"
    module.UPLOAD_DIR = tmp_path / "uploads_rl"
    module._db_initialized = False
    # Ensure RATE_BUCKETS is fresh
    module.RATE_BUCKETS = {}
    
    module.app.config.update(TESTING=True)
    return module

@pytest.fixture
def backend(tmp_path):
    return load_backend(tmp_path)

def test_rate_limited_happy_path(backend):
    """Test that multiple calls within the limit return False."""
    with backend.app.test_request_context(environ_base={'REMOTE_ADDR': '1.2.3.4'}):
        # Limit of 3
        limit = 3
        action = "test_action"
        
        # 1st call
        limited, retry = backend.is_rate_limited(action, limit, window_sec=60)
        assert not limited
        assert retry == 0
        
        # 2nd call
        limited, retry = backend.is_rate_limited(action, limit, window_sec=60)
        assert not limited
        assert retry == 0
        
        # 3rd call
        limited, retry = backend.is_rate_limited(action, limit, window_sec=60)
        assert not limited
        assert retry == 0

def test_rate_limited_exceeded(backend):
    """Test that calls exceeding the limit return True."""
    with backend.app.test_request_context(environ_base={'REMOTE_ADDR': '1.2.3.4'}):
        limit = 2
        action = "test_action"
        
        # 1st and 2nd calls
        backend.is_rate_limited(action, limit, window_sec=60)
        backend.is_rate_limited(action, limit, window_sec=60)
        
        # 3rd call (exceeds limit)
        limited, retry = backend.is_rate_limited(action, limit, window_sec=60)
        assert limited
        assert retry > 0
        assert retry <= 60

def test_rate_limited_different_ips(backend):
    """Test that rate limits are separate for different IPs."""
    action = "test_action"
    limit = 1
    
    # IP 1
    with backend.app.test_request_context(environ_base={'REMOTE_ADDR': '1.1.1.1'}):
        limited, _ = backend.is_rate_limited(action, limit)
        assert not limited
        
        # IP 1 is now limited
        limited, _ = backend.is_rate_limited(action, limit)
        assert limited

    # IP 2
    with backend.app.test_request_context(environ_base={'REMOTE_ADDR': '2.2.2.2'}):
        # IP 2 should NOT be limited yet
        limited, _ = backend.is_rate_limited(action, limit)
        assert not limited

def test_rate_limited_different_actions(backend):
    """Test that rate limits are separate for different actions."""
    ip = '1.2.3.4'
    limit = 1
    
    with backend.app.test_request_context(environ_base={'REMOTE_ADDR': ip}):
        # Action 1
        limited, _ = backend.is_rate_limited("action1", limit)
        assert not limited
        
        # Action 1 is now limited
        limited, _ = backend.is_rate_limited("action1", limit)
        assert limited
        
        # Action 2 should NOT be limited yet
        limited, _ = backend.is_rate_limited("action2", limit)
        assert not limited

def test_rate_limited_window_expiry(backend, monkeypatch):
    """Test that rate limit resets after the window expires."""
    with backend.app.test_request_context(environ_base={'REMOTE_ADDR': '1.2.3.4'}):
        limit = 1
        action = "test_action"
        window = 10
        
        current_time = 1000.0
        monkeypatch.setattr(time, "time", lambda: current_time)
        
        # 1st call
        limited, _ = backend.is_rate_limited(action, limit, window_sec=window)
        assert not limited
        
        # 2nd call (same time, limited)
        limited, _ = backend.is_rate_limited(action, limit, window_sec=window)
        assert limited
        
        # Advance time beyond window
        current_time += 11.0
        
        # 3rd call (should be allowed now)
        limited, retry = backend.is_rate_limited(action, limit, window_sec=window)
        assert not limited
        assert retry == 0

def test_rate_limited_zero_limit(backend):
    """Test that a limit of 0 or less disables rate limiting."""
    with backend.app.test_request_context(environ_base={'REMOTE_ADDR': '1.2.3.4'}):
        action = "test_action"
        
        # Limit 0
        limited, _ = backend.is_rate_limited(action, 0)
        assert not limited
        
        # Limit -1
        limited, _ = backend.is_rate_limited(action, -1)
        assert not limited

def test_rate_limited_xff_header(backend):
    """Test that client_ip correctly uses X-Forwarded-For header."""
    action = "test_action"
    limit = 1
    
    # Request with X-Forwarded-For
    with backend.app.test_request_context(headers={'X-Forwarded-For': '10.0.0.1, 10.0.0.2'}):
        limited, _ = backend.is_rate_limited(action, limit)
        assert not limited
        
        # Check that it recorded for 10.0.0.1
        assert f"{action}:10.0.0.1" in backend.RATE_BUCKETS
