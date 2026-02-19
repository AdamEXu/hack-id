"""Per-API-key rate limiting utilities."""

import time
import threading
from collections import defaultdict, deque
from typing import Dict, Optional
from models.api_key import get_key_rate_limit


class APIKeyRateLimiter:
    """
    In-memory rate limiter for API keys using sliding window approach.
    Each API key has its own rate limit (RPM) that can be configured.
    """

    def __init__(self):
        self._requests = defaultdict(deque)  # api_key -> deque of timestamps
        self._lock = threading.Lock()

    def is_allowed(self, api_key: str) -> tuple[bool, Dict]:
        """
        Check if request is allowed for the given API key.

        Returns:
            tuple: (is_allowed: bool, info: dict)
            info contains: rate_limit, current_count, reset_time
        """
        with self._lock:
            # Get rate limit for this API key
            rate_limit_rpm = get_key_rate_limit(api_key)

            if rate_limit_rpm <= 0:
                # Unlimited rate limit
                return True, {
                    "rate_limit": "unlimited",
                    "current_count": 0,
                    "reset_time": None,
                }

            current_time = time.time()
            window_start = current_time - 60  # 60 seconds window for RPM

            # Get or create request queue for this API key
            request_queue = self._requests[api_key]

            # Remove old requests outside the window
            while request_queue and request_queue[0] < window_start:
                request_queue.popleft()

            current_count = len(request_queue)

            # Check if we're under the limit
            if current_count < rate_limit_rpm:
                # Add current request timestamp
                request_queue.append(current_time)
                return True, {
                    "rate_limit": rate_limit_rpm,
                    "current_count": current_count + 1,
                    "reset_time": int(
                        window_start + 60
                    ),  # When the oldest request will expire
                }
            else:
                # Rate limit exceeded
                return False, {
                    "rate_limit": rate_limit_rpm,
                    "current_count": current_count,
                    "reset_time": int(
                        request_queue[0] + 60
                    ),  # When the oldest request will expire
                }

    def get_stats(self, api_key: str) -> Dict:
        """Get current rate limiting stats for an API key."""
        with self._lock:
            rate_limit_rpm = get_key_rate_limit(api_key)
            current_time = time.time()
            window_start = current_time - 60

            request_queue = self._requests[api_key]

            # Remove old requests
            while request_queue and request_queue[0] < window_start:
                request_queue.popleft()

            current_count = len(request_queue)

            return {
                "rate_limit": rate_limit_rpm if rate_limit_rpm > 0 else "unlimited",
                "current_count": current_count,
                "remaining": (
                    max(0, rate_limit_rpm - current_count)
                    if rate_limit_rpm > 0
                    else "unlimited"
                ),
                "reset_time": (
                    int(request_queue[0] + 60)
                    if request_queue
                    else int(current_time + 60)
                ),
            }

    def reset_key(self, api_key: str):
        """Reset rate limiting for a specific API key (admin function)."""
        with self._lock:
            if api_key in self._requests:
                del self._requests[api_key]

    def cleanup_old_entries(self):
        """Clean up old entries to prevent memory leaks."""
        with self._lock:
            current_time = time.time()
            window_start = current_time - 60

            keys_to_remove = []
            for api_key, request_queue in self._requests.items():
                # Remove old requests
                while request_queue and request_queue[0] < window_start:
                    request_queue.popleft()

                # If queue is empty, mark key for removal
                if not request_queue:
                    keys_to_remove.append(api_key)

            # Remove empty queues
            for api_key in keys_to_remove:
                del self._requests[api_key]


# Global rate limiter instance
api_rate_limiter = APIKeyRateLimiter()


def check_api_key_rate_limit(api_key: str) -> tuple[bool, Dict]:
    """
    Check if API key is within rate limit.

    Returns:
        tuple: (is_allowed: bool, rate_info: dict)
    """
    return api_rate_limiter.is_allowed(api_key)


def get_api_key_rate_stats(api_key: str) -> Dict:
    """Get rate limiting statistics for an API key."""
    return api_rate_limiter.get_stats(api_key)


def reset_api_key_rate_limit(api_key: str):
    """Reset rate limit for an API key (admin function)."""
    api_rate_limiter.reset_key(api_key)


def cleanup_rate_limiter():
    """Clean up old rate limiting entries."""
    api_rate_limiter.cleanup_old_entries()


# Background cleanup function (can be called periodically)
def start_cleanup_thread():
    """Start a background thread to clean up old rate limiting entries."""
    import threading
    import time
    from utils.db_init import cleanup_expired_records

    def cleanup_worker():
        while True:
            time.sleep(300)  # Clean up every 5 minutes
            cleanup_rate_limiter()
            cleanup_expired_records()

    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()


# Rate limiting decorator for API endpoints
def rate_limit_api_key(f):
    """
    Decorator to apply per-API-key rate limiting to endpoints.
    Should be used after the API key authentication decorator.
    Disabled in development mode.
    """
    from functools import wraps
    from flask import request, jsonify, g
    from config import DEBUG_MODE

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip rate limiting in development mode
        if DEBUG_MODE:
            return f(*args, **kwargs)

        # Get API key from request headers
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            # No API key, let the auth decorator handle it
            return f(*args, **kwargs)

        api_key = auth_header[7:]  # Remove "Bearer " prefix

        # Check rate limit
        is_allowed, rate_info = check_api_key_rate_limit(api_key)

        if not is_allowed:
            response = jsonify(
                {
                    "success": False,
                    "error": "Rate limit exceeded",
                    "rate_limit": rate_info["rate_limit"],
                    "current_count": rate_info["current_count"],
                    "reset_time": rate_info["reset_time"],
                }
            )
            response.status_code = 429

            # Add rate limiting headers
            response.headers["X-RateLimit-Limit"] = str(rate_info["rate_limit"])
            response.headers["X-RateLimit-Remaining"] = "0"
            response.headers["X-RateLimit-Reset"] = str(rate_info["reset_time"])

            return response

        # Add rate limiting info to response headers
        response = f(*args, **kwargs)
        if hasattr(response, "headers"):
            response.headers["X-RateLimit-Limit"] = str(rate_info["rate_limit"])
            response.headers["X-RateLimit-Remaining"] = str(
                rate_info["rate_limit"] - rate_info["current_count"]
            )
            response.headers["X-RateLimit-Reset"] = str(rate_info["reset_time"])

        return response

    return decorated_function


# Utility function to validate rate limit values
def validate_rate_limit(rate_limit_rpm: int) -> bool:
    """Validate that rate limit is within acceptable bounds."""
    if rate_limit_rpm < 0:
        return False
    if rate_limit_rpm > 10000:  # Max 10k requests per minute
        return False
    return True


def get_recommended_rate_limits() -> Dict[str, int]:
    """Get recommended rate limits for different use cases."""
    return {
        "development": 60,  # 1 request per second
        "testing": 120,  # 2 requests per second
        "production_light": 300,  # 5 requests per second
        "production_heavy": 600,  # 10 requests per second
        "unlimited": 0,  # No rate limit
    }
