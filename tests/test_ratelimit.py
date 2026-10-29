import pytest

from iptable_lite.ratelimit import RateLimiter


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def limiter(clock):
    return RateLimiter(clock=clock)


class TestBurst:
    def test_allows_the_whole_burst_up_front(self, limiter):
        assert [limiter.allow("rule", 1, 3) for _ in range(3)] == [True, True, True]

    def test_denies_once_the_burst_is_spent(self, limiter):
        for _ in range(3):
            limiter.allow("rule", 1, 3)
        assert limiter.allow("rule", 1, 3) is False

    def test_tokens_never_go_negative(self, limiter, clock):
        for _ in range(5):
            limiter.allow("rule", 1, 2)
        assert limiter.tokens("rule") == 0
        clock.advance(0.5)
        assert limiter.allow("rule", 1, 2) is False


class TestRefill:
    def test_refills_at_the_configured_rate(self, limiter, clock):
        limiter.allow("rule", 1, 1)  # spend the only token
        assert limiter.allow("rule", 1, 1) is False
        clock.advance(0.5)
        assert limiter.allow("rule", 1, 1) is False  # only half a token
        clock.advance(0.5)
        assert limiter.allow("rule", 1, 1) is True

    def test_refill_is_capped_at_the_burst(self, limiter, clock):
        limiter.allow("rule", 1, 2)
        clock.advance(3600)
        assert limiter.tokens("rule") == 2
        assert limiter.allow("rule", 1, 2) is True
        assert limiter.allow("rule", 1, 2) is True
        assert limiter.allow("rule", 1, 2) is False

    def test_activity_does_not_add_tokens_beyond_the_burst(self, limiter, clock):
        for _ in range(2):
            limiter.allow("rule", 1, 2)
        clock.advance(0.25)
        limiter.allow("rule", 1, 2)  # denied, but still refills 0.25
        clock.advance(0.75)
        assert limiter.tokens("rule") == 1


class TestIsolation:
    def test_different_rules_have_separate_buckets(self, limiter):
        assert limiter.allow("rule-a", 1, 1) is True
        assert limiter.allow("rule-a", 1, 1) is False
        assert limiter.allow("rule-b", 1, 1) is True

    def test_len_counts_buckets(self, limiter):
        assert len(limiter) == 0
        limiter.allow("rule-a", 1, 1)
        limiter.allow("rule-b", 1, 1)
        limiter.allow("rule-a", 1, 1)
        assert len(limiter) == 2

    def test_tokens_for_unknown_key_is_none(self, limiter):
        assert limiter.tokens("nope") is None


class TestValidation:
    @pytest.mark.parametrize("rate", [0, -1, -0.5])
    def test_rate_must_be_positive(self, limiter, rate):
        with pytest.raises(ValueError, match="rate"):
            limiter.allow("rule", rate, 1)

    @pytest.mark.parametrize("burst", [0, -1])
    def test_burst_must_be_positive(self, limiter, burst):
        with pytest.raises(ValueError, match="burst"):
            limiter.allow("rule", 1, burst)
