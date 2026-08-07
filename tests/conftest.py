"""Shared pytest configuration.

Registers a Hypothesis profile without a per-example deadline. The property tests run
max_examples=500 against real loaders on real fixtures, and Hypothesis' default 200ms
deadline measures wall-clock, so on a loaded CI runner a correct example fails purely
for being scheduled late. The job timeout is the real backstop.
"""

from hypothesis import HealthCheck, settings

settings.register_profile(
    "smda",
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("smda")
