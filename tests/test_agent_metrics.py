import sys
from pathlib import Path

import pytest

pytest.importorskip("docker")
pytest.importorskip("smbclient")

sys.path.insert(0, str(Path(__file__).parents[1]))

from agent import collect_containers, docker_uptime_seconds  # noqa: E402


class FakeContainer:
    id = "container-id"
    name = "synthetic-container"
    short_id = "container"
    status = "running"
    attrs = {
        "State": {
            "Running": True,
            "Status": "running",
            "StartedAt": "2026-08-16T20:00:00Z",
        },
        "Config": {"Labels": {}},
        "HostConfig": {},
        "Mounts": [],
        "NetworkSettings": {},
    }

    def stats(self, stream=False):
        assert stream is False
        return {"memory_stats": {"usage": 10, "limit": 100}}


class FakeAPI:
    def _url(self, path, container_id):
        assert path == "/containers/{0}/json"
        assert container_id == "container-id"
        return "/containers/container-id/json"

    def _get(self, url, params=None):
        assert url == "/containers/container-id/json"
        assert params == {"size": "1"}
        return FakeResponse()


class FakeResponse:
    def json(self):
        return {"SizeRw": 104857600}


class FakeContainers:
    def list(self, all=False):
        assert all is True
        return [FakeContainer()]


class FakeClient:
    containers = FakeContainers()
    api = FakeAPI()


def test_docker_uptime_seconds_parses_started_at():
    assert docker_uptime_seconds("2020-01-01T00:00:00Z") > 0
    assert docker_uptime_seconds(None) is None


def test_collect_containers_reports_uptime_and_size_rw():
    workload = collect_containers(FakeClient())[0]
    assert workload["storage_used"] == 104857600
    assert workload["storage_total"] is None
    assert workload["uptime_seconds"] > 0
    assert workload["memory_used"] == 10
