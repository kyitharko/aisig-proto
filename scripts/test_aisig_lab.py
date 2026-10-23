#!/usr/bin/env python3
"""Offline contract tests for scripts/aisig_lab.py; no Docker or model needed."""

import importlib.util
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("aisig_lab", Path(__file__).with_name("aisig_lab.py"))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.root_patch = patch.object(lab, "ROOT", root)
        self.local_patch = patch.object(lab, "LOCAL", root / "local-experiments")
        self.root_patch.start()
        self.local_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.local_patch.stop)

    def config(self, ip=None):
        lab.configure(SimpleNamespace(session="trial1", access_ip=ip))
        return json.loads((lab.LOCAL / "trial1" / "config.json").read_text())

    def test_session_names_prevent_path_traversal(self):
        for name in ("../escape", "two/slashes", ".hidden", "", "bad name", "a" * 51):
            with self.subTest(name=name), self.assertRaises(lab.LabError):
                lab.session_dir(name)
        self.assertEqual(lab.session_dir("trial-01"), lab.LOCAL / "trial-01")

    def test_private_access_accepts_cgnat_and_rfc1918_only(self):
        for ip in ("100.76.54.32", "192.168.99.10", "10.1.2.3", "172.20.1.5"):
            self.assertEqual(lab.trusted_address(ip), ip)
        for ip in ("0.0.0.0", "127.0.0.1", "8.8.8.8", "2001:db8::1", "100.x.y.z"):
            with self.subTest(ip=ip), self.assertRaises(lab.LabError):
                lab.trusted_address(ip)

    def test_local_configuration_is_ignored_and_not_overwritten(self):
        cfg = self.config()
        self.assertIsNone(cfg["access_ip"])
        path = lab.LOCAL / "trial1" / "config.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(lab.load_config("trial1")[0], cfg)
        with self.assertRaises(lab.LabError):
            self.config()

    def test_private_configuration_requires_a_host_interface(self):
        with patch.object(lab, "assigned_ipv4", return_value={"100.76.54.32"}):
            cfg = self.config("100.76.54.32")
        self.assertEqual(cfg["mode"], "private-ip")
        command, env = lab.compose(cfg)
        self.assertEqual(command, ["docker", "compose", "-f", lab.BASE, "-f", lab.ACCESS])
        self.assertEqual(env["AISIG_DEMO_ACCESS_IP"], "100.76.54.32")

    def test_unassigned_access_ip_fails_before_creating_session(self):
        with patch.object(lab, "assigned_ipv4", return_value={"10.1.1.2"}):
            with self.assertRaises(lab.LabError):
                self.config("100.76.54.32")
        self.assertFalse((lab.LOCAL / "trial1").exists())

    def test_local_compose_removes_inherited_access_ip(self):
        cfg = self.config()
        with patch.dict(lab.os.environ, AISIG_DEMO_ACCESS_IP="100.76.54.32"):
            command, env = lab.compose(cfg)
        self.assertEqual(command, ["docker", "compose", "-f", lab.BASE])
        self.assertNotIn("AISIG_DEMO_ACCESS_IP", env)

    def test_setup_checks_config_builds_and_recreates_before_health(self):
        self.config()
        args = SimpleNamespace(session="trial1", pull_model=True)
        with patch.object(lab, "doctor", return_value=0), \
             patch.object(lab, "run", return_value=SimpleNamespace(returncode=0)) as run, \
             patch.object(lab, "controller_url", return_value="http://172.20.1.8:8787"), \
             patch.object(lab, "health") as health:
            lab.setup(args)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[0], ["cargo", "build", "--release", "--bin", "demo_controller"])
        self.assertEqual(commands[1][-2:], ["config", "--quiet"])
        self.assertEqual(commands[2][-3:], ["up", "-d", "--force-recreate"])
        self.assertEqual(commands[3][-6:-1], ["exec", "-T", "ollama", "ollama", "pull"])
        self.assertEqual(commands[3][-1], lab.MODEL)
        health.assert_called_once_with("http://172.20.1.8:8787", attempts=12)

    def test_full_model_absent_does_not_start_the_collector(self):
        self.config()
        args = SimpleNamespace(session="trial1", mode="full")
        with patch.object(lab, "controller_url", return_value="http://172.20.1.8:8787"), \
             patch.object(lab, "health"), patch.object(lab, "model_available", return_value=False), \
             patch.object(lab, "run") as run:
            with self.assertRaises(lab.LabError):
                lab.experiment(args)
            run.assert_not_called()
        self.assertEqual(list((lab.LOCAL / "trial1").glob("full-*")), [])

    def test_controls_are_isolated_and_failure_stays_failed(self):
        self.config()
        args = SimpleNamespace(session="trial1", mode="controls")
        with patch.object(lab, "controller_url", return_value="http://172.20.1.8:8787"), \
             patch.object(lab, "health"), patch.object(lab, "run") as command, \
             patch.object(lab, "render") as render:
            command.side_effect = [SimpleNamespace(returncode=7),
                                   SimpleNamespace(returncode=0, stdout="deadbeef\n")]
            self.assertEqual(lab.experiment(args), 7)
            collector_env = command.call_args_list[0].kwargs["env"]
            self.assertEqual(collector_env["AISIG_SKIP_MODEL"], "1")
            self.assertIn("local-experiments/trial1/controls-", collector_env["AISIG_OUTPUT_DIR"])
            render.assert_not_called()
        runs = list((lab.LOCAL / "trial1").glob("controls-*/run_manifest.json"))
        self.assertEqual(len(runs), 1)
        self.assertEqual(json.loads(runs[0].read_text())["collector_returncode"], 7)

    def test_full_run_generates_a_report_only_after_success(self):
        self.config()
        args = SimpleNamespace(session="trial1", mode="full")
        with patch.object(lab, "controller_url", return_value="http://172.20.1.8:8787"), \
             patch.object(lab, "health"), patch.object(lab, "model_available", return_value=True), \
             patch.object(lab, "run") as command, patch.object(lab, "render") as render:
            command.side_effect = [SimpleNamespace(returncode=0),
                                   SimpleNamespace(returncode=0, stdout="deadbeef\n")]
            self.assertEqual(lab.experiment(args), 0)
            collector_env = command.call_args_list[0].kwargs["env"]
            self.assertNotIn("AISIG_SKIP_MODEL", collector_env)
            render.assert_called_once()
        manifests = list((lab.LOCAL / "trial1").glob("full-*/run_manifest.json"))
        self.assertEqual(len(manifests), 1)
        self.assertEqual(json.loads(manifests[0].read_text())["git_commit"], "deadbeef")

    def test_report_rejects_outside_or_failed_results(self):
        self.config()
        elsewhere = lab.ROOT / "elsewhere"
        elsewhere.mkdir()
        with self.assertRaises(lab.LabError):
            lab.report(SimpleNamespace(session="trial1", result_dir=str(elsewhere)))
        failed = lab.LOCAL / "trial1" / "full-failed"
        failed.mkdir()
        (failed / "run_manifest.json").write_text('{"collector_returncode":1}')
        with self.assertRaises(lab.LabError):
            lab.report(SimpleNamespace(session="trial1", result_dir=str(failed)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
