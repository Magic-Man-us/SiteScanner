import types

from sitescanner.scanners.pymetasploit_runner import PymetasploitRunner


def test_pymetasploit_runner_list_exploits(monkeypatch):
    # Create a fake MsfRpcClient with minimal interface used by PymetasploitRunner
    class FakeModules:
        def __init__(self):
            self.exploits = ["exploit/linux/nginx_fake", "exploit/multi/apache_mod"]

    class FakeClient:
        def __init__(self, password, server, port, ssl, user):
            self.modules = FakeModules()

        def get_module_options(self, name):
            if name == "exploit/linux/nginx_fake":
                return {"description": "nginx remote code execution", "references": ["CVE-XXXX"]}
            if name == "exploit/multi/apache_mod":
                return {"description": "apache module issue", "references": []}
            msg = "unknown module"
            raise RuntimeError(msg)

    # Monkeypatch the imported class in the pymetasploit wrapper import path
    fake_module = types.SimpleNamespace(msfrpc=types.SimpleNamespace(MsfRpcClient=FakeClient))

    monkeypatch.setitem(__import__("sys").modules, "pymetasploit3", fake_module)
    monkeypatch.setitem(__import__("sys").modules, "pymetasploit3.msfrpc", fake_module.msfrpc)

    runner = PymetasploitRunner(
        host="127.0.0.1", port=55553, user="user", password="pass", ssl=False
    )

    # Run list_exploits with a fingerprint that should match one of the fake modules
    results = list(runner.list_exploits("nginx"))
    assert any("nginx" in info.name for info in results)
