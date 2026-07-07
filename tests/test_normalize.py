from drbt import normalize_windows_fields


def test_maps_security_4688_fields_to_sysmon():
    rec = {
        "EventID": 4688,
        "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentProcessName": "C:\\Windows\\System32\\regsvr32.exe",
        "CommandLine": "powershell.exe -enc AAA",
    }
    out = normalize_windows_fields(rec)
    assert out["Image"] == rec["NewProcessName"]
    assert out["ParentImage"] == rec["ParentProcessName"]
    # Original keys are preserved alongside the canonical ones.
    assert out["NewProcessName"] == rec["NewProcessName"]


def test_does_not_overwrite_existing_sysmon_fields():
    rec = {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "NewProcessName": "should-not-win",
    }
    out = normalize_windows_fields(rec)
    assert out["Image"] == "C:\\Windows\\System32\\cmd.exe"


def test_ignores_empty_source_fields():
    rec = {"EventID": 1, "NewProcessName": "", "CommandLine": "x"}
    out = normalize_windows_fields(rec)
    assert "Image" not in out
