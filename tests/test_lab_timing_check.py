from tools import lab_timing_check as ltc


def test_attacker_check_uses_the_real_scheduler_and_sends_nothing(monkeypatch):
    sent = []
    monkeypatch.setattr(ltc.NullSender, "send", lambda self, packet: sent.append(bytes(packet)))
    result = ltc.check_attacker(0.5, rate=20)
    assert result["scheduled"] == 10 and result["delivered"] == len(sent)
    assert result["share"] == round(result["delivered"] / 10, 4)
    assert result["pass"] is (result["share"] >= ltc.ATTACK_MIN_SHARE)


def test_client_check_uses_a_mock_transport():
    result = ltc.check_client(0.5, rate=10)
    assert result["scheduled"] == 5 and 0 < result["delivered"] <= 5
    assert result["pass"] is (result["share"] >= ltc.CLIENT_MIN_SHARE)


def test_main_exit_code_follows_the_result(monkeypatch, capsys):
    monkeypatch.setattr(ltc, "check_client", lambda duration: {"pass": False, "duration": duration})
    assert ltc.main(["--role", "client", "--duration", "1"]) == 1
    monkeypatch.setattr(ltc, "check_client", lambda duration: {"pass": True, "duration": duration})
    assert ltc.main(["--role", "client"]) == 0
    assert '"duration": 20.0' in capsys.readouterr().out
