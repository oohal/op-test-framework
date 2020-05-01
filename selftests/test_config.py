import pytest

from optest.config import OpTestConfiguration

def test_config_args():
    args = {'bmc_type': 'QEMU'}
    c = OpTestConfiguration(overrides=args)
    assert c.args['bmc_type'] == 'QEMU'


def test_config_priority(tmpdir):
    with pytest.raises(KeyError):
        OpTestConfiguration(skip_user_conf=True)

    tmp_user_conf = tmpdir.join("userconf")
    tmp_user_conf.write("[op-test]\nhost_ip=testvalue\nbmc_type=1")
    c = OpTestConfiguration(user_config=str(tmp_user_conf))
    assert c.args.get('bmc_type') == '1'


    tmp_conf = tmpdir.join("conf")
    tmp_conf.write("[op-test]\nbmc_type=2")
    c = OpTestConfiguration(user_config=str(tmp_user_conf), config=str(tmp_conf))
    assert c.args.get('bmc_type') == '2'

    args = {'bmc_type': '3'}
    c = OpTestConfiguration(user_config=str(tmp_user_conf),
                            config=str(tmp_conf),
                            overrides=args)
    assert c.args.get('bmc_type') == '3'

def test_config_qemu():
    c = OpTestConfiguration(config="test_data/qemu.conf",
                            skip_user_config=True)
    qemu = c.create_system()
    qemu.host_power_on()
    qemu.waitfor('petitboot')


# hostlocker / aes tests?
