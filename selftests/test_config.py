import pytest

from optest.config import OpTestConfiguration, OpTestEnv

def test_config_args():
    args = {'bmc_type': 'QEMU'}
    c = OpTestConfiguration(overrides=args, env=None)
    assert c.args['bmc_type'] == 'QEMU'


def test_config_priority(tmpdir):
    with pytest.raises(KeyError):
        OpTestConfiguration(skip_user_conf=True)

    tmp_user_conf = tmpdir.join("userconf")
    tmp_user_conf.write("[op-test]\nhost_ip=testvalue\nbmc_type=1")
    env = OpTestEnv(tmp_user_conf)
    assert env.args.get('bmc_type') == '1'


    tmp_conf = tmpdir.join("conf")
    tmp_conf.write("[op-test]\nbmc_type=2")
    c = OpTestConfiguration(env=env, config=str(tmp_conf))
    assert c.args.get('bmc_type') == '2'

    args = {'bmc_type': '3'}
    c = OpTestConfiguration(env=env,
                            config=str(tmp_conf),
                            overrides=args)
    assert c.args.get('bmc_type') == '3'

# hostlocker / aes tests?
