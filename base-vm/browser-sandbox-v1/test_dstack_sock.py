import json,pathlib,sys
here=pathlib.Path(__file__).parent
sys.path.insert(0,str(here/'source/runner-content/lib'))
from dsmack_compose_contract.manifest import validate_compose_document
from dsmack_compose_contract.lowering import _service_mounts

# The convergence compose binds /var/run/dstack.sock; it must validate and lower to the worker's agent socket.
COMPOSE=(here/'../../dstack-compat/docker-compose.json').read_text()
MANIFEST={'docker_compose_file':COMPOSE,'allowed_files':[],'allowed_envs':[],'runtime_inputs':{'user_config':{'mode':'none'}}}

def test_dstack_sock_bind_validates_and_lowers_to_the_service_socket():
    errors=[];validate_compose_document(json.loads(COMPOSE),MANIFEST,errors)
    assert [str(e) for e in errors]==[]
    m=_service_mounts(MANIFEST,'worker','/w')[-1]
    assert (m['source'],m['target'],m['mode'])==('/run/dsmack-agent/worker.sock','/var/run/dstack.sock','ro')
