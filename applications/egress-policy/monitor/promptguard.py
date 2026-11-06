"""Offline, single-thread CPU PromptGuard worker. No input or decisions are logged."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
REGISTRY = json.loads((ROOT / 'registry.json').read_text())


def verify_files(directory):
    for name, digest in REGISTRY['baseline-pg2']['files'].items():
        path = directory / name
        kind, expected = digest.split(':')
        hasher = hashlib.sha256() if kind == 'sha256' else hashlib.sha1()
        if kind == 'git-sha1':
            hasher.update(b'blob ' + str(path.stat().st_size).encode() + b'\0')
        with path.open('rb') as source:
            while block := source.read(1 << 20):
                hasher.update(block)
        if hasher.hexdigest() != expected:
            raise ValueError('upstream model digest mismatch: ' + name)


def deny_network():
    """The classifier has no socket syscalls, including after a library import."""
    sec = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    sec.seccomp_init.argtypes = [ctypes.c_uint32]
    sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    sec.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    sec.seccomp_load.argtypes = [ctypes.c_void_p]
    sec.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
    sec.seccomp_release.argtypes = [ctypes.c_void_p]
    context = sec.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not context:
        raise OSError('seccomp_init')
    try:
        if sec.seccomp_attr_set(context, 4, 1) != 0:  # SCMP_FLTATR_CTL_TSYNC
            raise OSError('seccomp thread synchronization')
        for name in (b'socket', b'socketpair', b'connect', b'sendto', b'sendmsg', b'sendmmsg'):
            number = sec.seccomp_syscall_resolve_name(name)
            if number >= 0 and sec.seccomp_rule_add(context, 0x00050001, number, 0) != 0:
                raise OSError('seccomp_rule_add')
        if sec.seccomp_load(context) != 0:
            raise OSError('seccomp_load')
    finally:
        sec.seccomp_release(context)


class PromptGuard:
    def __init__(self, directory):
        verify_files(directory)
        os.environ.update(HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', TOKENIZERS_PARALLELISM='false')
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        torch.set_num_threads(1)
        torch.set_num_interop_threads(1)
        self.torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(directory, local_files_only=True, trust_remote_code=False)
        self.model = AutoModelForSequenceClassification.from_pretrained(directory, local_files_only=True, trust_remote_code=False).to('cpu').eval()
        deny_network()

    def classify(self, text):
        policy = REGISTRY['baseline-pg2']
        batches = self.tokenizer(text, max_length=policy['window_tokens'], truncation=True,
                                 stride=policy['stride_tokens'], return_overflowing_tokens=True,
                                 padding=True, return_tensors='pt')
        batches.pop('overflow_to_sample_mapping')
        # Sequential windows keep peak memory bounded on the 4 GiB guest.
        with self.torch.inference_mode():
            for index in range(batches['input_ids'].shape[0]):
                logits = self.model(**{key: value[index:index+1] for key, value in batches.items()}).logits
                if logits.softmax(dim=-1)[0, 1].item() >= policy['threshold']:
                    return 'PG2_PROMPT_ATTACK'
        return ''


def main():
    model = PromptGuard(Path(sys.argv[1]))
    print('ready', flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        code = model.classify(request['text'])
        print(json.dumps({'code': code}, separators=(',', ':')).ljust(127), flush=True)


if __name__ == '__main__':
    main()
