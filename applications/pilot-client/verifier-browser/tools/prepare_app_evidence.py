#!/usr/bin/env python3
"""Production Swift OUT -> operator verifier -> extracted retained checker IO.

No signatures, native statements, enrollments or expected contexts are invented.
prepare emits an UNVERIFIED request package. verify invokes the production-only
operator CLI, then independently extracts and checks the exact signed result.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runresult_ref import checker, operator_cli, protocol, retained_evidence as reader, schemas, statement
from runresult_ref.errors import Refusal, need
from runresult_ref.extraction import SafeExtractor
from runresult_ref.frozen import canonical_bytes, core, load_json_bytes, validate_receipt_bytes


def _write(root, rel, data):
    # root is a newly created private tree; parent components remain descriptor confined.
    from tools.evidence_transfer import _parent_fd
    parent = _parent_fd(root, rel, create=True)
    try:
        fd = os.open(rel.split('/')[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def _sync_tree(root):
    """Durably retain every newly created directory, deepest first."""
    for name in os.listdir(root):
        info = os.stat(name, dir_fd=root, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                _sync_tree(child)
            finally:
                os.close(child)
    os.fsync(root)


def _sync_parent(path):
    parent = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _named_paths(values, code):
    from runresult_ref.extraction import validate_image_path
    result = {}
    for value in values:
        need(isinstance(value, str) and '=' in value, code)
        selector, path = value.split('=', 1)
        validate_image_path(selector)
        need('/' not in selector and selector not in result and bool(path), code)
        result[selector] = path
    return result


def _copy(root, name, dest_root, target, cap):
    """Stream one admitted regular descriptor; hash exactly the retained bytes."""
    from tools.evidence_transfer import _parent_fd
    fd = None
    parent = None
    source_parent = None
    try:
        source_parent = _parent_fd(root, name)
        fd = reader._open_leaf_nofollow(source_parent, name.split('/')[-1], name)
        os.close(source_parent)
        source_parent = None
        parent = _parent_fd(dest_root, target, create=True)
        need(stat.S_ISREG(os.fstat(fd).st_mode), 'input_not_regular_file', name)
        outfd = os.open(target.split('/')[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        digest = hashlib.sha256(); total = 0
        with os.fdopen(outfd, 'wb') as out:
            while True:
                data = os.read(fd, min(1 << 20, cap + 1 - total))
                if not data: break
                total += len(data); need(total <= cap, 'input_too_large', name)
                digest.update(data); out.write(data)
            out.flush(); os.fsync(out.fileno())
        os.fsync(parent)
        return digest.hexdigest(), total
    finally:
        if source_parent is not None: os.close(source_parent)
        if parent is not None: os.close(parent)
        if fd is not None: os.close(fd)


def _counter(assertion):
    # This only transports a claim. The pinned verifier authenticates it.
    try:
        obj = core.decode(assertion)
        auth = obj['authenticatorData']
        need(isinstance(auth, bytes) and len(auth) >= 37, 'app_assertion_shape')
        return int.from_bytes(auth[33:37], 'big')
    except (core.Reject, KeyError, TypeError, ValueError) as exc:
        raise Refusal('app_assertion_shape', str(exc)) from exc


def _production_context(path):
    context = reader.load_wire_json(path, protocol.MAX_REQUEST_BYTES, 'checker_context')
    schemas.validate_checker_context(context)
    need(context['expected']['enrollment_class'] == protocol.ENROLLMENT_CLASS_PRODUCTION,
         'app_adapter_requires_production_context')
    return context


def _assemble(app_out, enrollment_bytes, context, bundle_dir, private_bytes=None, selector_inputs=None):
    """Byte mapping only: the returned package has NOT earned trust."""
    enrollment = load_json_bytes(enrollment_bytes)
    schemas.validate_enrollment(enrollment)
    root = os.open(app_out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    dest = None
    try:
        docs = {name: reader._read_doc_at(root, name, cap, name) for name, cap in (
            ('compose-manifest.bin', schemas.ATTACHMENT_BYTE_CAPS['manifest']),
            ('statement.json', protocol.MAX_STATEMENT_B64),
            ('envelope.json', protocol.MAX_ENVELOPE_B64),
            ('launch-assertion.cbor', protocol.MAX_ASSERTION_B64),
            ('result-assertion.cbor', protocol.MAX_ASSERTION_B64),
            ('launch-client-data.bin', protocol.MAX_REQUEST_BYTES),
            ('result-client-data.bin', protocol.MAX_REQUEST_BYTES),
            ('keyId.txt', protocol.MAX_KEY_ID_B64))}
        expected = context['expected']; manifest = docs['compose-manifest.bin']
        selector_inputs = {} if selector_inputs is None else selector_inputs
        expected_selectors = expected.get('selector_manifests', {expected['receipt_selector']: {'manifest_sha256': expected['manifest_sha256']}})
        need(set(expected_selectors) == set(expected['closure_context']['selectors']), 'app_selector_context_membership')
        need(set(selector_inputs) == set(expected_selectors) - {expected['receipt_selector']}, 'app_selector_input_membership')
        selector_inputs = dict(selector_inputs)
        selector_inputs[expected['receipt_selector']] = (manifest, private_bytes)
        for selector, (selector_manifest, _) in selector_inputs.items():
            need(hashlib.sha256(selector_manifest).hexdigest() == expected_selectors[selector]['manifest_sha256'], 'app_selector_manifest_mismatch', selector)
        envelope = load_json_bytes(docs['envelope.json']); schemas.validate_envelope_body(envelope)
        need(canonical_bytes(envelope) == docs['envelope.json'], 'envelope_not_canonical')
        native, launch_digest = statement.authenticate_statement(docs['statement.json'], manifest,
                                      expected['challenge'], expected['key_id_b64'], result_envelope=envelope)
        need(docs['keyId.txt'].decode('ascii') == expected['key_id_b64'] == enrollment['key_id_b64'], 'app_key_mismatch')
        need(hashlib.sha256(manifest).hexdigest() == expected['manifest_sha256'], 'expected_manifest_mismatch')
        need(docs['launch-client-data.bin'] == statement.launch_client_data(expected['manifest_sha256'], launch_digest, expected['challenge']), 'app_launch_client_data_mismatch')
        need(docs['result-client-data.bin'] == statement.result_client_data(launch_digest, statement.envelope_digest(envelope), expected['challenge']), 'app_result_client_data_mismatch')
        launch_counter = _counter(docs['launch-assertion.cbor'])
        result_counter = _counter(docs['result-assertion.cbor'])
        need(envelope['launch'] == {'evidence_sha256': launch_digest, 'manifest_sha256': expected['manifest_sha256'],
                                   'challenge': expected['challenge'], 'key_id_b64': expected['key_id_b64'], 'counter': launch_counter}, 'app_launch_binding')
        need(result_counter > launch_counter, 'counter_order')
        console = reader._read_doc_at(root, 'console-v3.log', protocol.MAX_CONSOLE_BYTES, 'console-v3.log')
        need(len(console) == envelope['console']['bytes'] and hashlib.sha256(console).hexdigest() == envelope['console']['sha256'], 'app_console_mismatch')
        os.mkdir(bundle_dir, 0o700)
        dest = os.open(bundle_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        image_sha, image_size = _copy(root, 'result.img', dest, 'attachments/result_image', protocol.RESULT_TEMPLATE_BYTES_MAX)
        need(image_sha == envelope['result_disk']['sha256'] and image_size == envelope['result_disk']['bytes'], 'app_image_mismatch')
        request = {'runresult_request_version': protocol.REQUEST_VERSION,
                   'manifest_sha256': expected['manifest_sha256'], 'receipt_selector': expected['receipt_selector'],
                   'challenge': expected['challenge'], 'key_id_b64': expected['key_id_b64'],
                   'launch_statement_b64': base64.b64encode(docs['statement.json']).decode(),
                   'launch_assertion_b64': base64.b64encode(docs['launch-assertion.cbor']).decode(), 'launch_counter': launch_counter,
                   'envelope_b64': base64.b64encode(docs['envelope.json']).decode(),
                   'result_assertion_b64': base64.b64encode(docs['result-assertion.cbor']).decode(), 'result_counter': result_counter,
                   'result_image_sha256': image_sha, 'result_image_bytes': image_size}
        schemas.validate_request(request)
        entries = []
        for role, data in [('manifest', manifest), ('enrollment', enrollment_bytes)]:
            _write(dest, 'attachments/' + role, data)
            entries.append({'role': role, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
        entries.append({'role': 'result_image', 'sha256': image_sha, 'bytes': image_size})
        if private_bytes is not None:
            _write(dest, 'attachments/runtime_envelope_private', private_bytes)
            entries.append({'role': 'runtime_envelope_private', 'bytes': len(private_bytes)})
        for rel, data in [('request.json', canonical_bytes(request)), ('attachment-index.json', canonical_bytes({'schema': protocol.ATTACHMENT_INDEX_SCHEMA, 'entries': entries})),
                          ('enrollment.json', enrollment_bytes), ('statement.json', docs['statement.json']), ('result-envelope.json', docs['envelope.json']), ('console', console)]:
            _write(dest, rel, data)
        for selector, (selector_manifest, selector_private) in sorted(selector_inputs.items()):
            _write(dest, 'attachments/selectors/' + selector + '/manifest', selector_manifest)
            if selector_private is not None:
                _write(dest, 'attachments/selectors/' + selector + '/runtime_envelope_private', selector_private)
        _sync_tree(dest)
        _sync_parent(bundle_dir)
        return request
    finally:
        if dest is not None: os.close(dest)
        os.close(root)


def prepare(app_out, enrollment_path, context_path, bundle_dir, private_envelope=None, selector_manifests=None, selector_private_envelopes=None):
    context = _production_context(context_path)
    enrollment_bytes = reader.read_regular_file(enrollment_path, schemas.ATTACHMENT_BYTE_CAPS['enrollment'], 'enrollment')
    enrollment = load_json_bytes(enrollment_bytes); schemas.validate_enrollment(enrollment)
    need(enrollment['enrollment_class'] == protocol.ENROLLMENT_CLASS_PRODUCTION, 'app_adapter_requires_production_enrollment')
    private = None if private_envelope is None else reader.read_regular_file(private_envelope, schemas.ATTACHMENT_BYTE_CAPS['runtime_envelope_private'], 'private envelope')
    manifests = _named_paths(selector_manifests or [], 'app_selector_manifest')
    privates = _named_paths(selector_private_envelopes or [], 'app_selector_private')
    need(set(privates) <= set(manifests), 'app_selector_private_membership')
    inputs = {selector: (reader.read_regular_file(path, schemas.ATTACHMENT_BYTE_CAPS['manifest'], 'selector manifest'),
                        reader.read_regular_file(privates[selector], schemas.ATTACHMENT_BYTE_CAPS['runtime_envelope_private'], 'selector private') if selector in privates else None)
              for selector, path in manifests.items()}
    _assemble(app_out, enrollment_bytes, context, bundle_dir, private, inputs)
    return {'prepared': True, 'authenticated': False, 'bundle': bundle_dir}


def _extract_retained(bundle_dir, report_path, context, retained_dir, extract_dir, tool_sha256):
    """Extract from the request-pinned image; external checker authenticates all."""
    bundle = operator_cli._load_bundle(bundle_dir)
    request = schemas.validate_request(bundle['request']); selector = request['receipt_selector']
    extractor = SafeExtractor(extract_dir, tool_sha256=tool_sha256)
    dest = None
    try:
        extractor.snapshot(os.path.join(bundle_dir, 'attachments', 'result_image'), request['result_image_sha256'], request['result_image_bytes'])
        expected_selectors = context['expected'].get('selector_manifests', {selector: {'manifest_sha256': context['expected']['manifest_sha256']}})
        need(set(expected_selectors) == set(context['expected']['closure_context']['selectors']), 'app_selector_context_membership')
        need(selector in expected_selectors, 'app_selected_selector_missing')
        extracted = {}
        src = os.open(bundle_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            from tools.evidence_transfer import _parent_fd
            for current in sorted(expected_selectors):
                prefix = 'attachments/' if current == selector else 'attachments/selectors/' + current + '/'
                parent = _parent_fd(src, prefix + 'manifest')
                try:
                    manifest = reader._read_doc_at(parent, 'manifest', schemas.ATTACHMENT_BYTE_CAPS['manifest'], 'manifest')
                    private = (reader._read_doc_at(parent, 'runtime_envelope_private', schemas.ATTACHMENT_BYTE_CAPS['runtime_envelope_private'], 'private envelope')
                               if reader._exists_at(parent, 'runtime_envelope_private') else None)
                finally:
                    os.close(parent)
                need(hashlib.sha256(manifest).hexdigest() == expected_selectors[current]['manifest_sha256'], 'app_selector_manifest_mismatch', current)
                _, receipt_bytes = extractor.extract_bootstrap(current)
                validate_receipt_bytes(manifest, receipt_bytes, private)
                receipt = load_json_bytes(receipt_bytes)
                collected = extractor.extract_outputs(current, receipt)
                extractor.extract_index(current)
                extracted[current] = (manifest, private, receipt_bytes, extractor.last_index_bytes, collected)
        finally:
            os.close(src)
        manifest, private, receipt_bytes, index_bytes, collected = extracted[selector]
        os.mkdir(retained_dir, 0o700); dest = os.open(retained_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        src = os.open(bundle_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in ('statement.json', 'result-envelope.json', 'console'):
                _write(dest, name, reader._read_doc_at(src, name, protocol.MAX_REQUEST_BYTES if name != 'console' else protocol.MAX_CONSOLE_BYTES, name))
            _copy(src, 'attachments/result_image', dest, 'result_image', protocol.RESULT_TEMPLATE_BYTES_MAX)
        finally: os.close(src)
        for rel, data in [('manifest', manifest), ('enrollment.json', canonical_bytes(bundle['enrollment'])), ('request.json', canonical_bytes(request)),
                          ('receipt.json', receipt_bytes), ('export-index.json', index_bytes),
                          ('report.json', reader.read_regular_file(report_path, protocol.MAX_REQUEST_BYTES, 'report'))]:
            _write(dest, rel, data)
        if private is not None: _write(dest, 'runtime_envelope_private', private)
        from tools.evidence_transfer import _parent_fd
        outputs_parent = _parent_fd(dest, 'outputs/.sentinel', create=True)
        os.close(outputs_parent)
        for label, (path, declared) in collected.items():
            kind, name = label.split(':', 1)
            _write(dest, 'outputs/' + ('streams' if kind == 'stream' else 'artifacts') + '/' + name,
                   reader.read_regular_file(path, declared['bytes'], label))
        _write(dest, 'retained-selectors.json', canonical_bytes({'schema': 'dsmack-retained-selectors/1', 'selectors': sorted(extracted)}))
        for current, (current_manifest, current_private, current_receipt, current_index, current_outputs) in sorted(extracted.items()):
            prefix = 'selectors/' + current + '/'
            from tools.evidence_transfer import _parent_fd
            outputs_parent = _parent_fd(dest, prefix + 'outputs/.sentinel', create=True)
            os.close(outputs_parent)
            for name, data in [('manifest', current_manifest), ('receipt.json', current_receipt), ('export-index.json', current_index)]:
                _write(dest, prefix + name, data)
            if current_private is not None:
                _write(dest, prefix + 'runtime_envelope_private', current_private)
            for label, (path, declared) in current_outputs.items():
                kind, name = label.split(':', 1)
                _write(dest, prefix + 'outputs/' + ('streams' if kind == 'stream' else 'artifacts') + '/' + name,
                       reader.read_regular_file(path, declared['bytes'], label))
        _sync_tree(dest)
        _sync_parent(retained_dir)
        evidence = reader.load_retained_check_evidence(retained_dir)
        evidence['launch_assertion_b64'] = request['launch_assertion_b64']; evidence['result_assertion_b64'] = request['result_assertion_b64']
        return checker.check(reader.read_regular_file(report_path, protocol.MAX_REQUEST_BYTES, 'report'), context, evidence)
    finally:
        if dest is not None: os.close(dest)
        extractor.cleanup()


def verify(args):
    context = _production_context(args.context)
    # The exact accepted production CLI enforces authenticated store, current
    # policy/root, secret permissions, pinned signing key and replay floor.
    need(os.path.isdir(args.work_root) and not os.path.islink(args.work_root), 'app_work_root_required')
    # A fresh private output directory prevents a pre-existing report symlink
    # from becoming the operator CLI's write target. Preserve it on failure.
    operation_root = tempfile.mkdtemp(prefix='app-evidence-', dir=args.work_root)
    report_path = os.path.join(operation_root, 'report.json')
    op = types.SimpleNamespace(policy=args.policy, allow_development=False, secret_file=args.secret_file,
        signing_key_file=args.signing_key_file, store=args.store, replay=args.replay,
        bundle=args.bundle, extract_dir=os.path.join(operation_root, 'verify-extraction'),
        extractor_sha256=args.extractor_sha256, report_key_id=args.report_key_id, now=None, out=report_path)
    operator_cli.cmd_verify(op)
    return _extract_retained(args.bundle, report_path, context, args.retained,
                             os.path.join(operation_root, 'retain-extraction'), args.extractor_sha256)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__); sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('prepare')
    for name in ('app-out', 'enrollment', 'context', 'bundle'): a.add_argument('--' + name, required=True)
    a.add_argument('--private-envelope')
    a.add_argument('--selector-manifest', action='append', default=[], metavar='SELECTOR=PATH')
    a.add_argument('--selector-private-envelope', action='append', default=[], metavar='SELECTOR=PATH')
    a = sub.add_parser('verify')
    for name in ('bundle','context','retained','policy','secret-file','signing-key-file','report-key-id','store','replay','work-root','extractor-sha256'):
        a.add_argument('--' + name, required=True)
    args = p.parse_args(argv)
    try:
        result = prepare(args.app_out,args.enrollment,args.context,args.bundle,args.private_envelope,args.selector_manifest,args.selector_private_envelope) if args.command == 'prepare' else verify(args)
        print(json.dumps(result, sort_keys=True))
        return 0 if args.command == 'prepare' or result['task_success'] else 3
    except (Refusal, OSError, ValueError, UnicodeError) as exc:
        print('REFUSED %s: %s' % (getattr(exc, 'code', 'app_io_invalid'), exc), file=sys.stderr)
        return 2

if __name__ == '__main__': sys.exit(main())
