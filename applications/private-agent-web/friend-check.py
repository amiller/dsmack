#!/usr/bin/env python3
"""Exercise the deployed first visit through visible controls, without setup files."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url', default='https://pod.dstack.soc1024.com/private-agent/')
parser.add_argument('--out', required=True, type=Path)
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=False)
marker = 'FRIEND_CHAT_PRIVATE_' + secrets.token_hex(16)
reply = 'FRIEND_CHAT_OK'
report = {'url': args.url, 'status': 'failed', 'requests': [], 'chain_transactions': 0,
          'manual_policy_upload': False, 'manual_repo_upload': False,
          'manual_key_or_url_entry': False, 'manual_node_verification': False}
responses = []
with sync_playwright() as runtime:
    browser = runtime.chromium.launch(headless=True, args=['--no-sandbox'])
    context = browser.new_context(viewport={'width': 1440, 'height': 1100}, accept_downloads=True)
    origin = urlsplit(args.url)
    context.grant_permissions(['clipboard-read','clipboard-write'], origin=origin.scheme+'://'+origin.netloc)
    page = context.new_page()
    page.on('pageerror', lambda e: report.setdefault('page_errors', []).append(str(e)))

    def guard(route):
        request = route.request
        if request.method == 'POST':
            try:
                value = request.post_data_json
            except Exception:
                value = None
            items = value if isinstance(value, list) else [value]
            if any(isinstance(item, dict) and item.get('method', '').startswith('eth_send') for item in items):
                report['chain_transactions'] += 1
                route.abort()
                return
        route.continue_()
    context.route('**/*', guard)

    def record(request):
        path = urlsplit(request.url).path
        if '/relay-broker/' not in path:
            return
        value = {'method': request.method, 'path': path}
        if request.method == 'POST' and path.endswith(('/inference/chat', '/sandbox/jobs')):
            raw = request.post_data or ''
            value.update(bytes=len(raw.encode()), sha256=hashlib.sha256(raw.encode()).hexdigest(),
                         private_chat_marker_hits=int(marker in raw))
        report['requests'].append(value)
    page.on('request', record)
    page.on('response', lambda response: responses.append(response)
            if urlsplit(response.url).path.endswith(('/inference/chat', '/sandbox/jobs')) else None)
    try:
        page.goto(args.url, wait_until='domcontentloaded')
        page.wait_for_function('document.documentElement.dataset.ready === "true"')
        page.wait_for_function('document.querySelector("#service").textContent.startsWith("Chat ready")')
        assert 'Approved sandbox policy included' in page.locator('#node-status').inner_text()
        assert page.locator('#policy').input_value() == ''
        assert page.locator('#repo').input_value() == ''
        assert page.locator('#credential').count() == 0
        assert not page.locator('.trust').evaluate('(element) => element.open')
        assert 'greet.txt' in page.locator('#job-prompt').input_value()
        page.screenshot(path=str(args.out/'01-first-visit.png'), full_page=True)

        page.locator('#burner').click()
        page.wait_for_function('document.querySelector("#chat-credit").dataset.remainingNanoUsd === "10000000"')
        report['wallet'] = page.locator('#wallet').inner_text()
        report['chat_credit_before_nano_usd'] = page.locator('#chat-credit').get_attribute('data-remaining-nano-usd')
        assert page.locator('#copy-address').is_visible()
        page.locator('#copy-address').click()
        assert page.evaluate('navigator.clipboard.readText()') == report['wallet']
        report['address_copy_verified'] = True
        assert 'coinbase.com' in page.locator('#wallet-tools a').get_attribute('href')
        page.screenshot(path=str(args.out/'02-wallet-and-starter-credit.png'), full_page=True)

        editor = page.locator('#chat-editor')
        message = 'Reply with exactly ' + reply + '. Do not repeat this private marker: ' + marker
        editor.locator('textarea,[contenteditable="true"]').first.fill(message)
        send = editor.get_by_role('button', name='Send', exact=False)
        if send.count():
            send.first.click()
        else:
            editor.locator('textarea,[contenteditable="true"]').first.press('Enter')
        page.wait_for_function('''reply => [...document.querySelectorAll('#messages assistant-message')].some(element => element.textContent.includes(reply)) ||
          !document.querySelector('#alert').hidden''', arg=reply, timeout=180000)
        if not page.locator('#alert').is_hidden():
            raise RuntimeError(page.locator('#alert').inner_text())
        page.wait_for_function('document.querySelector("#chat-credit").dataset.remainingNanoUsd !== "10000000"', timeout=60000)
        report['chat_credit_after_nano_usd'] = page.locator('#chat-credit').get_attribute('data-remaining-nano-usd')
        assert 0 < int(report['chat_credit_after_nano_usd']) < int(report['chat_credit_before_nano_usd'])
        report['chat_reply'] = page.locator('#messages assistant-message').last.inner_text()
        assert reply in report['chat_reply']
        page.wait_for_function('document.querySelector("#chat-editor textarea").value === ""')
        report['chat_composer_cleared'] = True
        report['chat_model_evidence'] = page.locator('#attestations').inner_text()
        page.screenshot(path=str(args.out/'03-verified-chat.png'), full_page=True)

        page.locator('#run').click()
        page.wait_for_function('''() => document.querySelector('#job-status').dataset.patchApplied === 'true' ||
          !document.querySelector('#alert').hidden''', timeout=360000)
        if not page.locator('#alert').is_hidden():
            raise RuntimeError(page.locator('#alert').inner_text())
        actual = page.locator('#updated-files pre[data-file="greet.txt"]').inner_text()
        assert actual == 'Hello from the private agent.\n', 'verified patch did not produce the requested file'
        assert page.locator('#sandbox-credit').get_attribute('data-status') == 'completed'
        report['starter_sandbox_status'] = 'completed'
        report['patch_applied'] = True
        report['updated_greet'] = actual
        report['job_status'] = page.locator('#job-status').inner_text()
        evidence = json.loads(page.locator('#job-evidence').text_content())
        (args.out/'job-evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
        transcript = page.locator('#transcript').text_content()
        (args.out/'transcript').write_text(transcript)
        report['provider_responses'] = sum(json.loads(line).get('type') == 'provider_attestation'
                                           for line in transcript.splitlines())
        assert report['provider_responses'] > 0
        with page.expect_download() as download:
            page.locator('#download').click()
        download.value.save_as(str(args.out/'patch'))
        assert hashlib.sha256((args.out/'patch').read_bytes()).hexdigest() == evidence['statement']['outputs']['patch']
        report['downloaded_patch_hash_verified'] = True
        report['job_id'] = evidence['statement']['job_id']
        assert page.locator('#policy').input_value() == ''
        assert page.locator('#repo').input_value() == ''
        assert not page.locator('.trust').evaluate('(element) => element.open')
        page.screenshot(path=str(args.out/'04-sandbox-patch-applied.png'), full_page=True)
        for response in responses:
            path = urlsplit(response.url).path
            raw = response.body()
            if path.endswith('/sandbox/jobs'):
                (args.out/'sealed-result.json').write_bytes(raw)
                assert response.status == 200
            else:
                report['raw_chat_reply_plaintext_hits'] = int(reply.encode() in raw)
                assert reply.encode() not in raw, 'reply appeared in plaintext at broker response boundary'
        jobs = [item for item in report['requests'] if item['method'] == 'POST' and item['path'].endswith('/sandbox/jobs')]
        assert len(jobs) == 1, 'the user flow resubmitted a job'
        assert not any(item.get('private_chat_marker_hits') for item in report['requests'])
        assert not report.get('page_errors')
        assert report['chain_transactions'] == 0
        report['status'] = 'passed'
    except Exception as error:
        report.update(error=str(error), alert=page.locator('#alert').inner_text(),
                      job_status=page.locator('#job-status').inner_text())
        page.screenshot(path=str(args.out/'failure.png'), full_page=True)
        raise
    finally:
        (args.out/'friend-browser.json').write_text(json.dumps(report, indent=2)+'\n')
        context.close()
        browser.close()
print(json.dumps({key:value for key,value in report.items() if key not in ('requests','chat_model_evidence')}))
