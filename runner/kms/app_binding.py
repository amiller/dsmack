"""Explicit app-less signed Runner compatibility; never invent an attested app."""
def app_binding_allowed(client, app, cdhash, *, legacy_genesis=False):
    if legacy_genesis:
        return ('app' not in client and
                app == cdhash + '|' + client['compose_hash'])
    return client.get('app') == app


def key_parcel(api_key, app, app_key, *, legacy_genesis=False):
    result = {'api_key': api_key, 'app_key': app_key}
    if not legacy_genesis:
        result['app'] = app
    return result
