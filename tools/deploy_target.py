"""Local source gate and project names for shared-webhost deployment."""
import subprocess

WEBHOST = 'https://pod.dstack.soc1024.com'
STAGING_HOST = 'https://private-agent-staging.dstack.soc1024.com'


def staging_page_url(origin):
    if origin not in (STAGING_HOST, WEBHOST):
        raise ValueError('staging origin must be the staging hostname or webhost')
    return origin + ('/private-agent-staging/' if origin == WEBHOST else '/')


def project_name(project, target):
    return project + ('-staging' if target == 'staging' else '')


def source_ref(repo, target):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()
    head = git('rev-parse', 'HEAD')
    if target == 'production':
        if git('status', '--porcelain', '--untracked-files=all'):
            raise ValueError('production requires a clean source tree')
        # Deploy from local main, including approved merges awaiting publication.
        for ref in ('refs/heads/main', 'refs/remotes/origin/main'):
            if subprocess.run(['git', '-C', str(repo), 'show-ref', '--verify', '--quiet', ref]).returncode == 0:
                break
        else:
            raise ValueError('production requires locally recorded origin/main or main')
        if subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', head, ref]).returncode != 0:
            raise ValueError('production HEAD must be contained in locally recorded main')
    return head
