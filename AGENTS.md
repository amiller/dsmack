# Code contribution instructions

Read README.md and CONTRIBUTING.md. This public repository must be usable
without the maintainer's private planning workspace. Keep changes bounded on a
topic branch or isolated worktree; independent review is required before integration.

Keep maintained code, protocols, build inputs and necessary regression fixtures
here. Put planning, raw captures, operator state and generated reports in ignored
local-data/ or the private research workspace. Never commit credentials or private
user traces. Document retained recorded fixtures, their provenance and replay scope.

Runtime/protocol changes need relevant positive and negative checks. Documentation
changes need local link/fragment and whitespace checks. Do not change live services
or publish release artifacts as a side effect of editing. Build and hardware
qualification are separate from source publication.
