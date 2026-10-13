"""Per-target takeover policy; no Chrome, profile or secret access.

Run on the broker's single asyncio event loop. The broker remains responsible
for authentication, target provenance and mapping nested sessions/OOPIFs to
page targets. Register only a resource already proven agent-owned.

Pause/release revoke admission before waiting for an in-flight send to drain.
Their return acknowledges quiescence, not cancellation/undo of a command
already sent. Callbacks must perform exactly one bounded upstream operation;
never nest dispatch, pause or release for the same target inside a callback.

Released IDs are tombstones for this browser generation: reconnect, repeated
registration and resume cannot reclaim them. Create a new registry only after
proving a fresh browser generation, never to bypass a takeover. State is not
persisted; restart integration must preserve ambiguous old resources.
"""
import asyncio


class TakeoverRegistry:
    def __init__(self):
        self._states = {}
        self._locks = {}
        self._revisions = {}

    def register(self, target_id, *, parent_id=None):
        if parent_id is not None:
            self._require_known(parent_id)
        if target_id not in self._states:
            self._states[target_id] = self._states[parent_id] if parent_id is not None else 'active'
            self._locks[target_id] = asyncio.Lock()
            self._revisions[target_id] = 0

    def is_active(self, target_id):
        return self._states.get(target_id) == 'active'

    def snapshot(self):
        return dict(self._states)

    def _require_known(self, target_id):
        if target_id not in self._states:
            raise PermissionError('target is not registered as owned')

    async def release(self, target_id):
        self._require_known(target_id)
        self._states[target_id] = 'released'
        self._revisions[target_id] += 1
        async with self._locks[target_id]:
            return 'released'

    async def pause(self, target_id):
        self._require_known(target_id)
        if self._states[target_id] != 'released':
            self._states[target_id] = 'paused'
        self._revisions[target_id] += 1
        async with self._locks[target_id]:
            return self._states[target_id]

    async def resume(self, target_id):
        self._require_known(target_id)
        revision = self._revisions[target_id]
        async with self._locks[target_id]:
            if revision != self._revisions[target_id]:
                raise PermissionError('resume superseded by takeover')
            if self._states[target_id] == 'released':
                raise PermissionError('released target cannot be reclaimed')
            self._states[target_id] = 'active'
            return 'active'

    async def close_if_active(self, target_id, operation):
        if not self.is_active(target_id):
            return False
        revision = self._revisions[target_id]
        async with self._locks[target_id]:
            if not self.is_active(target_id) or revision != self._revisions[target_id]:
                return False
            try:
                await operation()
            except BaseException:
                if self._states[target_id] == 'active':
                    self._states[target_id] = 'paused'
                self._revisions[target_id] += 1
                raise
            self._states[target_id] = 'released'
            return True

    async def dispatch(self, target_id, operation):
        self._require_known(target_id)
        if self._states[target_id] != 'active':
            raise PermissionError('target is not agent-active')
        async with self._locks[target_id]:
            if self._states.get(target_id) != 'active':
                raise PermissionError('target is not agent-active')
            return await operation()
