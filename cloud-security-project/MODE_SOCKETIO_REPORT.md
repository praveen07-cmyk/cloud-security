# MODE_SOCKETIO_REPORT
## Goal
Verify one global Socket.IO connection notifying state changes.

## Findings
- Server emits `mode_changed` on transition.
- Listeners asynchronously synchronize.

**Status**: PASS
