package mensagod.handlers

import mensagod.ClientSession

// GETUPDATES (time)
fun commandGetUpdates(state: ClientSession) {
    if (!state.requireLogin()) return

    // TODO: Implement commandGetUpdates. Depends on new Schema code.
}