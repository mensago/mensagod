package mensagod.auth

/**
 * isAuthorized returns true if the actor is authorized to perform the requested action on the
 * target.
 */
fun isAuthorized(actor: AuthActor, action: AuthAction, target: AuthTarget): Boolean {
    return false
}
