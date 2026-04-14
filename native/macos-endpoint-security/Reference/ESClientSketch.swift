// ESClientSketch.swift
//
// REFERENCE ONLY — not built by this repository.
//
// Requirements (all must be satisfied outside this repo):
// - macOS System Extension target (or other Apple-supported ES host).
// - com.apple.developer.endpoint-security.client entitlement from Apple.
// - Code signing + notarization; user must approve the extension.
//
// This sketch shows the *shape* of an AUTH_OPEN decision. A real product must
// handle errors, caching, mute rules, performance, and Apple’s auth deadlines.
// ClamAV integration usually belongs in a separate XPC helper, not inline here.

import EndpointSecurity
import Foundation

final class ESClientSketch {
    private var client: OpaquePointer?

    // Teardown: call es_delete_client(client) on the *same thread* that called es_new_client (Apple requirement).

    /// Returns `ES_NEW_CLIENT_RESULT_SUCCESS` only when the client was created; check subscribe result in logs.
    func start() -> es_new_client_result_t {
        let code = es_new_client(&client) { [weak self] client, message in
            guard let self, let client, let message else { return }
            self.handle(client: client, message: message)
        }
        guard code == ES_NEW_CLIENT_RESULT_SUCCESS, let c = client else {
            return code
        }

        var types: [es_event_type_t] = [ES_EVENT_TYPE_AUTH_OPEN]
        let sub = types.withUnsafeBufferPointer { buf in
            es_subscribe(c, buf.baseAddress!, UInt32(buf.count))
        }
        if sub != ES_RETURN_SUCCESS {
            // In real code: log, tear down client, or retry per policy.
            assertionFailure("es_subscribe failed: \(sub.rawValue)")
        }
        return code
    }

    private func handle(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        switch msg.event_type {
        case ES_EVENT_TYPE_AUTH_OPEN:
            // event.auth.open — inspect process + vnode before deciding.
            // TODO: policy, cache, ClamAV via XPC with strict timeouts.
            let allow = true
            _ = es_respond_auth_result(
                client,
                message,
                allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY,
                false
            )
        default:
            break
        }
    }
}
