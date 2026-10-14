import Foundation
import XKit
import NIOCore
import NIOPosix
import NIOHTTP1

/// Password login through a one-time page served on 127.0.0.1, for terminals where
/// typing or pasting into the hidden password prompt doesn't work. The browser also
/// lets password managers fill the Apple ID, password and verification code.
///
/// The page lives at a random, unguessable path and only answers requests whose Host
/// is the loopback address it is bound to. Credentials stay in this process and are
/// only ever sent to Apple, exactly as with the terminal prompt.
actor WebLoginSession {
    enum Step: String, Encodable {
        case credentials
        case working
        case code
        case team
        case done
        case failed
    }

    private struct State: Encodable {
        var step: Step
        var message: String?
        var teams: [String]?
    }

    private var state = State(step: .working)
    private var credentialsWaiter: CheckedContinuation<(username: String, password: String), Never>?
    private var codeWaiter: CheckedContinuation<String?, Never>?
    private var teamWaiter: CheckedContinuation<Int, Never>?
    private var allowedHosts: Set<String> = []

    let path: String

    init() {
        var generator = SystemRandomNumberGenerator()
        let token = (0..<32).map { _ in String(format: "%02x", UInt8.random(in: .min ... .max, using: &generator)) }
        path = "/login/\(token.joined())"
    }

    func setPort(_ port: Int) {
        allowedHosts = ["127.0.0.1:\(port)", "localhost:\(port)"]
    }

    // MARK: - Login flow

    func credentials(error: String?) async -> (username: String, password: String) {
        await withCheckedContinuation { continuation in
            credentialsWaiter = continuation
            state = State(step: .credentials, message: error)
        }
    }

    func code() async -> String? {
        await withCheckedContinuation { continuation in
            codeWaiter = continuation
            state = State(step: .code)
        }
    }

    func team(from names: [String]) async -> Int {
        await withCheckedContinuation { continuation in
            teamWaiter = continuation
            state = State(step: .team, teams: names)
        }
    }

    func working(_ message: String) {
        state = State(step: .working, message: message)
    }

    func finish(_ message: String) {
        state = State(step: .done, message: message)
    }

    func fail(_ message: String) {
        state = State(step: .failed, message: message)
    }

    // MARK: - HTTP

    struct Response: Sendable {
        var status: HTTPResponseStatus
        var contentType = "text/plain; charset=utf-8"
        var body = Data()

        static func text(_ status: HTTPResponseStatus, _ text: String) -> Response {
            Response(status: status, body: Data(text.utf8))
        }
    }

    private struct CredentialsBody: Decodable {
        var appleID: String
        var password: String
    }

    private struct CodeBody: Decodable {
        var code: String
    }

    private struct TeamBody: Decodable {
        var index: Int
    }

    func respond(to head: HTTPRequestHead, body: ByteBuffer) -> Response {
        // Rejecting other Host values stops DNS-rebinding pages from reaching the server.
        guard let host = head.headers.first(name: "host"), allowedHosts.contains(host.lowercased()) else {
            return .text(.forbidden, "Forbidden")
        }

        let path = head.uri.split(separator: "?", maxSplits: 1).first.map(String.init) ?? head.uri
        switch (head.method, path) {
        case (.GET, self.path), (.GET, self.path + "/"):
            return Response(status: .ok, contentType: "text/html; charset=utf-8", body: Data(WebLoginPage.html.utf8))
        case (.GET, self.path + "/state"):
            let data = (try? JSONEncoder().encode(state)) ?? Data("{}".utf8)
            return Response(status: .ok, contentType: "application/json", body: data)
        case (.POST, self.path + "/credentials"):
            guard let waiter = credentialsWaiter else { return .text(.conflict, "Not waiting for credentials") }
            guard let input = decode(CredentialsBody.self, head: head, body: body) else {
                return .text(.badRequest, "Invalid request")
            }
            let username = input.appleID.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !username.isEmpty, !input.password.isEmpty else {
                return .text(.badRequest, "Apple ID and password are required")
            }
            credentialsWaiter = nil
            state = State(step: .working, message: "Signing in…")
            waiter.resume(returning: (username, input.password))
            return .text(.ok, "OK")
        case (.POST, self.path + "/code"):
            guard let waiter = codeWaiter else { return .text(.conflict, "Not waiting for a code") }
            guard let input = decode(CodeBody.self, head: head, body: body) else {
                return .text(.badRequest, "Invalid request")
            }
            let code = input.code.filter { !$0.isWhitespace }
            guard !code.isEmpty else { return .text(.badRequest, "Code is required") }
            codeWaiter = nil
            state = State(step: .working, message: "Verifying code…")
            waiter.resume(returning: code)
            return .text(.ok, "OK")
        case (.POST, self.path + "/team"):
            guard let waiter = teamWaiter, let teams = state.teams else {
                return .text(.conflict, "Not waiting for a team")
            }
            guard let input = decode(TeamBody.self, head: head, body: body), teams.indices.contains(input.index) else {
                return .text(.badRequest, "Invalid team")
            }
            teamWaiter = nil
            state = State(step: .working, message: "Saving login…")
            waiter.resume(returning: input.index)
            return .text(.ok, "OK")
        default:
            return .text(.notFound, "Not found")
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, head: HTTPRequestHead, body: ByteBuffer) -> T? {
        // Requiring JSON means a cross-site form post can't reach these endpoints without a CORS preflight.
        guard head.headers.first(name: "content-type")?.lowercased().hasPrefix("application/json") == true else {
            return nil
        }
        return try? JSONDecoder().decode(type, from: Data(body.readableBytesView))
    }
}

/// Serves a `WebLoginSession` on an ephemeral loopback port until `close()`.
struct WebLoginServer: Sendable {
    private static let maxBodySize = 16 * 1024

    private let channel: Channel
    private let task: Task<Void, Never>
    let url: String

    static func start(session: WebLoginSession) async throws -> WebLoginServer {
        let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .bind(host: "127.0.0.1", port: 0) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.configureHTTPServerPipeline()
                    return try NIOAsyncChannel<HTTPServerRequestPart, HTTPServerResponsePart>(
                        wrappingChannelSynchronously: channel
                    )
                }
            }

        guard let port = server.channel.localAddress?.port else {
            throw Console.Error("Could not start the login server")
        }
        await session.setPort(port)

        let task = Task<Void, Never> {
            // Ends with an error when close() shuts the listening socket; nothing to report.
            _ = try? await withThrowingDiscardingTaskGroup { group in
                try await server.executeThenClose { connections in
                    for try await connection in connections {
                        group.addTask { await handle(connection, session: session) }
                    }
                }
            }
        }

        return WebLoginServer(channel: server.channel, task: task, url: "http://127.0.0.1:\(port)\(session.path)")
    }

    func close() async {
        try? await channel.close()
        await task.value
    }

    private static func handle(
        _ connection: NIOAsyncChannel<HTTPServerRequestPart, HTTPServerResponsePart>,
        session: WebLoginSession
    ) async {
        try? await connection.executeThenClose { inbound, outbound in
            var head: HTTPRequestHead?
            var body = ByteBuffer()
            for try await part in inbound {
                switch part {
                case .head(let requestHead):
                    head = requestHead
                    body.clear()
                case .body(var chunk):
                    guard body.readableBytes + chunk.readableBytes <= maxBodySize else {
                        try await write(.text(.payloadTooLarge, "Too large"), to: outbound)
                        return
                    }
                    body.writeBuffer(&chunk)
                case .end:
                    guard let requestHead = head else { return }
                    let response = await session.respond(to: requestHead, body: body)
                    try await write(response, to: outbound)
                    return
                }
            }
        }
    }

    private static func write(
        _ response: WebLoginSession.Response,
        to outbound: NIOAsyncChannelOutboundWriter<HTTPServerResponsePart>
    ) async throws {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: response.contentType)
        headers.add(name: "Content-Length", value: "\(response.body.count)")
        headers.add(name: "Connection", value: "close")
        headers.add(name: "Cache-Control", value: "no-store")
        headers.add(name: "Referrer-Policy", value: "no-referrer")
        headers.add(name: "X-Content-Type-Options", value: "nosniff")
        headers.add(name: "X-Frame-Options", value: "DENY")
        headers.add(
            name: "Content-Security-Policy",
            value: "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                + "connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        try await outbound.write(.head(HTTPResponseHead(version: .http1_1, status: response.status, headers: headers)))
        try await outbound.write(.body(.byteBuffer(ByteBuffer(bytes: response.body))))
        try await outbound.write(.end(nil))
    }
}

private final class WebTwoFactorDelegate: TwoFactorAuthDelegate {
    let session: WebLoginSession

    init(session: WebLoginSession) {
        self.session = session
    }

    func fetchCode() async -> String? {
        await session.code()
    }
}

extension AuthOperation {
    func logInWithPasswordInBrowser() async throws -> AuthToken {
        let session = WebLoginSession()
        let server = try await WebLoginServer.start(session: session)

        print("""
        Open this page to log in (it only works on this computer, and only for this login):

          \(server.url)

        Waiting for the login to finish in your browser. Press Ctrl-C to cancel.
        """)
        fflush(stdoutSafe)
        openInBrowser(server.url)

        do {
            let token = try await logIn(session: session)
            await session.finish("Logged in as \(token.appleID) (team \(token.teamID)). You can close this tab.")
            // Give the page a moment to pick up the final state before the server goes away.
            try? await Task.sleep(for: .seconds(3))
            await server.close()
            return .xcode(token)
        } catch {
            await session.fail("Login failed: \(error)")
            try? await Task.sleep(for: .seconds(3))
            await server.close()
            throw error
        }
    }

    private func logIn(session: WebLoginSession) async throws -> AuthToken.Xcode {
        var lastError: String?
        while true {
            let (username, password) = await session.credentials(error: lastError)
            let delegate = WebTwoFactorDelegate(session: session)
            let loginToken: DeveloperServicesLoginToken
            do {
                loginToken = try await DeveloperServicesLoginManager().logIn(
                    withUsername: username,
                    password: password,
                    twoFactorDelegate: delegate
                )
            } catch {
                lastError = "Login failed: \(error). Check your Apple ID, password and code, then try again."
                print("Login attempt failed: \(error)")
                continue
            }
            withExtendedLifetime(delegate) {}

            await session.working("Fetching your development teams…")
            let teams = try await DeveloperServicesClient(loginToken: loginToken)
                .send(DeveloperServicesListTeamsRequest())
            guard !teams.isEmpty else { throw Console.Error("No development teams found") }
            var team = teams[0]
            if teams.count > 1 {
                team = teams[await session.team(from: teams.map { "\($0.name) (\($0.id.rawValue))" })]
            }

            return xcodeToken(username: username, loginToken: loginToken, team: team)
        }
    }

    private func openInBrowser(_ url: String) {
        #if os(macOS)
        let opener = "open"
        #elseif os(Linux)
        let opener = "xdg-open"
        #else
        return
        #endif
        #if os(macOS) || os(Linux)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [opener, url]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        #endif
    }
}

private enum WebLoginPage {
    static let html = #"""
    <!doctype html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="no-referrer">
    <title>xtool login</title>
    <style>
      :root { color-scheme: light dark; --bg: #f5f5f7; --card: #fff; --fg: #1d1d1f; --muted: #6e6e73;
        --line: #d2d2d7; --accent: #0071e3; --bad: #c9252d; }
      @media (prefers-color-scheme: dark) { :root { --bg: #000; --card: #1c1c1e; --fg: #f5f5f7;
        --muted: #a1a1a6; --line: #3a3a3c; --accent: #2997ff; --bad: #ff6961; } }
      * { box-sizing: border-box; }
      body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px;
        background: var(--bg); color: var(--fg); font: 16px/1.45 system-ui, -apple-system, sans-serif; }
      main { width: 100%; max-width: 400px; background: var(--card); border: 1px solid var(--line);
        border-radius: 14px; padding: 28px 24px; }
      h1 { font-size: 21px; margin: 0 0 4px; }
      p { margin: 0 0 16px; color: var(--muted); font-size: 14px; }
      label { display: block; font-size: 13px; font-weight: 600; margin: 14px 0 6px; }
      input, select { width: 100%; font: inherit; padding: 10px 12px; border-radius: 8px;
        border: 1px solid var(--line); background: transparent; color: inherit; }
      input:focus, select:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
      button { width: 100%; margin-top: 20px; padding: 11px; font: inherit; font-weight: 600; border: 0;
        border-radius: 8px; background: var(--accent); color: #fff; cursor: pointer; }
      button:disabled { opacity: .6; cursor: default; }
      .error { color: var(--bad); font-size: 14px; margin: 12px 0 0; min-height: 1em; }
      .step { display: none; }
      .step.active { display: block; }
      .spinner { width: 22px; height: 22px; border: 3px solid var(--line); border-top-color: var(--accent);
        border-radius: 50%; animation: spin .8s linear infinite; margin: 8px 0 12px; }
      @keyframes spin { to { transform: rotate(360deg); } }
    </style>
    </head>
    <body>
    <main>
      <h1>Log in to xtool</h1>
      <p>Your Apple ID is only sent to Apple, by the xtool process on this computer.</p>

      <form id="credentials" class="step" autocomplete="on">
        <label for="appleID">Apple ID</label>
        <input id="appleID" name="appleID" type="email" autocomplete="username" required autofocus>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <button type="submit">Continue</button>
      </form>

      <form id="code" class="step">
        <label for="codeInput">Verification code</label>
        <input id="codeInput" name="code" inputmode="numeric" autocomplete="one-time-code" required>
        <p style="margin-top:8px">Enter the code shown on your trusted device or sent by SMS.</p>
        <button type="submit">Verify</button>
      </form>

      <form id="team" class="step">
        <label for="teamSelect">Development team</label>
        <select id="teamSelect" name="team"></select>
        <button type="submit">Use this team</button>
      </form>

      <div id="working" class="step"><div class="spinner"></div></div>
      <div id="done" class="step"></div>
      <div id="failed" class="step"></div>

      <div id="message" class="error" role="status" aria-live="polite"></div>
    </main>
    <script>
      const base = location.pathname.replace(/\/$/, "");
      const message = document.getElementById("message");
      let current = null;
      let timer = null;

      function show(step, text, isError) {
        for (const el of document.querySelectorAll(".step")) el.classList.toggle("active", el.id === step);
        message.textContent = text || "";
        message.style.color = isError ? "" : "var(--muted)";
        if (step !== current) {
          current = step;
          const field = document.querySelector("#" + step + " input, #" + step + " select");
          if (field) field.focus();
        }
      }

      async function refresh() {
        try {
          const response = await fetch(base + "/state", { cache: "no-store" });
          const state = await response.json();
          if (state.step === "team" && state.teams) {
            const select = document.getElementById("teamSelect");
            if (select.options.length !== state.teams.length) {
              select.replaceChildren(...state.teams.map((name, i) => new Option(name, String(i))));
            }
          }
          const isError = state.step === "failed" || (state.step === "credentials" && !!state.message);
          show(state.step, state.message, isError);
          if (state.step === "done" || state.step === "failed") { clearInterval(timer); return; }
        } catch {
          clearInterval(timer);
          show("failed", "Lost contact with xtool. Check the terminal.", true);
        }
      }

      async function post(endpoint, body, form) {
        const button = form.querySelector("button");
        button.disabled = true;
        try {
          const response = await fetch(base + endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          });
          if (!response.ok) { message.textContent = await response.text(); message.style.color = ""; return; }
          form.reset();
          show("working", "", false);
        } finally {
          button.disabled = false;
          refresh();
        }
      }

      document.getElementById("credentials").addEventListener("submit", (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        post("/credentials", { appleID: form.appleID.value, password: form.password.value }, form);
      });
      document.getElementById("code").addEventListener("submit", (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        post("/code", { code: form.code.value }, form);
      });
      document.getElementById("team").addEventListener("submit", (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        post("/team", { index: Number(form.team.value) }, form);
      });

      refresh();
      timer = setInterval(refresh, 1000);
    </script>
    </body>
    </html>
    """#
}
