import Foundation
import XKit
import ArgumentParser
import Crypto
import Dependencies

enum AuthMode: String, CaseIterable, CustomStringConvertible, ExpressibleByArgument {
    case key
    case password

    var description: String {
        switch self {
        case .key: "API Key (requires paid Apple Developer Program membership)"
        case .password: "Password (works with any Apple ID but uses private APIs)"
        }
    }
}

struct AuthOperation {
    var username: String?
    var password: String?
    var logoutFromExisting: Bool

    var mode: AuthMode?
    var quiet = false
    var web = false

    func run() async throws {
        if let token = try? AuthToken.saved(), !logoutFromExisting {
            if !quiet {
                print("Logged in.\n\(token)")
            }
            return
        }

        let mode: AuthMode
        if web {
            guard self.mode != .key else {
                throw Console.Error("--web only supports the password login mode.")
            }
            mode = .password
        } else if let existing = self.mode {
            mode = existing
        } else {
            mode = try await Console.choose(
                from: AuthMode.allCases,
                onNoElement: { throw Console.Error("Mode selection is required") },
                multiPrompt: "Select login mode",
                formatter: \.description
            )
        }

        let token = switch mode {
        case .password where web:
            try await logInWithPasswordInBrowser()
        case .password:
            try await logInWithPassword()
        case .key:
            try await logInWithKey()
        }
        try token.save()

        print("Logged in.\n\(token)")
    }

    private func logInWithKey() async throws -> AuthToken {
        let id = try await Console.promptRequired("Key ID: ", existing: nil)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let issuerID = try await Console.promptRequired("Issuer ID: ", existing: nil)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let path = try await Console.promptRequired("Key path: ", existing: nil)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let pem = try String(decoding: Data(contentsOf: URL(fileURLWithPath: path)), as: UTF8.self)
        do {
            _ = try P256.Signing.PrivateKey(pemRepresentation: pem)
        } catch {
            throw Console.Error("Key is invalid: \(error)")
        }

        return AuthToken.appStoreConnect(.init(id: id, issuerID: issuerID, pem: pem))
    }

    private func logInWithPassword() async throws -> AuthToken {
        print("""
        Heads up:
          This works by emulating a Pixel phone/Windows PC to interact with Apple services;
          consider using a secondary Apple ID. Credentials are only ever sent to Apple.
        """)

        let username = try await Console.promptRequired("Apple ID: ", existing: username)

        let password: String
        if let existing = self.password {
            password = existing
        } else {
            password = try await Console.getPassword("Password: ")
        }
        guard !password.isEmpty else {
            throw Console.Error("Password cannot be empty.")
        }

        print("Logging in...")

        let authDelegate = XToolAuthDelegate()
        let manager = DeveloperServicesLoginManager()
        let token = try await manager.logIn(
            withUsername: username,
            password: password,
            twoFactorDelegate: authDelegate
        )

        let client = DeveloperServicesClient(loginToken: token)
        let teams = try await client.send(DeveloperServicesListTeamsRequest())
        let team = try await Console.choose(
            from: teams,
            onNoElement: {
                throw Console.Error("No development teams found")
            },
            multiPrompt: "\nSelect a team",
            formatter: {
                "\($0.name) (\($0.id.rawValue))"
            }
        )

        return .xcode(xcodeToken(username: username, loginToken: token, team: team))
    }

    func xcodeToken(
        username: String,
        loginToken: DeveloperServicesLoginToken,
        team: DeveloperServicesTeam
    ) -> AuthToken.Xcode {
        @Dependency(\.anisetteDataProvider) var anisetteProvider

        return AuthToken.Xcode(
            appleID: username,
            adsid: loginToken.adsid,
            token: loginToken.token,
            expiry: loginToken.expiry,
            teamID: team.id.rawValue,
            anisetteProviderID: anisetteProvider.providerID
        )
    }
}

struct AuthLoginCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "login",
        abstract: "Log in to Apple Developer Services"
    )

    @Option(name: [.short, .long], help: "Apple ID") var username: String?
    @Option(name: [.short, .long]) var password: String?
    @Option(name: [.short, .long]) var mode: AuthMode?
    @Flag(
        help: ArgumentHelp(
            "Enter your Apple ID, password and verification code in a browser page served on 127.0.0.1",
            discussion: """
            Use this when the terminal prompts don't accept typed or pasted input. \
            Implies the password login mode.
            """
        )
    ) var web = false

    func run() async throws {
        try await AuthOperation(
            username: username,
            password: password,
            logoutFromExisting: true,
            mode: mode,
            web: web
        ).run()
    }
}

struct AuthLogoutCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "logout",
        abstract: "Log out of Apple Developer Services"
    )

    @Flag(
        name: [.short, .customLong("reset-2fa")],
        help: ArgumentHelp(
            "Reset 2-factor authentication data",
            discussion: """
            This resets the "pseudo-device" that xtool presents itself as \
            when authenticating with Apple using the password login mode.

            Effectively, this means you will be prompted to complete 2-factor \
            authentication again the next time you log in.
            """
        )
    ) var reset2FA = false

    func run() async throws {
        if (try? AuthToken.saved()) != nil {
            try AuthToken.clear()
            print("Logged out")
        } else {
            print("Already logged out")
        }

        if reset2FA {
            @Dependency(\.anisetteDataProvider) var anisetteProvider
            await anisetteProvider.resetProvisioning()
            print("Forgot device")
        }
    }
}

struct AuthStatusCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Get Apple Developer Services auth status"
    )

    func run() async throws {
        if let token = try? AuthToken.saved() {
            print("Logged in.\n\(token)")
        } else {
            print("Logged out")
        }
    }
}

struct AuthCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "auth",
        abstract: "Manage Apple Developer Services authentication",
        subcommands: [
            AuthLoginCommand.self,
            AuthLogoutCommand.self,
            AuthStatusCommand.self,
        ],
        defaultSubcommand: AuthLoginCommand.self
    )
}
