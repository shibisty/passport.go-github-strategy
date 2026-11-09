# passport-github

Login with GitHub for [`passport`](https://github.com/shibisty/passport.go), on
[`passport-oauth2`](https://github.com/shibisty/passport.go-oauth2-strategy). Go package: `github`.

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-github-strategy
```

## Usage

```go
a.Use(github.New(clientID, clientSecret, "https://app.example.com/auth/github/callback"))
```

- `ProviderUserID` is GitHub's numeric id (the login can be renamed); `Name` falls back to
  the login.
- GitHub's `/user` shows an email only when it is public and never says whether it is
  verified, so the strategy reads `/user/emails` and takes the primary verified address
  (`EmailVerified: true`), or another verified one; with none, `Email` is empty.
- Options: `WithScopes`, `WithHTTPClient`, `WithEndpoints` (GitHub Enterprise, tests),
  `WithPKCE(stateKey)`.

## License

MIT
