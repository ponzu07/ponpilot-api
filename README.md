# ponpilot-api

Self-hosted backend for [openpilot](https://github.com/commaai/openpilot) and
[comma connect](https://github.com/commaai/connect).

## Status

Early development. Nothing works yet.

## Running

```sh
PUBLIC_URL=https://api.example.com \
FRONTEND_URL=https://connect.example.com \
cargo run
```

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `PUBLIC_URL` | yes | — | This server's public URL. Used to build the OAuth `redirect_uri`, which must match the value registered with the provider |
| `FRONTEND_URL` | yes | — | Where to send the browser after login |
| `BIND` | no | `0.0.0.0:8080` | Listen address |
| `GITHUB_CLIENT_ID` | no | — | GitHub OAuth App |
| `GITHUB_CLIENT_SECRET` | no | — | GitHub OAuth App |

## License

MIT
