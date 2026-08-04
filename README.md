# ponpilot-api

Self-hosted backend for [openpilot](https://github.com/commaai/openpilot) and
[comma connect](https://github.com/commaai/connect).

Serves both the connect web frontend and the device itself.

## Status

Early development. GitHub login works; nothing else does yet.

## Running

Copy `.env.example` to `.env` and fill it in, then:

```sh
set -a && . ./.env && set +a && cargo run
```

## License

MIT
