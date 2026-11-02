# goosecode

A small Claude Code–style terminal coding agent written in
[Goose](https://github.com/aardappel/goose), talking to
[OpenRouter](https://openrouter.ai) with OAuth (PKCE) login.

- Streaming replies, spinner, readline editing/history
- Tools: `read_file`, `list_dir`, `grep` (read-only); `write_file`, `edit_file` (colored diff preview), `bash`, `web_fetch` (ask for approval)
- Ctrl-C cancels a reply or running command
- `/model [filter]` picks from OpenRouter's live model list

## Build

Needs the `goose` compiler on PATH (or `GOOSE=/path/to/goose`), plus libcurl,
OpenSSL and readline development headers.

```sh
./build.sh
cp goosecode ~/.local/bin/
```

Goose has no networking in its stdlib, so `shim.h` is a small C shim (libcurl,
OAuth loopback listener, SHA-256, subprocesses) pulled in with `--include`.

## Use

```sh
goosecode login            # browser OAuth; key saved to ~/.config/goosecode/key
goosecode                  # interactive session
goosecode "do a thing"     # one-shot
goosecode -m <model> -y    # choose model; auto-approve tools
```

`OPENROUTER_API_KEY` overrides the stored key; `GOOSECODE_API` overrides the API base URL.
Interactive commands: `/model [filter]`, `/clear`, `/undo`, `/save [name]`, `/load [name]`,
`/sessions`, `/usage`, `/login`, `/help`, `/exit`, and `!<command>` to run a shell command yourself.

Put project instructions in `GOOSECODE.md` (or `AGENTS.md`) in the working directory and they are added
to the system prompt. Prompt history persists in `~/.config/goosecode/history`; saved conversations live in
`~/.config/goosecode/sessions/`. Each reply shows its token count and cost.

## License

MIT, see [LICENSE](LICENSE).
