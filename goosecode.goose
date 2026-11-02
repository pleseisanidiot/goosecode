// goosecode: a small Claude Code-style coding agent in Goose, talking to
// OpenRouter. Logs in with OpenRouter's OAuth PKCE flow, then runs a tool-
// calling loop (read/write/edit files, list dirs, shell) against any model.
//
//   goosecode login            browser OAuth, stores the key
//   goosecode                  interactive session
//   goosecode "do a thing"     one-shot prompt
//   goosecode -m <model> ...   pick a model (default anthropic/claude-sonnet-4.5)

import std;
import os;
import json;

extern fn gc_http_post(url: const u8[:], bearer: const u8[:], ctype: const u8[:], body: const u8[:], out: u8[>..]&) -> i32;
extern fn gc_sha256_b64url(s: const u8[:], out: u8[>..]&);
extern fn gc_random_b64url(n: i64, out: u8[>..]&);
extern fn gc_oauth_wait(port: i32, out: u8[>..]&) -> bool;
extern fn gc_open_url(url: const u8[:]);
extern fn gc_http_stream(url: const u8[:], bearer: const u8[:], body: const u8[:], out: u8[>..]&) -> i32;
extern fn gc_readline(prompt: const u8[:], out: u8[>..]&) -> bool;
extern fn gc_ask(prompt: const u8[:], out: u8[>..]&) -> bool;
extern fn gc_history_init(path: const u8[:]);
extern fn gc_http_get(url: const u8[:], out: u8[>..]&) -> i32;
extern fn gc_init_signals();
extern fn gc_cancelled() -> bool;
extern fn gc_clear_cancel();
extern fn gc_spinner_start(label: const u8[:]);
extern fn gc_spinner_stop();
extern fn gc_run(cmd: const u8[:], out: u8[>..]&) -> i32;

let VERSION = "0.2.0";
var API: u8[>..] = [];   // GOOSECODE_API overrides, for testing
let CALLBACK_PORT: i32 = 3000;
let SYSTEM_PROMPT = "You are goosecode, a concise coding agent running in the user's terminal. Use the tools to inspect and change files and run commands in the current working directory. Prefer small, verified steps. When done, summarize briefly.";

// name, description, parameter schema -- OpenAI tool format.
let TOOLS = "[{\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"description\":\"Read a text file.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}}},{\"type\":\"function\",\"function\":{\"name\":\"write_file\",\"description\":\"Create or overwrite a file.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"},\"content\":{\"type\":\"string\"}},\"required\":[\"path\",\"content\"]}}},{\"type\":\"function\",\"function\":{\"name\":\"edit_file\",\"description\":\"Replace one exact, unique occurrence of old_text with new_text in a file.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"},\"old_text\":{\"type\":\"string\"},\"new_text\":{\"type\":\"string\"}},\"required\":[\"path\",\"old_text\",\"new_text\"]}}},{\"type\":\"function\",\"function\":{\"name\":\"list_dir\",\"description\":\"List a directory.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}}},{\"type\":\"function\",\"function\":{\"name\":\"bash\",\"description\":\"Run a shell command; returns combined output and exit status.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}},\"required\":[\"command\"]}}},{\"type\":\"function\",\"function\":{\"name\":\"grep\",\"description\":\"Search file contents recursively for a regex; returns file:line:text matches (max 200).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"pattern\":{\"type\":\"string\"},\"path\":{\"type\":\"string\",\"description\":\"directory or file, default .\"}},\"required\":[\"pattern\"]}}}]";

// --- key storage ------------------------------------------------------------

fn key_path() -> u8[>..] {
    var home: u8[>..] = [];
    if !env("HOME", home) { home.append("."); }
    return str(home, "/.config/goosecode/key");
}

fn load_key() -> u8[>..] {
    var key: u8[>..] = [];
    if env("OPENROUTER_API_KEY", key) && key.len > 0 { return key; }
    var raw: u8[>..] = [];
    if read_file(key_path(), raw) { key.append(trim(raw)); }
    return key;
}

fn save_key(key: u8[:]) -> bool {
    var home: u8[>..] = [];
    if !env("HOME", home) { home.append("."); }
    make_dir(str(home, "/.config"));
    make_dir(str(home, "/.config/goosecode"));
    return write_file_atomic(key_path(), key);
}

// --- saved sessions -----------------------------------------------------------

fn sessions_dir() -> u8[>..] {
    var home: u8[>..] = [];
    if !env("HOME", home) { home.append("."); }
    return str(home, "/.config/goosecode/sessions");
}

// Session names are plain words: no path tricks.
fn session_path(name: u8[:], out: u8[>..]&) -> bool {
    if name.len == 0 { return false; }
    for c in name {
        let ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if !ok { return false; }
    }
    out.append(sessions_dir());
    out.append("/");
    out.append(name);
    out.append(".json");
    return true;
}

// --- OAuth PKCE against OpenRouter -----------------------------------------

fn login() -> bool {
    var verifier: u8[>..] = [];
    gc_random_b64url(48, verifier);
    var challenge: u8[>..] = [];
    gc_sha256_b64url(verifier, challenge);
    let url = str("https://openrouter.ai/auth?callback_url=http%3A%2F%2Flocalhost%3A", CALLBACK_PORT,
                  "&code_challenge=", challenge, "&code_challenge_method=S256");
    print("Opening browser to log in with OpenRouter. If it doesn't open, visit:\n", url);
    gc_open_url(url);
    var code: u8[>..] = [];
    if !gc_oauth_wait(CALLBACK_PORT, code) {
        print("login failed: no OAuth callback received (is port ", CALLBACK_PORT, " free?)");
        return false;
    }
    var body: u8[>..] = [];
    body.append("{");
    json::format_key(body, "code"); json::format_string(body, code); body.push(',');
    json::format_key(body, "code_verifier"); json::format_string(body, verifier); body.push(',');
    json::format_key(body, "code_challenge_method"); json::format_string(body, "S256");
    body.append("}");
    var resp: u8[>..] = [];
    let status = gc_http_post(str(API, "/auth/keys"), "", "application/json", body, resp);
    var doc: json::Node[>..] = [];
    var dec: u8[>..] = [];
    let root, err = json::parse(resp, doc, dec);
    guard root else { print("login failed (", status, "): ", resp); return false; }
    let key, ok = json::as_string(json::member(root, "key"));
    guard ok else { print("login failed (", status, "): ", resp); return false; }
    if !save_key(key) { print("could not save key to ", key_path()); return false; }
    print("Logged in. Key saved to ", key_path());
    return true;
}

// --- tools -------------------------------------------------------------------

var auto_approve = false;

fn approve(what: u8[:]) -> bool {
    if auto_approve { return true; }
    var line: u8[>..] = [];
    if !gc_ask(str("  allow ", what, "? [y/N/a(lways)] "), line) { return false; }
    if line == "a" { auto_approve = true; return true; }
    return line == "y";
}

fn arg_str(args: json::Node?, name: u8[:], out: u8[>..]&) -> bool {
    let s, ok = json::as_string(json::member(args, name));
    if ok { out.append(s); }
    return ok;
}

// 'x' -> 'x' with embedded quotes escaped, safe as one shell word.
fn shell_quote(s: u8[:], out: u8[>..]&) {
    out.push('\'');
    for c in s {
        if c == '\'' { out.append("'\\''"); } else { out.push(c); }
    }
    out.push('\'');
}

fn run_tool(name: u8[:], arguments: u8[:], out: u8[>..]&) {
    var doc: json::Node[>..] = [];
    var dec: u8[>..] = [];
    let root, err = json::parse(arguments, doc, dec);
    guard root else { out.append("error: bad tool arguments"); return; }
    var path: u8[>..] = [];
    arg_str(root, "path", path);
    if name == "read_file" {
        if !read_file(path, out) { out.append("error: cannot read file"); }
    } else if name == "list_dir" {
        if !list_dir(path, out) { out.append("error: cannot list directory"); }
    } else if name == "write_file" {
        var content: u8[>..] = [];
        arg_str(root, "content", content);
        if !approve(str("write ", path, " (", content.len, " bytes)")) { out.append("error: user denied"); return; }
        if write_file(path, content) { out.append("ok"); } else { out.append("error: cannot write file"); }
    } else if name == "edit_file" {
        var old: u8[>..] = [];
        var new: u8[>..] = [];
        arg_str(root, "old_text", old);
        arg_str(root, "new_text", new);
        var text: u8[>..] = [];
        if !read_file(path, text) { out.append("error: cannot read file"); return; }
        let at = find(text, old);
        if old.len == 0 || at < 0 { out.append("error: old_text not found"); return; }
        if find(text[at + old.len..], old) >= 0 { out.append("error: old_text is not unique"); return; }
        if !approve(str("edit ", path)) { out.append("error: user denied"); return; }
        var result: u8[>..] = [];
        result.append(text[..at]);
        result.append(new);
        result.append(text[at + old.len..]);
        if write_file(path, result) { out.append("ok"); } else { out.append("error: cannot write file"); }
    } else if name == "grep" {
        var pattern: u8[>..] = [];
        arg_str(root, "pattern", pattern);
        if pattern.len == 0 { out.append("error: empty pattern"); return; }
        if path.len == 0 { path.append("."); }
        var qp: u8[>..] = [];
        var qd: u8[>..] = [];
        shell_quote(pattern, qp);
        shell_quote(path, qd);
        var cmd: u8[>..] = [];
        format(cmd, "(command -v rg >/dev/null && rg -n --no-heading -e ", qp, " ", qd,
               " || grep -rnI --exclude-dir=.git -e ", qp, " ", qd, ") | head -200");
        gc_run(cmd, out);
        if out.len == 0 { out.append("no matches"); }
    } else if name == "bash" {
        var cmd: u8[>..] = [];
        arg_str(root, "command", cmd);
        if !approve(str("run `", cmd, "`")) { out.append("error: user denied"); return; }
        gc_spinner_start("running");
        let status = gc_run(cmd, out);
        gc_spinner_stop();
        format(out, "\n[exit ", status, "]");
    } else {
        format(out, "error: unknown tool ", name);
    }
}

// --- the agent loop ------------------------------------------------------------

// Project instructions: GOOSECODE.md (or AGENTS.md) in the working directory.
var project_notes: u8[>..] = [];
var project_notes_file: u8[>..] = [];

fn load_project_notes() {
    var raw: u8[>..] = [];
    if read_file("GOOSECODE.md", raw) { project_notes_file.append("GOOSECODE.md"); }
    else if read_file("AGENTS.md", raw) { project_notes_file.append("AGENTS.md"); }
    project_notes.append(trim(raw));
}

// Messages are kept as comma-separated JSON objects, ready to splice in.
var history: u8[>..] = [];

fn add_message(role: u8[:], content: u8[:]) {
    if history.len > 0 { history.push(','); }
    history.append("{\"role\":");
    json::format_string(history, role);
    history.append(",\"content\":");
    json::format_string(history, content);
    history.push('}');
}

// Walks the SSE stream: calls F(delta) for each chunk's choices[0].delta.
fn each_delta<F>(resp: u8[:]) {
    each_split(resp, '\n') {
        if starts_with(it, "data: {") {
            var doc: json::Node[>..] = [];
            var dec: u8[>..] = [];
            let root, err = json::parse(it[6..], doc, dec);
            if root {
                let choices = json::member(root, "choices");
                if choices {
                    var done = false;
                    json::each(choices) { choice =>
                        let delta = json::member(choice, "delta");
                        if delta && !done { done = true; F(delta); }
                    };
                }
            }
        }
    };
}

// Tool call k's id, name and arguments, pieced together from the deltas.
fn assemble(resp: u8[:], k: i64, id: u8[>..]&, name: u8[>..]&, args: u8[>..]&) {
    each_delta(resp) { delta =>
        let calls = json::member(delta, "tool_calls");
        if calls {
            json::each(calls) { call =>
                let idx, ok = json::as_i64(json::member(call, "index"));
                if ok && idx == k {
                    let s1, h1 = json::as_string(json::member(call, "id"));
                    if h1 { id.append(s1); }
                    let f = json::member(call, "function");
                    let s2, h2 = json::as_string(json::member(f, "name"));
                    if h2 { name.append(s2); }
                    let s3, h3 = json::as_string(json::member(f, "arguments"));
                    if h3 { args.append(s3); }
                }
            };
        }
    };
}

// One user turn: call the model until it stops asking for tools.
fn turn(key: u8[:], model: u8[:]) {
    loop {
        var body: u8[>..] = [];
        body.append("{\"stream\":true,\"model\":");
        json::format_string(body, model);
        body.append(",\"messages\":[{\"role\":\"system\",\"content\":");
        var system: u8[>..] = [];
        system.append(SYSTEM_PROMPT);
        if project_notes.len > 0 {
            format(system, "\n\nProject instructions from ", project_notes_file, ":\n", project_notes);
        }
        json::format_string(body, system);
        body.append("},");
        body.append(history);
        body.append("],\"tools\":");
        body.append(TOOLS);
        body.push('}');

        var resp: u8[>..] = [];
        let status = gc_http_stream(str(API, "/chat/completions"), key, body, resp);
        if status == 499 { print("\x1b[33m(cancelled)\x1b[0m"); return; }
        if status != 200 {
            var doc: json::Node[>..] = [];
            var dec: u8[>..] = [];
            let root, err = json::parse(resp, doc, dec);
            let emsg, has_err = json::as_string(json::member(json::member(root, "error"), "message"));
            if has_err { print("\x1b[31mAPI error (http ", status, "): ", emsg, "\x1b[0m"); }
            else { print("\x1b[31merror (http ", status, "): ", resp, "\x1b[0m"); }
            return;
        }

        var content: u8[>..] = [];
        var ncalls = 0;
        each_delta(resp) { delta =>
            let c, hc = json::as_string(json::member(delta, "content"));
            if hc { content.append(c); }
            let calls = json::member(delta, "tool_calls");
            if calls {
                json::each(calls) { call =>
                    let idx, ok = json::as_i64(json::member(call, "index"));
                    if ok && idx + 1 > ncalls { ncalls = idx + 1; }
                };
            }
        };

        // Record the assistant message, tool calls included.
        if history.len > 0 { history.push(','); }
        history.append("{\"role\":\"assistant\",\"content\":");
        json::format_string(history, content);
        if ncalls > 0 {
            history.append(",\"tool_calls\":[");
            for k in ncalls {
                var id: u8[>..] = [];
                var nm: u8[>..] = [];
                var ar: u8[>..] = [];
                assemble(resp, k, id, nm, ar);
                if k > 0 { history.push(','); }
                history.append("{\"type\":\"function\",\"id\":");
                json::format_string(history, id);
                history.append(",\"function\":{\"name\":");
                json::format_string(history, nm);
                history.append(",\"arguments\":");
                json::format_string(history, if ar.len == 0 { "{}" } else { ar });
                history.append("}}");
            }
            history.push(']');
        }
        history.push('}');
        if ncalls == 0 { return; }

        for k in ncalls {
            var id: u8[>..] = [];
            var nm: u8[>..] = [];
            var ar: u8[>..] = [];
            assemble(resp, k, id, nm, ar);
            if ar.len == 0 { ar.append("{}"); }
            print("\x1b[36m● ", nm, "\x1b[0m\x1b[2m ", ar, "\x1b[0m");
            var result: u8[>..] = [];
            if gc_cancelled() { result.append("error: cancelled by user"); }
            else { run_tool(nm, ar, result); }
            if result.len > 60000 { result.pop_n(result.len - 60000); }
            history.append(",{\"role\":\"tool\",\"tool_call_id\":");
            json::format_string(history, id);
            history.append(",\"content\":");
            json::format_string(history, result);
            history.push('}');
        }
        if gc_cancelled() { gc_clear_cancel(); print("\x1b[33m(cancelled)\x1b[0m"); return; }
    }
}

// Interactive model picker: lists OpenRouter's models matching `filter`
// and lets the user choose one by number.
fn pick_model(filter: u8[:], model: u8[>..]&) {
    var resp: u8[>..] = [];
    let status = gc_http_get(str(API, "/models"), resp);
    var doc: json::Node[>..] = [];
    var dec: u8[>..] = [];
    let root, err = json::parse(resp, doc, dec);
    guard root else { print("could not fetch models (http ", status, ")"); return; }
    let data = json::member(root, "data");
    guard data else { print("could not fetch models (http ", status, ")"); return; }
    var lf: u8[>..] = [];
    lf.append(filter);
    to_lower(lf);
    var ids: u8[>..] = [];
    var total = 0;
    var shown = 0;
    json::each(data) { m =>
        let id, ok = json::as_string(json::member(m, "id"));
        if ok {
            var li: u8[>..] = [];
            li.append(id);
            to_lower(li);
            if lf.len == 0 || find(li, lf) >= 0 {
                total++;
                if shown < 20 { ids.append(id); ids.push('\n'); shown++; }
            }
        }
    };
    if shown == 0 { print("no models match '", filter, "'"); return; }
    var n = 0;
    each_split(ids, '\n') {
        if it.len > 0 { n++; print("  \x1b[36m", n, "\x1b[0m) ", it); }
    };
    if total > shown { print("  \x1b[2m… ", total - shown, " more; narrow with /model <filter>\x1b[0m"); }
    var choice: u8[>..] = [];
    if !gc_ask("pick a number (enter cancels): ", choice) { return; }
    let num, ok = parse_int(trim(choice));
    guard ok && num >= 1 && num <= shown else { print("cancelled"); return; }
    var k = 0;
    each_split(ids, '\n') {
        if it.len > 0 {
            k++;
            if k == num { model.pop_n(model.len); model.append(it); }
        }
    };
    print("model: ", model);
}

fn save_session(name: u8[:]) {
    var home: u8[>..] = [];
    if !env("HOME", home) { home.append("."); }
    make_dir(str(home, "/.config"));
    make_dir(str(home, "/.config/goosecode"));
    make_dir(sessions_dir());
    var path: u8[>..] = [];
    if !session_path(name, path) { print("session names: letters, digits, - and _ only"); return; }
    if write_file_atomic(path, history) { print("saved ", path); } else { print("could not write ", path); }
}

fn load_session(name: u8[:]) {
    var path: u8[>..] = [];
    if !session_path(name, path) { print("session names: letters, digits, - and _ only"); return; }
    var data: u8[>..] = [];
    if !read_file(path, data) { print("no session '", name, "'"); return; }
    history.pop_n(history.len);
    history.append(data);
    print("loaded ", name, " (", history.len, " bytes of history)");
}

fn list_sessions() {
    var names: u8[>..] = [];
    if !list_dir(sessions_dir(), names) { print("no saved sessions"); return; }
    each_split(names, '\n') {
        if ends_with(it, ".json") { print("  ", it[..it.len - 5]); }
    };
}

fn print_help() {
    print("goosecode ", VERSION, " - a coding agent in Goose, powered by OpenRouter\n");
    print("usage: goosecode [options] [prompt]\n       goosecode login\n");
    print("options:\n  -m <model>   model id (default anthropic/claude-sonnet-4.5)\n  -y           auto-approve writes, edits and shell commands\n  -h, --help   this help\n  -v, --version\n");
    print("session commands:\n  /model [filter]  pick a model\n  /clear           forget the conversation\n  /save [name]     save the conversation (default: last)\n  /load [name]     restore a saved conversation\n  /sessions        list saved conversations\n  /login           log in again\n  /help            this help\n  /exit            quit (or Ctrl-D)");
}

fn main() {
    if !env("GOOSECODE_API", API) || API.len == 0 { API.pop_n(API.len); API.append("https://openrouter.ai/api/v1"); }
    let argv = args();
    var model: u8[>..] = [];
    model.append("anthropic/claude-sonnet-4.5");
    var prompt: u8[>..] = [];
    var i = 1;
    while i < argv.len {
        if argv[i] == "login" {
            exit(if login() { 0 } else { 1 });
        } else if argv[i] == "-m" && i + 1 < argv.len {
            model.pop_n(model.len);
            model.append(argv[i + 1]);
            i++;
        } else if argv[i] == "-h" || argv[i] == "--help" {
            print_help();
            exit(0);
        } else if argv[i] == "-v" || argv[i] == "--version" {
            print("goosecode ", VERSION);
            exit(0);
        } else if argv[i] == "-y" {
            auto_approve = true;
        } else {
            if prompt.len > 0 { prompt.push(' '); }
            prompt.append(argv[i]);
        }
        i++;
    }

    load_project_notes();
    var key = load_key();
    if key.len == 0 {
        print("Not logged in.");
        if !login() { exit(1); }
        key = load_key();
    }

    if prompt.len > 0 {
        add_message("user", prompt);
        turn(key, model);
        return;
    }

    gc_init_signals();
    var home: u8[>..] = [];
    if !env("HOME", home) { home.append("."); }
    make_dir(str(home, "/.config"));
    make_dir(str(home, "/.config/goosecode"));
    gc_history_init(str(home, "/.config/goosecode/history"));
    print("goosecode — model ", model, if project_notes_file.len > 0 { str("\nloaded ", project_notes_file) } else { str("") }, "\n/model [filter] pick a model · /clear · /login · /exit · Ctrl-C cancels a reply");
    loop {
        var line: u8[>..] = [];
        if !gc_readline("\x01\x1b[1;32m\x02> \x01\x1b[0m\x02", line) { break; }
        let text = trim(line);
        if text.len == 0 { continue; }
        if text == "/exit" { break; }
        if text == "/help" { print_help(); continue; }
        if text == "/save" { save_session("last"); continue; }
        if starts_with(text, "/save ") { save_session(trim(text[6..])); continue; }
        if text == "/load" { load_session("last"); continue; }
        if starts_with(text, "/load ") { load_session(trim(text[6..])); continue; }
        if text == "/sessions" { list_sessions(); continue; }
        if text == "/clear" { history.pop_n(history.len); print("cleared"); continue; }
        if text == "/login" { if login() { key = load_key(); } continue; }
        if text == "/model" || text == "/models" { pick_model("", model); continue; }
        if starts_with(text, "/models ") { pick_model(trim(text[8..]), model); continue; }
        if starts_with(text, "/model ") {
            let arg = trim(text[7..]);
            if find(arg, "/") >= 0 { model.pop_n(model.len); model.append(arg); print("model: ", model); }
            else { pick_model(arg, model); }
            continue;
        }
        add_message("user", text);
        turn(key, model);
    }
}
