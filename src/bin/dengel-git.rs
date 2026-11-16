//! The server binary. CLI contract (locked - the oracle's end-to-end
//! tests invoke exactly this):
//!
//!   dengel-git upload-pack <git-dir>
//!       Protocol v2 upload-pack over stdio. Stock git reaches it via
//!       `git -c protocol.ext.allow=always clone "ext::dengel-git upload-pack %S"`.
//!
//!   dengel-git receive-pack <git-dir>
//!       receive-pack (ADR-0008's ingress-quarantine pipeline) over
//!       stdio. Stock git reaches it via
//!       `git push "ext::dengel-git receive-pack %S" <refspec>` - same
//!       ext:: convention as upload-pack, one argument, no flags.
//!
//!   dengel-git serve-http --addr <ip:port> --root <dir>
//!       Smart-HTTP: serves every <root>/<name>.git at
//!       http://<addr>/<name>.git for stock `git clone`/`git fetch`/
//!       `git push`.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => println!("dengel-git {}", env!("CARGO_PKG_VERSION")),
        Some("upload-pack") => run_upload_pack(&args),
        Some("receive-pack") => run_receive_pack(&args),
        Some("serve-http") => run_serve_http(&args),
        _ => {
            eprintln!(
                "usage: dengel-git upload-pack <git-dir> | dengel-git receive-pack <git-dir> | dengel-git serve-http --addr <ip:port> --root <dir>"
            );
            std::process::exit(2);
        }
    }
}

fn run_upload_pack(args: &[String]) {
    let Some(git_dir) = args.get(1) else {
        eprintln!("usage: dengel-git upload-pack <git-dir>");
        std::process::exit(2);
    };
    let git_dir = std::path::PathBuf::from(git_dir);

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();

    if let Err(e) =
        dengel_git_engine::server::session::serve_upload_pack(&git_dir, &mut input, &mut output)
    {
        eprintln!("dengel-git upload-pack: {e}");
        std::process::exit(1);
    }
}

fn run_receive_pack(args: &[String]) {
    let Some(git_dir) = args.get(1) else {
        eprintln!("usage: dengel-git receive-pack <git-dir>");
        std::process::exit(2);
    };
    let git_dir = std::path::PathBuf::from(git_dir);

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();

    if let Err(e) =
        dengel_git_engine::receive::session::serve_receive_pack(&git_dir, &mut input, &mut output)
    {
        eprintln!("dengel-git receive-pack: {e}");
        std::process::exit(1);
    }
}

fn run_serve_http(args: &[String]) {
    let mut addr = "127.0.0.1:8080".to_owned();
    let mut root: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                let Some(value) = args.get(i + 1) else {
                    eprintln!("dengel-git serve-http: --addr needs an address");
                    std::process::exit(2);
                };
                addr.clone_from(value);
                i += 2;
            }
            "--root" => {
                root = args.get(i + 1).cloned();
                i += 2;
            }
            other => {
                eprintln!("dengel-git serve-http: unrecognized argument {other:?}");
                std::process::exit(2);
            }
        }
    }

    let Some(root) = root else {
        eprintln!("usage: dengel-git serve-http --addr <ip:port> --root <dir>");
        std::process::exit(2);
    };

    let socket_addr: std::net::SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("dengel-git serve-http: invalid --addr {addr:?}: {e}");
            std::process::exit(2);
        }
    };
    let root = std::path::PathBuf::from(root);

    let runtime = tokio::runtime::Runtime::new().expect("failed to start the tokio runtime");
    if let Err(e) = runtime.block_on(dengel_git_engine::standalone::serve(socket_addr, root)) {
        eprintln!("dengel-git serve-http: {e}");
        std::process::exit(1);
    }
}
