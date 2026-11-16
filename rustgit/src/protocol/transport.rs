//! Local transport: spawns `git upload-pack <repo>` as a persistent
//! subprocess and speaks pkt-lines over its stdin/stdout.
//!
//! Invocation choice source: git-reference/Documentation/
//! git-upload-pack.adoc ("--stateless-rpc: Perform only a single
//! read-write cycle... fits the HTTP POST model") and gitprotocol-v2
//! .adoc's "SSH and File Transport" section ("the GIT_PROTOCOL
//! environment variable must be set explicitly to include
//! 'version=2'"). We need a persistent multi-round pipe (capability
//! advertisement, then ls-refs, then fetch - all on one connection),
//! which is the ssh/file transport model, not stateless-rpc's HTTP
//! model - so: plain `git upload-pack <repo>`, no --stateless-rpc,
//! with GIT_PROTOCOL=version=2 in the child's environment. See
//! NOTES-02.md for the reasoning that led here.

use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use super::pktline::{self, PktLine};

pub struct UploadPackClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl UploadPackClient {
    pub fn spawn(repo_path: &Path) -> std::io::Result<Self> {
        Self::spawn_with_protocol(repo_path, true)
    }

    /// P4: spawn WITHOUT GIT_PROTOCOL=version=2, to get real git's
    /// legacy (v0) behaviour - see NOTES-02.md's P4 finding for why
    /// this (omitting the env var), not a server-side config, is the
    /// actual mechanism that controls this for the local transport.
    pub fn spawn_legacy(repo_path: &Path) -> std::io::Result<Self> {
        Self::spawn_with_protocol(repo_path, false)
    }

    fn spawn_with_protocol(repo_path: &Path, request_v2: bool) -> std::io::Result<Self> {
        let mut cmd = Command::new("git");
        cmd.arg("upload-pack").arg(repo_path);
        if request_v2 {
            cmd.env("GIT_PROTOCOL", "version=2");
        } else {
            cmd.env_remove("GIT_PROTOCOL");
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take().expect("child stdin not piped");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout not piped"));
        Ok(UploadPackClient {
            child,
            stdin,
            stdout,
        })
    }

    pub fn write_data_line(&mut self, payload: &[u8]) -> std::io::Result<()> {
        pktline::write_data_line(&mut self.stdin, payload)
    }

    pub fn write_flush(&mut self) -> std::io::Result<()> {
        pktline::write_flush(&mut self.stdin)
    }

    pub fn write_delim(&mut self) -> std::io::Result<()> {
        pktline::write_delim(&mut self.stdin)
    }

    pub fn flush_stdin(&mut self) -> std::io::Result<()> {
        self.stdin.flush()
    }

    pub fn read_pkt_line(&mut self) -> std::io::Result<Option<PktLine>> {
        pktline::read_pkt_line(&mut self.stdout)
    }

    pub fn read_until_flush(&mut self) -> std::io::Result<Vec<PktLine>> {
        pktline::read_until_flush(&mut self.stdout)
    }

    /// Read raw bytes directly (used by fetch.rs for the packfile
    /// section, which is its own pkt-line-framed sideband stream but
    /// benefits from being handed to the pack reader as a plain byte
    /// stream once demultiplexed).
    pub fn read_exact_raw(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.stdout.read_exact(buf)
    }

    /// Close stdin (signals EOF to the child - used after sending a
    /// final flush with nothing more to say) and collect stderr, for
    /// diagnosing a non-zero exit.
    pub fn finish(mut self) -> std::io::Result<String> {
        drop(self.stdin);
        let mut stderr_buf = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            let _ = stderr.read_to_string(&mut stderr_buf);
        }
        self.child.wait()?;
        Ok(stderr_buf)
    }
}
