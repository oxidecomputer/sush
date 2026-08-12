// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! SSH public key identity.

use std::io;
use std::path::{Path, PathBuf};

use bytes::{Buf as _, Bytes, BytesMut};
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use sush_common::keys::{KeyError, KeyId, Signature, Signed, Signer, SshPublicKey, ToBeSigned};

use crate::agent::{
    self, AgentError, MAX_MESSAGE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
    SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST, unexpected,
};

/// An open connection to the SSH agent.
#[derive(Debug)]
pub struct SshAgentConnection {
    path: PathBuf,
    sock: UnixStream,
    identity: Option<SshPublicKey>,
}

impl SshAgentConnection {
    pub async fn connect<P>(path: P) -> Result<SshAgentConnection, IdentityError>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref().to_owned();
        let io_err = |err| IdentityError::file_io(&path, err);
        let sock = UnixStream::connect(&path).await.map_err(io_err)?;
        Ok(Self {
            path,
            sock,
            identity: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn list_identities(&mut self) -> Result<Vec<SshPublicKey>, IdentityError> {
        let (kind, payload) = self.transact(agent::request_identities()).await?;
        let keys = match kind {
            SSH_AGENT_IDENTITIES_ANSWER => agent::identities_answer(payload)?,
            got => return Err(unexpected(SSH_AGENTC_REQUEST_IDENTITIES, got).into()),
        };
        Ok(keys
            .into_iter()
            .map(SshPublicKey::from)
            .filter(SshPublicKey::is_acceptable_algorithm)
            .collect())
    }

    /// Get and cache an SSH public key to use for authentication.
    ///
    /// Picks either the specified key or the first key with an
    /// acceptable algorithm (ECDSA, Ed25519, or SK-* variants).
    /// Does not perform any signing.
    pub async fn identity(
        &mut self,
        key_id: Option<&KeyId>,
    ) -> Result<SshPublicKey, IdentityError> {
        if key_id.is_none()
            && let Some(identity) = &self.identity
        {
            return Ok(identity.clone());
        }

        let identities = self.list_identities().await?;
        let identity = if let Some(key_id) = key_id {
            identities
                .iter()
                .find(|key| key.key_id().map(|id| id == *key_id).unwrap_or(false))
                .ok_or(IdentityError::NoIdentity)?
        } else if let Some(first) = identities.first() {
            first
        } else {
            return Err(IdentityError::NoIdentity);
        };
        self.identity = Some(identity.clone());
        Ok(identity.clone())
    }

    /// Sign an arbitrary message with the specified key.
    /// May require a presence check for an SK-* key, and
    /// may return an error if the message is empty.
    pub async fn sign_with(
        &mut self,
        key: &SshPublicKey,
        message: &[u8],
    ) -> Result<Signature, IdentityError> {
        let request = agent::sign_request(key, message)?;
        let (kind, payload) = self.transact(request).await?;
        match kind {
            SSH_AGENT_SIGN_RESPONSE => Ok(agent::sign_response(payload)?.try_into()?),
            got => Err(unexpected(SSH_AGENTC_SIGN_REQUEST, got).into()),
        }
    }

    /// One request-response exchange with the agent, returning the
    /// response's type byte and payload.
    async fn transact(&mut self, request: Bytes) -> Result<(u8, Bytes), IdentityError> {
        self.sock
            .write_all(&request)
            .await
            .map_err(|err| self.sock_error(err))?;
        let length = self
            .sock
            .read_u32()
            .await
            .map_err(|err| self.sock_error(err))?;
        if length > MAX_MESSAGE {
            return Err(AgentError::Oversized(length.into()).into());
        }
        let mut body = BytesMut::zeroed(length as usize);
        self.sock
            .read_exact(&mut body)
            .await
            .map_err(|err| self.sock_error(err))?;
        let mut body = body.freeze();
        if body.is_empty() {
            return Err(AgentError::Empty.into());
        }
        Ok((body.get_u8(), body))
    }

    fn sock_error(&self, err: io::Error) -> IdentityError {
        IdentityError::file_io(self.path.clone(), err)
    }
}

impl Signer for SshAgentConnection {
    type Error = IdentityError;

    async fn sign<T: ToBeSigned>(&mut self, thing: T) -> Result<Signed<T>, Self::Error> {
        let identity = self.identity(None).await?;
        let signature = self.sign_with(&identity, &thing.to_be_signed()).await?;
        Ok(Signed::new(thing, identity.key_id()?, signature.encode()?))
    }
}

/// What went wrong accessing or proving an identity.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("SSH agent protocol error: {0}")]
    Agent(#[from] AgentError),
    #[error("I/O error accessing `{path}`: {error}")]
    FileIo { path: PathBuf, error: io::Error },
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("No usable SSH identities found, only NIST P-256 and Ed25519 keys are supported")]
    NoIdentity,
}

impl IdentityError {
    pub fn file_io(path: impl AsRef<Path>, error: io::Error) -> Self {
        Self::FileIo {
            path: path.as_ref().to_owned(),
            error,
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use sush_common::codephrases::Codephrase;
    use tempfile::TempDir;
    use tokio::process::Command;

    use super::*;

    #[tokio::test]
    async fn ssh_identities() {
        let ssh_home = TempDir::new().unwrap();
        let sock = ssh_home.path().join("sock");
        let key = ssh_home.path().join("id_ed25519");

        let status = Command::new("ssh-keygen")
            .args(["-t", "ed25519"])
            .args(["-P", ""]) // Don't set a password.
            .arg("-f")
            .arg(&key)
            .status()
            .await
            .expect("failed to run ssh-keygen");
        if !status.success() {
            panic!("ssh-keygen failed with {status:?}");
        }

        let mut agent_process = Command::new("ssh-agent")
            .arg("-D") // Start the agent in foreground mode.
            .arg("-a")
            .arg(&sock)
            .spawn()
            .expect("failed to spawn ssh-agent");

        // Wait for the agent to start up.
        for _ in 0..20 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let status = Command::new("ssh-add")
            .arg(&key)
            .env("SSH_AUTH_SOCK", &sock)
            .status()
            .await
            .expect("failed to run ssh-add");
        if !status.success() {
            panic!("ssh-add failed with {status:?}");
        }

        let mut agent = SshAgentConnection::connect(&sock).await.unwrap();
        for key in agent.list_identities().await.unwrap() {
            let nonce = Codephrase::random();
            let signature = agent.sign_with(&key, &nonce.to_be_bytes()).await.unwrap();
            key.verify(&nonce.to_be_bytes(), &signature).unwrap();
        }

        agent_process
            .kill()
            .await
            .expect("failed to kill ssh-agent");
    }
}
