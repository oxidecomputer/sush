//! SSH public key identity.

use std::io;
use std::path::{Path, PathBuf};

use bytes::{Bytes, BytesMut};
use kms_agent_lib::protocol::{
    AgentRequest, AgentRequestKind, AgentResponse, AgentResponseKind, PartialMessage, ProtocolError,
};
use thiserror::Error;
use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;

use sush_common::keys::{KeyError, KeyId, Signature, Signed, Signer, SshPublicKey, ToBeSigned};

/// An open connection to the SSH agent.
#[derive(Debug)]
pub struct SshAgentConnection {
    path: PathBuf,
    sock: UnixStream,
    identity: Option<SshPublicKey>,
}

impl SshAgentConnection {
    const BUFFER_SIZE: usize = 0x1000;

    pub async fn connect(path: &Path) -> Result<SshAgentConnection, IdentityError> {
        let io_err = |err| IdentityError::file_io(path, err);
        let path = path.to_owned();
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
        let request = AgentRequest::RequestIdentities;
        let response = self.request(&request).await?;
        match response {
            AgentResponse::IdentitiesAnswer { keys } => Ok(keys
                .into_iter()
                .map(SshPublicKey::from)
                .filter(SshPublicKey::is_acceptable_algorithm)
                .collect()),
            response => Err(IdentityError::InvalidResponse(
                request.kind(),
                response.kind(),
            )),
        }
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
        let request = AgentRequest::SignRequest {
            key: key.to_owned().into_inner(),
            data: Bytes::copy_from_slice(message),
            flags: 0,
        };

        let response = self.request(&request).await?;
        match response {
            AgentResponse::SignResponse { signature } => Ok(signature.try_into()?),
            response => Err(IdentityError::InvalidResponse(
                request.kind(),
                response.kind(),
            )),
        }
    }

    /// Make an arbitrary request to the SSH agent and wait for a response.
    async fn request(&mut self, request: &AgentRequest) -> Result<AgentResponse, IdentityError> {
        let request_bytes = request.to_bytes()?;
        let sock_err = |err| self.sock_error(err);
        self.sock.writable().await.map_err(sock_err)?;
        loop {
            match self.sock.try_write(&request_bytes) {
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(self.sock_error(e)),
            }
        }

        let mut buffer = BytesMut::with_capacity(Self::BUFFER_SIZE);
        let mut message = PartialMessage::Start;
        self.sock.readable().await.map_err(sock_err)?;
        loop {
            match self.sock.read_buf(&mut buffer).await {
                Ok(0) => break,
                Ok(_) => {
                    message = message.extend(&mut buffer)?;
                    if message.is_complete() {
                        break;
                    }
                    buffer.truncate(0);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(self.sock_error(e)),
            }
        }
        Ok(AgentResponse::parse(message.complete()?)?)
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
    #[error("I/O error accessing `{path}`: {error}")]
    FileIo { path: PathBuf, error: io::Error },
    #[error("Invalid SSH agent response to {0}: {1}")]
    InvalidResponse(AgentRequestKind, AgentResponseKind),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("No usable SSH identities found, only NIST P-256 and Ed25519 keys are supported")]
    NoIdentity,
    #[error("SSH agent protocol error: {0}")]
    Protocol(#[from] ProtocolError),
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
    use std::env;

    use sush_common::codephrases::{PHRASE_WORDS_ID, WORD_SEPARATOR, generate_id};

    use super::*;

    /// May require a presence check if using SK-* keys.
    #[tokio::test]
    async fn ssh_identities() {
        let sock = PathBuf::from(env::var("SSH_AUTH_SOCK").unwrap());
        let mut agent = SshAgentConnection::connect(&sock).await.unwrap();
        for key in agent.list_identities().await.unwrap() {
            let key_id = key.key_id().unwrap();
            assert_eq!(key_id.split(WORD_SEPARATOR).count(), PHRASE_WORDS_ID);

            let nonce = generate_id();
            let signature = agent.sign_with(&key, nonce.as_bytes()).await.unwrap();
            key.verify(nonce.as_bytes(), &signature).unwrap();
        }
    }
}
