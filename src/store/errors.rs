use thiserror::Error;

pub type StoreResult<T> = std::result::Result<T, StoreError>;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error(transparent)]
    UrlParserError(#[from] url::ParseError),
    #[error("faild to read verification file: {0}")]
    VerificationFileReadError(#[from] std::io::Error),
    #[error("cannot read policy in local storage: {0}")]
    FailedToReadPolicyInLocalStorageError(#[from] walkdir::Error),
    #[error(transparent)]
    PolicyStoragePathError(#[from] std::path::StripPrefixError),
    #[error("unknown scheme: {0}")]
    UnknownSchemeError(String),
    #[error("multiple policies found with the same prefix: {0}")]
    MultiplePoliciesFoundError(String),
    #[error(transparent)]
    DigestError(#[from] crate::policy::DigestError),
    #[error(transparent)]
    DecoderError(#[from] base64::DecodeError),
}
