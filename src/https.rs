#![allow(clippy::upper_case_acronyms)]

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::{
    boxed::Box,
    convert::{TryFrom, TryInto},
};
use url::Url;

use crate::fetcher::{ClientProtocol, PolicyFetcher, TlsVerificationMode};
use crate::sources::Certificate;

// Struct used to reference a WASM module that is hosted on a HTTP(s) server
#[derive(Default)]
pub(crate) struct Https {}

impl TryFrom<&Certificate> for reqwest::Certificate {
    type Error = anyhow::Error;

    fn try_from(certificate: &Certificate) -> Result<Self> {
        match certificate {
            Certificate::Der(certificate) => reqwest::Certificate::from_der(certificate)
                .map_err(|err| anyhow!("could not load certificate as DER encoded: {}", err)),
            Certificate::Pem(certificate) => reqwest::Certificate::from_pem(certificate)
                .map_err(|err| anyhow!("could not load certificate as PEM encoded: {}", err)),
        }
    }
}

#[async_trait]
impl PolicyFetcher for Https {
    async fn fetch(&self, url: &Url, client_protocol: ClientProtocol) -> Result<Vec<u8>> {
        let mut client_builder = reqwest::Client::builder();
        match client_protocol {
            ClientProtocol::Http => {}
            ClientProtocol::Https(ref tls_fetch_mode) => {
                client_builder = client_builder.https_only(true);
                match tls_fetch_mode {
                    TlsVerificationMode::SystemCa => {}
                    TlsVerificationMode::CustomCaCertificates(ca_certificates) => {
                        for certificate in ca_certificates.iter() {
                            client_builder =
                                client_builder.add_root_certificate(certificate.try_into()?);
                        }
                    }
                    TlsVerificationMode::NoTlsVerification => {
                        client_builder = client_builder.danger_accept_invalid_certs(true);
                    }
                }
            }
        };

        let client = client_builder.build()?;
        Ok(client
            .get(url.as_ref())
            .send()
            .await?
            .bytes()
            .await?
            .to_vec())
    }
}
