use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::host_capabilities::verification::{
    Signature, VerificationConfig, VerificationConfigV1, VersionedVerificationConfig,
};
use sigstore::{
    cosign::verification_constraint::VerificationConstraint, crypto::SignatureDigestAlgorithm,
};
use std::boxed::Box;
use std::{fs, path::Path};

use crate::verify::verification_constraints;
pub use kubewarden_policy_sdk::host_capabilities::verification;

/// Alias to the type that is currently used to store the
/// verification settings.
///
/// When a new version is created:
/// * Update this stype to point to the new version
/// * Implement `TryFrom` that goes from (v - 1) to (v)
pub type LatestVerificationConfig = VerificationConfigV1;

pub struct SignatureVerifier {
    signature: Signature,
}

impl SignatureVerifier {
    pub fn new(signature: Signature) -> Self {
        SignatureVerifier { signature }
    }
    pub fn verifier(self) -> Result<Box<dyn VerificationConstraint>> {
        match self.signature {
            Signature::PubKey {
                owner,
                key,
                annotations,
            } => {
                let vc = verification_constraints::PublicKeyAndAnnotationsVerifier::new(
                    owner.as_deref(),
                    key.as_str(),
                    SignatureDigestAlgorithm::default(),
                    annotations.as_ref(),
                )
                .map_err(|e| anyhow!("Cannot create public key verifier: {}", e))?;
                Ok(Box::new(vc))
            }
            Signature::GenericIssuer {
                issuer,
                subject,
                annotations,
            } => Ok(Box::new(
                verification_constraints::GenericIssuerSubjectVerifier::new(
                    issuer.as_str(),
                    &subject,
                    annotations.as_ref(),
                ),
            )),
            Signature::GithubAction {
                owner,
                repo,
                annotations,
            } => Ok(Box::new(verification_constraints::GitHubVerifier::new(
                owner.as_str(),
                repo.as_deref(),
                annotations.as_ref(),
            ))),
        }
    }
}

pub fn read_verification_file(path: &Path) -> Result<LatestVerificationConfig> {
    let config = fs::read_to_string(path)?;
    build_latest_verification_config(&config)
}

/// This function builds a `LatestVerificationConfig` starting from YAML representation
/// of the verification config.
///
/// **Note well:** because of how we version our configuration structs, this method is required
/// to provide helpful error messages to the end users when their configuration has some mistakes.
/// For example, when the configuration is missing a required attribute.
/// This methods should be used instead of invoking `serde_yaml` deserialization functions against
/// the YAML string.
pub fn build_latest_verification_config(config_str: &str) -> Result<LatestVerificationConfig> {
    let vc: VerificationConfig = serde_yaml::from_str(config_str)?;
    let config = match vc {
        VerificationConfig::Versioned(versioned_config) => match versioned_config {
            VersionedVerificationConfig::V1(c) => c,
            VersionedVerificationConfig::Unsupported => {
                return Err(anyhow!(
                    "Not a supported configuration version: {:?}",
                    versioned_config
                ))
            }
        },
        VerificationConfig::Invalid(mut value) => {
            // let's try to get a more specific error message
            // for that we will perform a direct conversion into LatestVerificationConfig,
            // this is going to provide a more detailed error message to the user, like
            // "missing field `subject`"
            let sanitized_value = if value.is_mapping() {
                // The value includes the `apiVersion` key, which is unknown to the
                // LatestVerificationConfig type.
                // We have to remove it to avoid a non-relevant error.
                let mapping = value.as_mapping_mut().unwrap();
                let unwanted_key: serde_yaml::Value = "apiVersion".to_string().into();
                mapping.remove(&unwanted_key);

                // need to convert back to a non-mutable Mapping, there's no From<mut Mapping>
                let immutable_mapping = mapping.clone();
                let v: serde_yaml::Value = immutable_mapping.into();
                v
            } else {
                value
            };
            let err = serde_yaml::from_value::<LatestVerificationConfig>(sanitized_value);
            return Err(anyhow!("Not a valid configuration file: {:?}", err));
        }
    };

    if config.all_of.is_none() && config.any_of.is_none() {
        return Err(anyhow!(
            "config is missing signatures in both allOf and anyOff list"
        ));
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kubewarden_policy_sdk::host_capabilities::verification::Subject;
    use url::Url;

    #[test]
    fn test_deserialize_on_broken_yaml() {
        let config = r#"---
    foo: [
    "#;
        let vc = serde_yaml::from_str::<VerificationConfig>(config);
        assert!(vc.is_err());
    }

    #[test]
    #[should_panic(expected = "missing field `subject`")]
    fn test_deserialize_on_missing_signature() {
        let config = r#"---
    apiVersion: v1

    allOf:
      - kind: genericIssuer
        issuer: https://token.actions.githubusercontent.com
        # missing subject
        #subject:
        #   urlPrefix: https://github.com/kubewarden/
    "#;
        build_latest_verification_config(config).unwrap();
    }

    #[test]
    fn test_deserialize() {
        let config = r#"---
    apiVersion: v1

    allOf:
      - kind: genericIssuer
        issuer: https://token.actions.githubusercontent.com
        subject:
           equal: https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main
      - kind: genericIssuer
        issuer: https://token.actions.githubusercontent.com
        subject:
           urlPrefix: https://github.com/kubewarden
    "#;

        let vc: VerificationConfig = serde_yaml::from_str(config).unwrap();
        let signatures: Vec<Signature> = vec![
            Signature::GenericIssuer {
                    issuer: "https://token.actions.githubusercontent.com".to_string(),
                    subject: Subject::Equal("https://github.com/kubewarden/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main".to_string()),
                    annotations: None
                },
            Signature::GenericIssuer {
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                subject: Subject::UrlPrefix(Url::parse("https://github.com/kubewarden/").unwrap()),
                annotations: None,
            }
        ];

        match vc {
            VerificationConfig::Versioned(versioned) => match versioned {
                VersionedVerificationConfig::V1(v1) => {
                    let expected = VerificationConfigV1 {
                        all_of: Some(signatures),
                        any_of: None,
                    };
                    assert_eq!(v1, expected);
                }
                _ => panic!("not the expected versioned config"),
            },
            _ => panic!("got an invalid config"),
        }
    }

    #[test]
    fn test_sanitize_url_prefix() {
        let config = r#"---
    apiVersion: v1

    allOf:
      - kind: genericIssuer
        issuer: https://token.actions.githubusercontent.com
        subject:
           urlPrefix: https://github.com/kubewarden # should deserialize path to kubewarden/
      - kind: genericIssuer
        issuer: https://yourdomain.com/oauth2
        subject:
           urlPrefix: https://github.com/kubewarden/ # should deserialize path to kubewarden/
    "#;
        let vc: VerificationConfig = serde_yaml::from_str(config).unwrap();
        let signatures: Vec<Signature> = vec![
            Signature::GenericIssuer {
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                subject: Subject::UrlPrefix(Url::parse("https://github.com/kubewarden/").unwrap()),
                annotations: None,
            },
            Signature::GenericIssuer {
                issuer: "https://yourdomain.com/oauth2".to_string(),
                subject: Subject::UrlPrefix(Url::parse("https://github.com/kubewarden/").unwrap()),
                annotations: None,
            },
        ];

        match vc {
            VerificationConfig::Versioned(versioned) => match versioned {
                VersionedVerificationConfig::V1(v1) => {
                    let expected = VerificationConfigV1 {
                        all_of: Some(signatures),
                        any_of: None,
                    };
                    assert_eq!(v1, expected);
                }
                _ => panic!("not the expected versioned config"),
            },
            _ => panic!("got an invalid config"),
        }
    }
}
