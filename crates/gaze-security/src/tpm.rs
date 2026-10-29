// SPDX-FileCopyrightText: 2026 Gundu Labs
// SPDX-License-Identifier: GPL-3.0-or-later

//! TPM sealing shared by gazed's template key and the keyring credential.
//! PAM uses a local device, never a TCTI supplied through its host's environment.

use anyhow::{Context as _, anyhow, ensure};
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::{CapabilityType, SessionType, Tss2ResponseCodeKind};
use tss_esapi::handles::SessionHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::AesKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{
    CapabilityData, Digest, EccPoint, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme,
    PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
    SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::DeviceConfig;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{Context, TctiNameConf};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;

/// SHA-256 PCRs a sealed object is bound to, as a bitmask over PCR 0..=23. Empty means no policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pcrs(u32);

impl Pcrs {
    pub const NONE: Self = Self(0);
    pub const MAX: u32 = 23;

    pub fn from_bits(bits: u32) -> anyhow::Result<Self> {
        ensure!(
            bits >> (Self::MAX + 1) == 0,
            "PCR selection names a PCR above {}",
            Self::MAX
        );
        Ok(Self(bits))
    }
    pub fn bits(self) -> u32 {
        self.0
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub fn iter(self) -> impl Iterator<Item = u32> {
        (0..=Self::MAX).filter(move |pcr| self.0 & (1 << pcr) != 0)
    }
    fn slots(self) -> anyhow::Result<Vec<PcrSlot>> {
        self.iter()
            .map(|pcr| PcrSlot::try_from(1u32 << pcr).map_err(|e| anyhow!("PCR {pcr}: {e}")))
            .collect()
    }
}

/// Parses `7,14`; an empty string or `none` selects no PCRs.
impl FromStr for Pcrs {
    type Err = anyhow::Error;
    fn from_str(text: &str) -> anyhow::Result<Self> {
        let text = text.trim();
        if text.is_empty() || text.eq_ignore_ascii_case("none") {
            return Ok(Self::NONE);
        }
        let mut bits = 0;
        for part in text.split(',') {
            let pcr: u32 = part
                .trim()
                .parse()
                .map_err(|_| anyhow!("`{}` is not a PCR number", part.trim()))?;
            ensure!(
                pcr <= Self::MAX,
                "PCR {pcr} does not exist; use 0-{}",
                Self::MAX
            );
            bits |= 1 << pcr;
        }
        Ok(Self(bits))
    }
}

impl fmt::Display for Pcrs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("none");
        }
        let list: Vec<String> = self.iter().map(|pcr| pcr.to_string()).collect();
        f.write_str(&list.join(","))
    }
}

/// The TPM refused an unseal because the sealed object's PCR policy no longer holds.
/// The PCRs come from the unauthenticated record header, so the message allows for both causes.
#[derive(Debug)]
pub struct PolicyFailed(pub Pcrs);

impl fmt::Display for PolicyFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PCRs {} changed since enrollment, or the record was altered",
            self.0
        )
    }
}

impl std::error::Error for PolicyFailed {}

/// A sealed key never leaves this crate as a bare array: the caller's copy wipes on drop.
pub type SealedKey = Zeroizing<[u8; KEY_LEN]>;

pub const TPM_RM_DEVICE: &str = "/dev/tpmrm0";
pub const TPM_RAW_DEVICE: &str = "/dev/tpm0";
pub const TPM_DEVICES: [&str; 2] = [TPM_RM_DEVICE, TPM_RAW_DEVICE];

fn local_device_context() -> anyhow::Result<Context> {
    for device in TPM_DEVICES {
        if Path::new(device).exists() {
            let config = DeviceConfig::from_str(device)?;
            if let Ok(context) = Context::new(TctiNameConf::Device(config)) {
                return Ok(context);
            }
        }
    }
    Err(anyhow!("no usable local TPM 2.0 device"))
}

// Nothing about this parent is stored on disk. CreatePrimary re-derives the identical key
// from the owner seed and this exact template, and no PCR policy means updates don't break it.
fn create_primary(context: &mut Context) -> anyhow::Result<tss_esapi::handles::KeyHandle> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .build()
        .context("failed to build primary object attributes")?;
    let params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_symmetric(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
        })
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .context("failed to build primary ECC parameters")?;
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .context("failed to build primary public template")?;
    Ok(context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .context("TPM CreatePrimary failed")?
        .key_handle)
}

pub fn sealed_object_public() -> anyhow::Result<Public> {
    sealed_template(None)
}

// With a policy, only a session satisfying it can unseal: the empty auth value no longer works.
fn sealed_template(policy: Option<Digest>) -> anyhow::Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(policy.is_none())
        // We supply the data, so it must not originate in the TPM.
        .with_sensitive_data_origin(false)
        .with_sign_encrypt(false)
        .with_decrypt(false)
        .with_restricted(false)
        .build()
        .context("failed to build sealed-object attributes")?;
    let mut builder = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default());
    if let Some(digest) = policy {
        builder = builder.with_auth_policy(digest);
    }
    builder
        .build()
        .context("failed to build sealed-object public template")
}

// An empty PolicyPCR digest makes the TPM use the PCR values it holds right now: a trial
// session records them into the policy, a real session matches against them at unseal.
fn pcr_policy_session(
    context: &mut Context,
    kind: SessionType,
    pcrs: Pcrs,
) -> anyhow::Result<PolicySession> {
    let session = context
        .start_auth_session(
            None,
            None,
            None,
            kind,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("TPM StartAuthSession failed")?
        .context("TPM returned no policy session")?;
    let policy = PolicySession::try_from(session)?;
    let result = (|| {
        let selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &pcrs.slots()?)
            .build()?;
        context
            .policy_pcr(policy, Digest::default(), selection)
            .context("TPM PolicyPCR failed")
    })();
    if let Err(error) = result {
        let _ = context.flush_context(SessionHandle::from(policy).into());
        return Err(error);
    }
    Ok(policy)
}

/// PCRs in `pcrs` that the TPM's SHA-256 bank does not hold.
fn missing_from_sha256_bank(pcrs: Pcrs, allocated: &PcrSelectionList) -> anyhow::Result<Pcrs> {
    let held = allocated
        .get_selections()
        .iter()
        .filter(|selection| selection.hashing_algorithm() == HashingAlgorithm::Sha256)
        .flat_map(|selection| selection.selected())
        .fold(0, |bits, slot| bits | u32::from(slot));
    Pcrs::from_bits(pcrs.bits() & !held)
}

// PolicyPCR silently drops PCRs from banks the TPM has not allocated, so without this check
// a SHA-1-only TPM would seal to an empty selection that matches any boot.
fn ensure_sha256_bank(context: &mut Context, pcrs: Pcrs) -> anyhow::Result<()> {
    let (data, _) = context
        .get_capability(CapabilityType::AssignedPcr, 0, 1)
        .context("TPM GetCapability(PCRS) failed")?;
    let CapabilityData::AssignedPcr(allocated) = data else {
        anyhow::bail!("TPM returned no PCR allocation");
    };
    let missing = missing_from_sha256_bank(pcrs, &allocated)?;
    ensure!(
        missing.is_empty(),
        "the TPM's SHA-256 bank does not hold PCRs {missing}, so binding to them would \
         protect nothing; enable the SHA-256 PCR bank in firmware"
    );
    Ok(())
}

fn pcr_policy_digest(context: &mut Context, pcrs: Pcrs) -> anyhow::Result<Digest> {
    ensure_sha256_bank(context, pcrs)?;
    let trial = pcr_policy_session(context, SessionType::Trial, pcrs)?;
    let digest = context.policy_get_digest(trial);
    let _ = context.flush_context(SessionHandle::from(trial).into());
    digest.context("TPM PolicyGetDigest failed")
}

pub fn seal_in(context: &mut Context, key: &[u8; KEY_LEN]) -> anyhow::Result<(Public, Private)> {
    seal_bound_in(context, key, Pcrs::NONE)
}

pub fn seal_bound_in(
    context: &mut Context,
    key: &[u8; KEY_LEN],
    pcrs: Pcrs,
) -> anyhow::Result<(Public, Private)> {
    let policy = if pcrs.is_empty() {
        None
    } else {
        Some(pcr_policy_digest(context, pcrs)?)
    };
    let public = sealed_template(policy)?;
    let sensitive =
        SensitiveData::try_from(key.to_vec()).map_err(|e| anyhow!("invalid key length: {e}"))?;
    let parent = create_primary(context)?;
    let result = context.execute_with_nullauth_session(|ctx| {
        ctx.create(parent, public, None, Some(sensitive), None, None)
    });
    let _ = context.flush_context(parent.into());
    let created = result.context("TPM Create (seal) failed")?;
    Ok((created.out_public, created.out_private))
}

pub fn unseal_in(
    context: &mut Context,
    public: Public,
    private: Private,
) -> anyhow::Result<SealedKey> {
    unseal_bound_in(context, public, private, Pcrs::NONE)
}

pub fn unseal_bound_in(
    context: &mut Context,
    public: Public,
    private: Private,
    pcrs: Pcrs,
) -> anyhow::Result<SealedKey> {
    let parent = create_primary(context)?;
    let result = if pcrs.is_empty() {
        context
            .execute_with_nullauth_session(|ctx| {
                let object = ctx.load(parent, private, public)?;
                let data = ctx.unseal(object.into());
                let _ = ctx.flush_context(object.into());
                data
            })
            .map_err(anyhow::Error::from)
    } else {
        unseal_with_pcr_policy(context, parent, public, private, pcrs)
    };
    let _ = context.flush_context(parent.into());

    // SensitiveData holds a Zeroizing buffer, so the only copy to guard is the one we return.
    let sensitive = result.context("TPM Load/Unseal failed")?;
    let bytes = sensitive.value();
    let key: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
        anyhow!(
            "unsealed key has unexpected length {} (expected {KEY_LEN})",
            bytes.len()
        )
    })?;
    Ok(Zeroizing::new(key))
}

fn unseal_with_pcr_policy(
    context: &mut Context,
    parent: tss_esapi::handles::KeyHandle,
    public: Public,
    private: Private,
    pcrs: Pcrs,
) -> anyhow::Result<SensitiveData> {
    let object = context.execute_with_nullauth_session(|ctx| ctx.load(parent, private, public))?;
    let result = pcr_policy_session(context, SessionType::Policy, pcrs).and_then(|policy| {
        let data =
            context.execute_with_session(Some(policy.into()), |ctx| ctx.unseal(object.into()));
        let _ = context.flush_context(SessionHandle::from(policy).into());
        data.map_err(|error| match error {
            tss_esapi::Error::Tss2Error(rc)
                if rc.kind() == Some(Tss2ResponseCodeKind::PolicyFail) =>
            {
                PolicyFailed(pcrs).into()
            }
            other => other.into(),
        })
    });
    let _ = context.flush_context(object.into());
    result
}

pub fn seal(key: &[u8; KEY_LEN], pcrs: Pcrs) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut context = local_device_context()?;
    let (public, private) = seal_bound_in(&mut context, key, pcrs)?;
    Ok((public.marshall()?, private.value().to_vec()))
}

pub fn unseal(public: &[u8], private: &[u8], pcrs: Pcrs) -> anyhow::Result<SealedKey> {
    let mut context = local_device_context()?;
    unseal_bound_in(
        &mut context,
        Public::unmarshall(public)?,
        Private::try_from(private.to_vec())?,
        pcrs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_constants_point_at_the_local_tpms() {
        assert_eq!(TPM_RM_DEVICE, "/dev/tpmrm0");
        assert_eq!(TPM_RAW_DEVICE, "/dev/tpm0");
        assert_eq!(TPM_DEVICES, [TPM_RM_DEVICE, TPM_RAW_DEVICE]);
        assert_eq!(KEY_LEN, 32);
    }

    #[test]
    fn sealed_template_needs_no_tpm_and_is_a_keyed_hash() {
        let public = sealed_object_public().expect("template builds without hardware");
        assert!(
            matches!(public, Public::KeyedHash { .. }),
            "sealing needs a keyed-hash object, not a key"
        );
        assert_eq!(public.name_hashing_algorithm(), HashingAlgorithm::Sha256);
    }

    #[test]
    fn sealed_template_is_bound_to_this_tpm_but_supplied_externally() {
        let public = sealed_object_public().unwrap();
        let attrs = public.object_attributes();
        assert!(
            attrs.fixed_tpm(),
            "sealed blob must not migrate to another TPM"
        );
        assert!(
            attrs.fixed_parent(),
            "sealed blob must stay under the same parent"
        );
        assert!(
            !attrs.sensitive_data_origin(),
            "we supply the key, so it must not originate in the TPM"
        );
        assert!(attrs.user_with_auth(), "unseal is gated on auth");
        assert!(
            !attrs.decrypt() && !attrs.sign_encrypt() && !attrs.restricted(),
            "a sealed object is data, not a key"
        );
    }

    #[test]
    fn sealed_template_round_trips_through_its_on_disk_form() {
        let public = sealed_object_public().unwrap();
        let bytes = public.marshall().expect("template must marshall for disk");
        assert!(!bytes.is_empty());
        let parsed = Public::unmarshall(&bytes).expect("stored blob must parse");
        assert_eq!(parsed.marshall().unwrap(), bytes);
    }

    #[test]
    fn pcr_lists_parse_and_print_in_the_same_form() {
        assert_eq!("".parse::<Pcrs>().unwrap(), Pcrs::NONE);
        assert_eq!("none".parse::<Pcrs>().unwrap(), Pcrs::NONE);
        let pcrs: Pcrs = " 14, 7 ,7".parse().unwrap();
        assert_eq!(pcrs.bits(), (1 << 7) | (1 << 14));
        assert_eq!(pcrs.to_string(), "7,14");
        assert_eq!(Pcrs::NONE.to_string(), "none");
        assert_eq!(
            "0,23".parse::<Pcrs>().unwrap().iter().collect::<Vec<_>>(),
            [0, 23]
        );
        for bad in ["24", "-1", "7,", "seven", "7;14"] {
            assert!(bad.parse::<Pcrs>().is_err(), "{bad} must be rejected");
        }
        assert!(Pcrs::from_bits(1 << 24).is_err());
    }

    #[test]
    fn a_pcr_policy_replaces_the_empty_auth_value() {
        let digest = Digest::try_from(vec![1u8; 32]).unwrap();
        let public = sealed_template(Some(digest.clone())).unwrap();
        assert!(
            !public.object_attributes().user_with_auth(),
            "with a policy, the empty password must not unseal"
        );
        assert_eq!(public.auth_policy(), &digest);
        assert!(sealed_object_public().unwrap().auth_policy().is_empty());
    }

    // Run against swtpm, e.g. TCTI=swtpm:port=2321 cargo test -p gaze-security -- --ignored
    // The guard serializes tests sharing the TPM, since some of them extend PCR 16.
    fn test_context() -> (std::sync::MutexGuard<'static, ()>, Context) {
        static TPM: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = TPM.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let context = Context::new(
            TctiNameConf::from_environment_variable().expect("set TCTI to a test TPM"),
        )
        .expect("test TPM unreachable");
        (guard, context)
    }

    fn extend_pcr16(context: &mut Context) {
        use tss_esapi::handles::PcrHandle;
        use tss_esapi::structures::DigestValues;
        let mut digests = DigestValues::new();
        digests.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(vec![0xa5u8; 32]).unwrap(),
        );
        context
            .execute_with_nullauth_session(|ctx| ctx.pcr_extend(PcrHandle::Pcr16, digests))
            .unwrap();
    }

    #[test]
    #[ignore = "requires a test TPM (swtpm) named by TCTI"]
    fn pcr_bound_key_unseals_until_the_pcr_changes() {
        let (_tpm, mut context) = test_context();
        let pcrs: Pcrs = "7,16".parse().unwrap();
        let key = [3u8; KEY_LEN];
        let (public, private) = seal_bound_in(&mut context, &key, pcrs).unwrap();
        assert!(!public.object_attributes().user_with_auth());
        let unsealed =
            unseal_bound_in(&mut context, public.clone(), private.clone(), pcrs).unwrap();
        assert_eq!(*unsealed, key);
        assert!(
            unseal_bound_in(&mut context, public.clone(), private.clone(), Pcrs::NONE).is_err(),
            "the empty auth value must not bypass the policy"
        );

        extend_pcr16(&mut context);
        let error = unseal_bound_in(&mut context, public, private, pcrs).unwrap_err();
        assert!(error.downcast_ref::<PolicyFailed>().is_some(), "{error:#}");
    }

    #[test]
    fn only_pcrs_the_sha256_bank_holds_can_be_bound() {
        let bank = |algorithm, pcrs: &str| {
            let slots = pcrs.parse::<Pcrs>().unwrap().slots().unwrap();
            PcrSelectionListBuilder::new()
                .with_selection(algorithm, &slots)
                .build()
                .unwrap()
        };
        let wanted: Pcrs = "7,16".parse().unwrap();
        assert!(
            missing_from_sha256_bank(wanted, &bank(HashingAlgorithm::Sha256, "0,7,16,23"))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            missing_from_sha256_bank(wanted, &bank(HashingAlgorithm::Sha256, "7"))
                .unwrap()
                .to_string(),
            "16"
        );
        assert_eq!(
            missing_from_sha256_bank(wanted, &bank(HashingAlgorithm::Sha1, "0,7,16,23")).unwrap(),
            wanted,
            "a SHA-1 bank does not count"
        );
    }

    #[test]
    #[ignore = "requires a test TPM (swtpm) named by TCTI"]
    fn sealing_needs_the_pcrs_in_the_sha256_bank() {
        let (_tpm, mut context) = test_context();
        let (data, _) = context
            .get_capability(CapabilityType::AssignedPcr, 0, 1)
            .unwrap();
        let CapabilityData::AssignedPcr(allocated) = data else {
            panic!("no PCR allocation")
        };
        let pcrs: Pcrs = "7".parse().unwrap();
        let sealed = seal_bound_in(&mut context, &[5u8; KEY_LEN], pcrs);
        if missing_from_sha256_bank(pcrs, &allocated)
            .unwrap()
            .is_empty()
        {
            sealed.unwrap();
        } else {
            let error = sealed.unwrap_err();
            assert!(format!("{error:#}").contains("SHA-256 bank"), "{error:#}");
        }
    }

    #[test]
    #[ignore = "requires a test TPM (swtpm) named by TCTI"]
    fn unbound_keys_keep_unsealing_after_pcr_changes() {
        let (_tpm, mut context) = test_context();
        let key = [4u8; KEY_LEN];
        let (public, private) = seal_in(&mut context, &key).unwrap();
        extend_pcr16(&mut context);
        assert_eq!(*unseal_in(&mut context, public, private).unwrap(), key);
    }

    #[test]
    fn unmarshall_rejects_garbage_instead_of_panicking() {
        assert!(Public::unmarshall(&[]).is_err());
        assert!(Public::unmarshall(&[0u8; 8]).is_err());
    }
}
