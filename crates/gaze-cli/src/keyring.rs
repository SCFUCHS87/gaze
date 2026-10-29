// SPDX-FileCopyrightText: 2026 Gundu Labs
// SPDX-License-Identifier: GPL-3.0-or-later

use gaze_core::config::Config;
use gaze_security::keyring::{Backend, Pcrs, Zeroizing};
use std::path::Path;

const PCR_SYSFS: &str = "/sys/class/tpm/tpm0/pcr-sha256";
const SECURE_BOOT_EFIVAR: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// Checks whether this backend is enabled before changing core-dump settings or
/// prompting for a password. Kept pure so it can be tested without PAM.
fn ensure_backend_enabled(config: &Config, backend: Backend) -> anyhow::Result<()> {
    let enabled = match backend {
        Backend::Gnome => config.storage.unlock_gnome_keyring,
        Backend::KWallet => config.storage.unlock_kwallet,
    };
    anyhow::ensure!(
        enabled,
        "enable {} unlock with gaze config first",
        backend.name()
    );
    Ok(())
}

/// The EFI variable holds four attribute bytes, then 1 when Secure Boot is on.
fn secure_boot_enabled(efivar: &Path) -> bool {
    std::fs::read(efivar).is_ok_and(|data| data.get(4) == Some(&1))
}

/// Why a PCR says nothing about how this machine booted, if it doesn't.
/// `sysfs` holds one hex file per PCR; unreadable PCRs are not guessed at.
fn weak_pcr(pcr: u32, sysfs: &Path) -> Option<String> {
    if matches!(pcr, 16 | 23) {
        return Some(format!(
            "PCR {pcr} can be reset or extended by any program at runtime, so it says nothing \
             about how this machine booted"
        ));
    }
    let value = std::fs::read_to_string(sysfs.join(pcr.to_string())).unwrap_or_default();
    let value = value.trim();
    // PCRs 17-22 reset to all ones and the rest to all zeros until something measures them.
    let reset = |digit| value.bytes().all(|b| b.eq_ignore_ascii_case(&digit));
    (!value.is_empty() && (reset(b'0') || reset(b'f'))).then(|| {
        format!(
            "PCR {pcr} still holds its reset value: nothing measured it this boot, so binding to \
             it adds no protection"
        )
    })
}

/// Refuses a binding that protects nothing because every PCR in it is weak.
fn check_pcrs(pcrs: Pcrs, sysfs: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        pcrs.is_empty() || pcrs.iter().any(|pcr| weak_pcr(pcr, sysfs).is_none()),
        "every PCR in {pcrs} can be reset or was not measured this boot, so binding to them \
         would protect nothing; choose PCRs such as 7"
    );
    Ok(())
}

/// Advice for PCRs that bind poorly or a boot that leaves them weak.
fn pcr_warnings(pcrs: Pcrs, sysfs: &Path, efivar: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    if !pcrs.is_empty() && !secure_boot_enabled(efivar) {
        warnings.push(
            "Secure Boot is not enabled, so PCR binding cannot tell this boot from another OS \
             started from a USB stick; enable Secure Boot in firmware, then run `gaze keyring` \
             again"
                .to_string(),
        );
    }
    for pcr in pcrs.iter() {
        if let Some(weak) = weak_pcr(pcr, sysfs) {
            warnings.push(weak);
            continue;
        }
        match pcr {
            0 | 1 | 2 | 4 | 5 | 8 | 9 | 11 => warnings.push(format!(
                "PCR {pcr} changes on routine firmware, boot loader, boot entry, or kernel \
                 updates; expect to run `gaze keyring` again after them"
            )),
            10 => warnings.push(
                "PCR 10 is extended by IMA as programs run, so with an IMA policy loaded it can \
                 change before the next login"
                    .to_string(),
            ),
            _ => {}
        }
    }
    if pcrs.iter().any(|pcr| pcr == 7) {
        warnings.push(
            "PCR 7 changes when Secure Boot is toggled or its key databases (db, dbx) are \
             updated; run `gaze keyring` again after such an update"
                .to_string(),
        );
    }
    warnings
}

/// The binding to enroll with: the one asked for, else the existing record's, so that
/// enrolling again after a boot change keeps it.
fn chosen_pcrs(
    requested: Option<Pcrs>,
    existing: impl FnOnce() -> anyhow::Result<Option<Pcrs>>,
) -> anyhow::Result<Pcrs> {
    match requested {
        Some(pcrs) => Ok(pcrs),
        None => Ok(existing()
            .map_err(|err| {
                anyhow::anyhow!(
                    "the existing record's PCR binding could not be read ({err:#}); pass --pcrs \
                     with a list or `none`"
                )
            })?
            .unwrap_or(Pcrs::NONE)),
    }
}

/// The current record's binding, used as the wizard's default.
pub fn existing_pcrs(backend: Backend, username: &str) -> Pcrs {
    gaze_security::keyring::record_pcrs(backend, username)
        .ok()
        .flatten()
        .unwrap_or(Pcrs::NONE)
}

pub fn enroll(
    username: &str,
    config: &Config,
    backend: Backend,
    pcrs: Option<Pcrs>,
) -> anyhow::Result<()> {
    ensure_backend_enabled(config, backend)?;
    let pcrs = chosen_pcrs(pcrs, || {
        gaze_security::keyring::record_pcrs(backend, username)
    })?;
    check_pcrs(pcrs, Path::new(PCR_SYSFS))?;
    config.storage.validate_keyring(&config.liveness)?;
    // The CLI owns this process, so it can safely change the core-dump limit. A PAM host may
    // have a different policy.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    anyhow::ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0,
        "cannot disable credential core dumps"
    );
    if let Some(warning) = gaze_security::storage::encryption_warning(
        gaze_security::storage::disk_encryption(std::path::Path::new(backend.store_dir())),
    ) {
        eprintln!("Warning: {warning}");
    }
    for warning in pcr_warnings(pcrs, Path::new(PCR_SYSFS), Path::new(SECURE_BOOT_EFIVAR)) {
        eprintln!("Warning: {warning}");
    }
    // Check the account before prompting. Enrollment checks again in case it changes meanwhile.
    gaze_security::keyring::Account::lookup(username)?;
    println!("Enter the {} password for {username}.", backend.name());
    let password = Zeroizing::new(
        dialoguer::Password::new()
            .with_prompt(format!("{} password", backend.name()))
            .with_confirmation("Confirm keyring password", "Passwords did not match")
            .interact()?,
    );
    gaze_security::keyring::enroll_for(backend, username, password.as_bytes(), pcrs)?;
    if pcrs.is_empty() {
        println!("{} unlock enrolled for {username}.", backend.name());
    } else {
        println!(
            "{} unlock enrolled for {username}, bound to PCRs {pcrs}.",
            backend.name()
        );
    }
    // The greeter's PAM worker runs confined as xdm_t. Distribution policy blocks it from
    // reading /etc/shadow and the TPM, so it cannot use the record we just wrote.
    if crate::selinux::is_enforcing() {
        let module = crate::selinux::GREETER_KEYRING_MODULE;
        match crate::selinux::load_module(module) {
            Ok(()) => println!("Loaded the {module} SELinux policy for the login screen."),
            Err(err) => eprintln!(
                "Warning: the {module} SELinux policy could not be loaded ({err}). Face login \
                 cannot unlock {} until you run `sudo semodule -i {}`.",
                backend.name(),
                crate::selinux::policy_path(module)
            ),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(unlock_gnome: bool, unlock_kwallet: bool) -> Config {
        let mut config = Config::default();
        config.storage.unlock_gnome_keyring = unlock_gnome;
        config.storage.unlock_kwallet = unlock_kwallet;
        config
    }

    #[test]
    fn disabled_backend_is_rejected_before_any_side_effect() {
        let config = config_with(false, false);
        for backend in [Backend::Gnome, Backend::KWallet] {
            let err = ensure_backend_enabled(&config, backend).expect_err("must refuse");
            assert!(
                err.to_string().contains(backend.name()),
                "error should name the backend: {err}"
            );
            assert!(
                err.to_string().contains("gaze config"),
                "error should say how to enable it: {err}"
            );
        }
    }

    // create_dir, not create_dir_all: a path someone planted makes the test fail, not follow it.
    fn fake_sysfs(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gaze-{name}-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("12"), "0".repeat(64) + "\n").unwrap();
        std::fs::write(dir.join("14"), "ab".repeat(32) + "\n").unwrap();
        std::fs::write(dir.join("17"), "F".repeat(64) + "\n").unwrap();
        std::fs::write(dir.join("secure-boot-on"), [6, 0, 0, 0, 1]).unwrap();
        std::fs::write(dir.join("secure-boot-off"), [6, 0, 0, 0, 0]).unwrap();
        dir
    }

    #[test]
    fn pcr_warnings_flag_volatile_resettable_and_unmeasured_pcrs() {
        let sysfs = fake_sysfs("pcr-warnings");
        let on = sysfs.join("secure-boot-on");
        let warn = |list: &str| pcr_warnings(list.parse().unwrap(), &sysfs, &on);

        assert!(warn("none").is_empty());
        assert!(
            warn("14").is_empty(),
            "a measured, stable PCR needs no warning"
        );
        assert!(warn("15").is_empty(), "an unreadable PCR is not guessed at");
        assert!(warn("12")[0].contains("reset value"), "all zeros");
        assert!(warn("17")[0].contains("reset value"), "all ones");
        for volatile in ["1", "4", "5", "11"] {
            assert!(warn(volatile)[0].contains("updates"), "PCR {volatile}");
        }
        assert!(warn("10")[0].contains("IMA"));
        assert!(warn("16")[0].contains("reset"));
        let seven = warn("7");
        assert_eq!(seven.len(), 1);
        assert!(seven[0].contains("dbx"));
        assert_eq!(warn("0,7,12,16").len(), 4);
        let _ = std::fs::remove_dir_all(&sysfs);
    }

    #[test]
    fn binding_without_secure_boot_warns_for_any_pcr() {
        let sysfs = fake_sysfs("secure-boot");
        for efivar in ["secure-boot-off", "missing"] {
            let warnings = pcr_warnings("14".parse().unwrap(), &sysfs, &sysfs.join(efivar));
            assert_eq!(warnings.len(), 1, "{efivar}: {warnings:?}");
            assert!(
                warnings[0].contains("Secure Boot is not enabled"),
                "{efivar}"
            );
        }
        assert!(
            pcr_warnings(Pcrs::NONE, &sysfs, &sysfs.join("missing")).is_empty(),
            "no binding, nothing to warn about"
        );
        let _ = std::fs::remove_dir_all(&sysfs);
    }

    #[test]
    fn a_binding_of_only_weak_pcrs_is_refused() {
        let sysfs = fake_sysfs("check-pcrs");
        let check = |list: &str| check_pcrs(list.parse().unwrap(), &sysfs);
        assert!(check("none").is_ok());
        assert!(check("7").is_ok(), "unreadable PCRs are not guessed at");
        assert!(check("14,16").is_ok(), "one measured PCR is enough");
        for weak in ["16", "23", "12", "17", "12,16,17"] {
            assert!(check(weak).is_err(), "{weak} must be refused");
        }
        let _ = std::fs::remove_dir_all(&sysfs);
    }

    #[test]
    fn enrolling_again_keeps_the_existing_binding_unless_told_otherwise() {
        let seven: Pcrs = "7".parse().unwrap();
        let existing = || Ok(Some(seven));
        assert_eq!(chosen_pcrs(None, existing).unwrap(), seven);
        assert_eq!(chosen_pcrs(Some(Pcrs::NONE), existing).unwrap(), Pcrs::NONE);
        assert_eq!(chosen_pcrs(None, || Ok(None)).unwrap(), Pcrs::NONE);
        let err = chosen_pcrs(None, || Err(anyhow::anyhow!("corrupt"))).unwrap_err();
        assert!(
            err.to_string().contains("pass --pcrs"),
            "an unreadable binding is never silently dropped: {err}"
        );
        assert_eq!(
            chosen_pcrs(Some(seven), || panic!("not read when --pcrs is given")).unwrap(),
            seven
        );
    }

    #[test]
    fn each_backend_is_gated_independently() {
        assert!(ensure_backend_enabled(&config_with(true, false), Backend::Gnome).is_ok());
        assert!(ensure_backend_enabled(&config_with(true, false), Backend::KWallet).is_err());
        assert!(ensure_backend_enabled(&config_with(false, true), Backend::KWallet).is_ok());
        assert!(ensure_backend_enabled(&config_with(false, true), Backend::Gnome).is_err());
    }
}
