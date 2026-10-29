// SPDX-FileCopyrightText: 2026 Gundu Labs
// SPDX-License-Identifier: GPL-3.0-or-later

use gaze_core::config::Config;
use gaze_security::keyring::{Backend, Pcrs, Zeroizing};
use std::path::Path;

const PCR_SYSFS: &str = "/sys/class/tpm/tpm0/pcr-sha256";

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

/// Advice for PCRs that bind poorly. `sysfs` holds one hex file per PCR; unreadable PCRs are skipped.
fn pcr_warnings(pcrs: Pcrs, sysfs: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    for pcr in pcrs.iter() {
        match pcr {
            16 | 23 => warnings.push(format!(
                "PCR {pcr} can be reset or extended by any program at runtime, so it says nothing \
                 about how this machine booted"
            )),
            0 | 2 | 4 | 8 | 9 | 10 => warnings.push(format!(
                "PCR {pcr} changes on routine firmware, boot loader, or kernel updates; expect to \
                 run `gaze keyring` again after them"
            )),
            _ => {
                let value =
                    std::fs::read_to_string(sysfs.join(pcr.to_string())).unwrap_or_default();
                let value = value.trim();
                if !value.is_empty() && value.bytes().all(|b| b == b'0') {
                    warnings.push(format!(
                        "PCR {pcr} is all zeros: nothing measured it this boot, so binding to it \
                         adds no protection"
                    ));
                }
            }
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

pub fn enroll(username: &str, config: &Config, backend: Backend, pcrs: Pcrs) -> anyhow::Result<()> {
    ensure_backend_enabled(config, backend)?;
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
    for warning in pcr_warnings(pcrs, Path::new(PCR_SYSFS)) {
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

    #[test]
    fn pcr_warnings_flag_volatile_resettable_and_unmeasured_pcrs() {
        let sysfs = std::env::temp_dir().join(format!("gaze-pcr-sysfs-{}", std::process::id()));
        std::fs::create_dir_all(&sysfs).unwrap();
        std::fs::write(sysfs.join("11"), "0".repeat(64) + "\n").unwrap();
        std::fs::write(sysfs.join("14"), "ab".repeat(32) + "\n").unwrap();
        let warn = |list: &str| pcr_warnings(list.parse().unwrap(), &sysfs);

        assert!(warn("none").is_empty());
        assert!(
            warn("14").is_empty(),
            "a measured, stable PCR needs no warning"
        );
        assert!(warn("15").is_empty(), "an unreadable PCR is not guessed at");
        assert!(warn("11")[0].contains("all zeros"));
        assert!(warn("4")[0].contains("updates"));
        assert!(warn("16")[0].contains("reset"));
        let seven = warn("7");
        assert_eq!(seven.len(), 1);
        assert!(seven[0].contains("dbx"));
        assert_eq!(warn("0,7,11,16").len(), 4);
        let _ = std::fs::remove_dir_all(&sysfs);
    }

    #[test]
    fn each_backend_is_gated_independently() {
        assert!(ensure_backend_enabled(&config_with(true, false), Backend::Gnome).is_ok());
        assert!(ensure_backend_enabled(&config_with(true, false), Backend::KWallet).is_err());
        assert!(ensure_backend_enabled(&config_with(false, true), Backend::KWallet).is_ok());
        assert!(ensure_backend_enabled(&config_with(false, true), Backend::Gnome).is_err());
    }
}
