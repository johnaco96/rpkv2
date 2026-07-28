#[derive(Clone, Copy, Debug, Default, clap::Args)]
pub struct VersionArgs {
    #[arg(
        long = "version",
        short = 'V',
        action = clap::ArgAction::SetTrue,
        help = "Print build and release metadata, then exit"
    )]
    pub version: bool,
}

impl VersionArgs {
    pub fn print_and_exit_if_requested(self) -> bool {
        if self.version {
            print();
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Debug)]
pub struct BuildInfo {
    pub crate_version: &'static str,
    pub git_commit: &'static str,
    pub build_features: String,
    pub build_profile: &'static str,
}

impl BuildInfo {
    pub fn current() -> Self {
        Self {
            crate_version: env!("CARGO_PKG_VERSION"),
            git_commit: env!("RPKV2_GIT_COMMIT"),
            build_features: build_features().join(","),
            build_profile: build_profile(),
        }
    }

    pub fn render(&self) -> String {
        format!(
            concat!(
                "rpkv2 {}\n",
                "git_commit: {}\n",
                "build_features: {}\n",
                "build_profile: {}"
            ),
            self.crate_version, self.git_commit, self.build_features, self.build_profile
        )
    }
}

pub fn render() -> String {
    BuildInfo::current().render()
}

pub fn print() {
    println!("{}", render());
}

pub fn env_requested() -> bool {
    std::env::args().any(|arg| arg == "--version" || arg == "-V")
}

pub fn print_if_requested_from_env() -> bool {
    if env_requested() {
        print();
        true
    } else {
        false
    }
}

#[cfg(feature = "ed25519")]
const FEATURE_ED25519: Option<&str> = Some("ed25519");
#[cfg(not(feature = "ed25519"))]
const FEATURE_ED25519: Option<&str> = None;

#[cfg(feature = "insecure_demo")]
const FEATURE_INSECURE_DEMO: Option<&str> = Some("insecure_demo");
#[cfg(not(feature = "insecure_demo"))]
const FEATURE_INSECURE_DEMO: Option<&str> = None;

#[cfg(feature = "dalek_batch")]
const FEATURE_DALEK_BATCH: Option<&str> = Some("dalek_batch");
#[cfg(not(feature = "dalek_batch"))]
const FEATURE_DALEK_BATCH: Option<&str> = None;

fn build_features() -> Vec<&'static str> {
    [FEATURE_ED25519, FEATURE_INSECURE_DEMO, FEATURE_DALEK_BATCH]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
}

fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_output_contains_required_release_metadata() {
        let text = render();

        assert!(text.contains("rpkv2 "));
        assert!(text.contains("git_commit: "));
        assert!(text.contains("build_features: "));
        assert!(text.contains("build_profile: "));
    }
}
