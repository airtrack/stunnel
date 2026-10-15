use shadow_rs::shadow;

pub mod config;
pub mod metrics;
pub mod proxy;
pub mod quic;
pub mod telemetry;
pub mod tlstcp;
pub mod tunnel;

shadow!(build);

/// The version line a binary prints and reports as `service.version`.
pub fn version(program: &str) -> String {
    let hash = build::SHORT_COMMIT;
    let dirty = if build::GIT_CLEAN { "" } else { "*" };
    let build_time = build::BUILD_TIME
        .rsplit_once(' ')
        .map(|(time, _)| time)
        .unwrap_or(build::BUILD_TIME);

    format!(
        "{program} {} ({hash}{dirty} {build_time})",
        build::PKG_VERSION
    )
}

pub fn print_version(program: &str) {
    println!("{}", version(program));
}
