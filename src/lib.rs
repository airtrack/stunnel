use shadow_rs::shadow;

pub mod quic;
pub mod tlstcp;
pub mod tunnel;

shadow!(build);

pub fn print_version(program: &str) {
    let hash = build::SHORT_COMMIT;
    let dirty = if build::GIT_CLEAN { "" } else { "*" };
    let build_time = build::BUILD_TIME
        .rsplit_once(' ')
        .map(|(time, _)| time)
        .unwrap_or(build::BUILD_TIME);

    println!(
        "{program} {} ({hash}{dirty} {build_time})",
        build::PKG_VERSION
    );
}
