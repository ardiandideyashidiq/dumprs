use indicatif::MultiProgress;
use std::sync::OnceLock;

static MULTI_PROGRESS: OnceLock<MultiProgress> = OnceLock::new();

pub fn get_multi_progress() -> &'static MultiProgress {
    MULTI_PROGRESS.get_or_init(MultiProgress::new)
}
