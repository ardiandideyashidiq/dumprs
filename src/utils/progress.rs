use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing_indicatif::IndicatifWriter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

static MULTI_PROGRESS: LazyLock<MultiProgress> =
    LazyLock::new(|| MultiProgress::with_draw_target(ProgressDrawTarget::stderr_with_hz(12)));

static BYTE_STYLE: LazyLock<ProgressStyle> = LazyLock::new(|| {
    ProgressStyle::with_template(
        "  {spinner:.cyan} {prefix:<18.bold} [{bar:28.cyan/dim}] {bytes:>10}/{total_bytes:<10} {bytes_per_sec:>12.green} ({eta}) {msg}",
    )
    .expect("valid byte progress template")
    .progress_chars("━━╾─")
});

const BATCH_FLUSH_BYTES: u64 = 1024 * 1024;
const MIN_PROGRESS_BYTES: u64 = 4 * 1024 * 1024;

pub fn get_multi_progress() -> &'static MultiProgress {
    &MULTI_PROGRESS
}

pub fn init_logging() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("dumprs=info,warn"));

    let writer =
        IndicatifWriter::<tracing_indicatif::writer::Stderr>::new(get_multi_progress().clone());

    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_writer(writer)
                .with_target(false)
                .without_time(),
        )
        .with(filter)
        .try_init();
}

pub struct ByteProgress {
    pb: Option<ProgressBar>,
    pending: AtomicU64,
}

impl ByteProgress {
    pub fn new(prefix: impl Into<String>, total_bytes: u64) -> Self {
        let mp = get_multi_progress();
        if total_bytes < MIN_PROGRESS_BYTES || mp.is_hidden() {
            return Self {
                pb: None,
                pending: AtomicU64::new(0),
            };
        }

        let pb = mp.add(ProgressBar::new(total_bytes));
        pb.set_style(BYTE_STYLE.clone());
        pb.set_prefix(prefix.into());
        Self {
            pb: Some(pb),
            pending: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn inc(&self, bytes: u64) {
        let Some(pb) = &self.pb else {
            return;
        };
        let prev = self.pending.fetch_add(bytes, Ordering::Relaxed);
        if prev + bytes >= BATCH_FLUSH_BYTES {
            let delta = self.pending.swap(0, Ordering::Relaxed);
            if delta > 0 {
                pb.inc(delta);
            }
        }
    }

    #[inline]
    pub fn set_message(&self, msg: impl Into<std::borrow::Cow<'static, str>>) {
        if let Some(pb) = &self.pb {
            pb.set_message(msg);
        }
    }

    pub fn finish(self) {
        if let Some(pb) = self.pb {
            let rem = self.pending.load(Ordering::Relaxed);
            if rem > 0 {
                pb.inc(rem);
            }
            pb.finish_and_clear();
        }
    }
}
