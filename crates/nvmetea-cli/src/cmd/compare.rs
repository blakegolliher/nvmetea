//! `nvmetea compare BASELINE CURRENT`: compare two captures (LAD per stage).

use crate::Ctx;
use crate::fmt::{emit, emit_json};
use anyhow::Context;
use nvmetea_export::capture;
use nvmetea_export::compare::{Options, compare, render_text};
use std::path::Path;

pub fn run(ctx: &Ctx, baseline: &Path, current: &Path, min_samples: u64) -> anyhow::Result<()> {
    let b = capture::read(baseline).with_context(|| format!("reading {}", baseline.display()))?;
    let c = capture::read(current).with_context(|| format!("reading {}", current.display()))?;
    let r = compare(&b, &c, &Options { min_samples });
    if ctx.json {
        return emit_json(&r);
    }
    emit(&render_text(&r));
    Ok(())
}
