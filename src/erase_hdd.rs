//! Effacement par écrasement (HDD) : DoD 5220.22-M, passes configurables, vérification,
//! écriture alignée, reprise sur erreur, comptage des erreurs, débit.
//!
//! Le moteur travaille sur un `BlockDevice` : disque brut Windows en production,
//! fichier ou mémoire dans les tests (aucun test ne touche un vrai disque).
//!
//! NIST 800-88 : un écrasement vaut « Clear », jamais « Purge ».

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub trait BlockDevice {
    fn size(&self) -> u64;
    fn sector_size(&self) -> u32;
    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()>;
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

// ---------- Motifs d'écriture ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fill {
    Byte(u8),
    Random,
}

impl Fill {
    /// "0x00", "0xFF", "00", "random"
    pub fn parse(s: &str) -> Result<Fill, String> {
        let t = s.trim();
        if t.eq_ignore_ascii_case("random") || t.eq_ignore_ascii_case("prng") {
            return Ok(Fill::Random);
        }
        let hex = t.trim_start_matches("0x").trim_start_matches("0X");
        u8::from_str_radix(hex, 16)
            .map(Fill::Byte)
            .map_err(|_| format!("passe invalide « {s} » (attendu : 0x00, 0xFF, random…)"))
    }

    pub fn label(&self) -> String {
        match self {
            Fill::Byte(b) => format!("0x{b:02X}"),
            Fill::Random => "random".to_string(),
        }
    }

    /// Libellé « passe finale » du rapport nwipe.
    pub fn final_label(&self) -> &'static str {
        match self {
            Fill::Byte(0) => "Zéros",
            Fill::Byte(0xFF) => "Uns",
            Fill::Byte(_) => "Octet fixe",
            Fill::Random => "Aléatoire",
        }
    }
}

const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

fn splitmix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Remplit `buf` (situé à l'offset disque `offset`, multiple de 8). Le flux aléatoire
/// SplitMix64 est indexé par la position : la vérification le régénère sans le stocker.
pub fn fill_buf(fill: Fill, seed: u64, offset: u64, buf: &mut [u8]) {
    match fill {
        Fill::Byte(b) => buf.fill(b),
        Fill::Random => {
            let base = offset / 8;
            for (i, c) in buf.chunks_mut(8).enumerate() {
                let v = splitmix(seed.wrapping_add((base + i as u64 + 1).wrapping_mul(GAMMA)));
                c.copy_from_slice(&v.to_le_bytes()[..c.len()]);
            }
        }
    }
}

/// Tampon aligné sur 4096 octets (exigé par FILE_FLAG_NO_BUFFERING).
pub struct AlignedBuf {
    raw: Vec<u8>,
    start: usize,
    len: usize,
}

impl AlignedBuf {
    pub fn new(len: usize) -> AlignedBuf {
        let raw = vec![0u8; len + 4096];
        let start = (4096 - raw.as_ptr() as usize % 4096) % 4096;
        AlignedBuf { raw, start, len }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.raw[self.start..self.start + self.len]
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.raw[self.start..self.start + self.len]
    }
}

// ---------- Plan, progression, résultat ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    None,
    Last,
    All,
}

impl VerifyMode {
    pub fn parse(s: &str) -> Result<VerifyMode, String> {
        match s.trim().to_lowercase().as_str() {
            "none" | "non" => Ok(VerifyMode::None),
            "last" | "derniere" | "dernière" => Ok(VerifyMode::Last),
            "all" | "toutes" => Ok(VerifyMode::All),
            _ => Err(format!("vérification invalide « {s} » (none | last | all)")),
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            VerifyMode::None => "None",
            VerifyMode::Last => "Last",
            VerifyMode::All => "All",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub passes: Vec<Fill>,
    pub verify: VerifyMode,
    pub chunk_bytes: usize,
    pub retries: u32,
    pub seed: u64,
}

impl Plan {
    /// DoD 5220.22-M par défaut : 0x00, 0xFF, aléatoire, puis vérification de la dernière passe.
    pub fn dod_default(seed: u64) -> Plan {
        Plan {
            passes: vec![Fill::Byte(0x00), Fill::Byte(0xFF), Fill::Random],
            verify: VerifyMode::Last,
            chunk_bytes: 1 << 20,
            retries: 3,
            seed,
        }
    }

    /// Une passe est-elle vérifiée ?
    pub fn verifies(&self, index: usize) -> bool {
        match self.verify {
            VerifyMode::None => false,
            VerifyMode::Last => index + 1 == self.passes.len(),
            VerifyMode::All => true,
        }
    }

    pub fn pass_seed(&self, index: usize) -> u64 {
        splitmix(self.seed.wrapping_add(index as u64 + 1))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCounts {
    pub pass: u64,
    pub sync: u64,
    pub verify: u64,
    pub retries: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Write,
    Verify,
}

#[derive(Debug, Clone)]
pub struct Progress {
    pub phase: Phase,
    pub pass_index: usize,
    pub pass_total: usize,
    pub done: u64,
    pub total: u64,
    pub speed_mb_s: f64,
    pub errors: ErrorCounts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    NotRequested,
    Passed,
    Failed,
    /// Demandée mais interrompue.
    Incomplete,
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub size: u64,
    /// Octets écrits avec succès au moins une fois (meilleure couverture d'une passe).
    pub bytes_erased: u64,
    pub passes_completed: usize,
    pub verify: VerifyResult,
    pub errors: ErrorCounts,
    pub aborted: bool,
    pub abort_reason: Option<String>,
    /// (avancement global %, débit MB/s)
    pub speed_samples: Vec<(f32, f32)>,
    pub avg_mb_s: f64,
    pub min_mb_s: f64,
    pub max_mb_s: f64,
    pub elapsed: Duration,
}

// ---------- Moteur ----------

pub(crate) const MAX_CONSECUTIVE_BAD_SECTORS: u64 = 2048;
const SAMPLE_WINDOW: Duration = Duration::from_millis(500);

pub(crate) struct Job<'a> {
    pub dev: &'a mut dyn BlockDevice,
    pub size: u64,
    pub ss: u64,
    pub chunk: usize,
    pub retries: u32,
    pub errors: ErrorCounts,
    pub cancel: &'a AtomicBool,
    pub cb: &'a mut dyn FnMut(&Progress),
    pub pass_total: usize,
    pub bad_run: u64,
    pub abort_reason: Option<String>,
    // mesure
    start: Instant,
    win_start: Instant,
    win_bytes: u64,
    last_speed: f64,
    total_work: u64,
    done_work: u64,
    samples: Vec<(f32, f32)>,
    moved_total: u64,
}

impl<'a> Job<'a> {
    pub(crate) fn stopped(&self) -> bool {
        self.abort_reason.is_some() || self.cancel.load(Ordering::Relaxed)
    }

    /// Compte `n` octets traités et notifie l'appelant.
    pub(crate) fn advance(
        &mut self,
        phase: Phase,
        pass_index: usize,
        done: u64,
        total: u64,
        n: u64,
    ) {
        self.done_work += n;
        self.win_bytes += n;
        self.moved_total += n;
        let el = self.win_start.elapsed();
        if el >= SAMPLE_WINDOW {
            self.last_speed = self.win_bytes as f64 / el.as_secs_f64() / 1e6;
            let pct = (self.done_work as f64 / self.total_work.max(1) as f64 * 100.0) as f32;
            self.samples.push((pct, self.last_speed as f32));
            self.win_start = Instant::now();
            self.win_bytes = 0;
        }
        (self.cb)(&Progress {
            phase,
            pass_index,
            pass_total: self.pass_total,
            done,
            total,
            speed_mb_s: self.last_speed,
            errors: self.errors,
        });
    }

    fn write_retry(&mut self, off: u64, data: &[u8]) -> bool {
        for attempt in 0..=self.retries {
            if self.dev.write_at(off, data).is_ok() {
                return true;
            }
            if attempt < self.retries {
                self.errors.retries += 1;
            }
        }
        false
    }

    pub(crate) fn read_retry(&mut self, off: u64, data: &mut [u8]) -> bool {
        for attempt in 0..=self.retries {
            if self.dev.read_at(off, data).is_ok() {
                return true;
            }
            if attempt < self.retries {
                self.errors.retries += 1;
            }
        }
        false
    }

    /// Une passe d'écriture. Renvoie les octets écrits avec succès.
    fn write_pass(&mut self, plan: &Plan, index: usize, buf: &mut AlignedBuf) -> u64 {
        let fill = plan.passes[index];
        let seed = plan.pass_seed(index);
        let (size, ss) = (self.size, self.ss);
        let mut ok_bytes = 0u64;
        let mut off = 0u64;
        while off < size {
            if self.stopped() {
                return ok_bytes;
            }
            let n = (self.chunk as u64).min(size - off) as usize;
            fill_buf(fill, seed, off, &mut buf.as_mut_slice()[..n]);
            if self.write_retry(off, &buf.as_slice()[..n]) {
                ok_bytes += n as u64;
                self.bad_run = 0;
            } else {
                // Reprise : secteur par secteur, les secteurs défectueux sont comptés puis ignorés.
                // Sous-tranche du tampon aligné (jamais de copie non alignée : NO_BUFFERING).
                let data = buf.as_slice();
                for s in 0..(n as u64 / ss) {
                    let o = s * ss;
                    if self.write_retry(off + o, &data[o as usize..(o + ss) as usize]) {
                        ok_bytes += ss;
                        self.bad_run = 0;
                    } else {
                        self.errors.pass += 1;
                        self.bad_run += 1;
                        if self.bad_run > MAX_CONSECUTIVE_BAD_SECTORS {
                            self.abort_reason =
                                Some("Trop de secteurs illisibles d'affilée : disque inaccessible ou débranché".into());
                            return ok_bytes;
                        }
                    }
                }
            }
            off += n as u64;
            self.advance(Phase::Write, index, off, size, n as u64);
        }
        if self.dev.flush().is_err() {
            self.errors.sync += 1;
        }
        ok_bytes
    }
}

/// Lance l'effacement complet. `cancel` permet d'arrêter proprement (le résultat reste fidèle).
pub fn erase(
    dev: &mut dyn BlockDevice,
    plan: &Plan,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&Progress),
) -> Outcome {
    let size = dev.size();
    let ss = (dev.sector_size() as u64).max(1);
    let chunk = ((plan.chunk_bytes as u64 / ss).max(1) * ss) as usize;
    let verify_count = (0..plan.passes.len()).filter(|&i| plan.verifies(i)).count() as u64;
    let now = Instant::now();
    let mut job = Job {
        dev,
        size,
        ss,
        chunk,
        retries: plan.retries,
        errors: ErrorCounts::default(),
        cancel,
        cb: progress,
        pass_total: plan.passes.len(),
        bad_run: 0,
        abort_reason: None,
        start: now,
        win_start: now,
        win_bytes: 0,
        last_speed: 0.0,
        total_work: (plan.passes.len() as u64 + verify_count) * size,
        done_work: 0,
        samples: Vec::new(),
        moved_total: 0,
    };

    let mut wbuf = AlignedBuf::new(chunk);
    let mut rbuf = AlignedBuf::new(chunk);
    // Couverture de chaque passe commencée.
    let mut covers: Vec<u64> = Vec::with_capacity(plan.passes.len());
    let mut completed = 0usize;
    let mut verify = if verify_count == 0 {
        VerifyResult::NotRequested
    } else {
        VerifyResult::Passed
    };

    for index in 0..plan.passes.len() {
        let ok = job.write_pass(plan, index, &mut wbuf);
        covers.push(ok);
        if job.stopped() {
            if verify_count > 0 {
                verify = VerifyResult::Incomplete;
            }
            break;
        }
        completed += 1;
        if plan.verifies(index) {
            let before = job.errors.verify;
            let finished = job.verify_pass(plan, index, &mut rbuf);
            if !finished {
                verify = VerifyResult::Incomplete;
                break;
            }
            if job.errors.verify > before && verify != VerifyResult::Incomplete {
                verify = VerifyResult::Failed;
            }
        }
    }
    if completed < plan.passes.len() && verify_count > 0 && verify == VerifyResult::Passed {
        verify = VerifyResult::Incomplete;
    }

    // Octets effacés : couverture de la passe FINALE si toutes les passes sont terminées,
    // sinon la plus faible des passes commencées (jamais la meilleure).
    let bytes_erased = if completed == plan.passes.len() {
        covers.last().copied().unwrap_or(0)
    } else {
        covers.iter().copied().min().unwrap_or(0)
    };

    // Dernière fenêtre de mesure partielle (petits disques/fichiers) : gardée si elle contient des octets.
    if job.win_bytes > 0 {
        let el = job.win_start.elapsed().as_secs_f64().max(1e-6);
        let pct = (job.done_work as f64 / job.total_work.max(1) as f64 * 100.0) as f32;
        job.samples
            .push((pct, (job.win_bytes as f64 / el / 1e6) as f32));
    }

    let elapsed = job.start.elapsed();
    let secs = elapsed.as_secs_f64().max(1e-6);
    let avg = job.moved_total as f64 / secs / 1e6;
    let mut samples: Vec<(f32, f32)> = std::mem::take(&mut job.samples)
        .into_iter()
        .filter(|s| s.0.is_finite() && s.1.is_finite())
        .collect();
    if samples.is_empty() {
        samples.push((100.0, avg as f32));
    }
    let min = samples.iter().map(|s| s.1 as f64).fold(f64::MAX, f64::min);
    let max = samples.iter().map(|s| s.1 as f64).fold(0.0, f64::max);
    Outcome {
        size,
        bytes_erased,
        passes_completed: completed,
        verify,
        errors: job.errors,
        aborted: job.stopped(),
        abort_reason: job.abort_reason.clone(),
        speed_samples: samples,
        avg_mb_s: avg,
        min_mb_s: min,
        max_mb_s: max,
        elapsed,
    }
}

// ---------- Périphériques ----------

/// Fichier utilisé comme disque de test (--erase-file) et dans les tests unitaires.
pub struct FileDevice {
    file: std::fs::File,
    size: u64,
}

impl FileDevice {
    pub fn open(path: &std::path::Path) -> io::Result<FileDevice> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let size = file.metadata()?.len();
        if size < 512 {
            return Err(io::Error::other(
                "fichier vide ou plus petit qu'un secteur (512 octets)",
            ));
        }
        Ok(FileDevice { file, size })
    }
}

impl BlockDevice for FileDevice {
    fn size(&self) -> u64 {
        self.size / 512 * 512
    }
    fn sector_size(&self) -> u32 {
        512
    }
    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        self.file.seek(SeekFrom::Start(off))?;
        self.file.write_all(buf)
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        self.file.seek(SeekFrom::Start(off))?;
        self.file.read_exact(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Disque en mémoire avec défauts simulables.
    pub struct MemDisk {
        pub data: Vec<u8>,
        pub bad_write: HashSet<u64>,
        pub silent_corrupt: HashSet<u64>,
        pub bad_read: HashSet<u64>,
        pub fail_all_after: Option<u64>,
        pub writes: u64,
    }

    impl MemDisk {
        pub fn new(size: usize) -> MemDisk {
            MemDisk {
                data: (0..size).map(|i| (i % 251) as u8 ^ 0xA5).collect(),
                bad_write: HashSet::new(),
                silent_corrupt: HashSet::new(),
                bad_read: HashSet::new(),
                fail_all_after: None,
                writes: 0,
            }
        }
        fn touches(set: &HashSet<u64>, off: u64, len: usize) -> bool {
            set.iter()
                .any(|&s| s >= off / 512 && s < (off + len as u64).div_ceil(512))
        }
        /// Comme un disque ouvert en NO_BUFFERING : tampon et longueur alignés sur 512 exigés.
        fn check_aligned(ptr: *const u8, len: usize) -> io::Result<()> {
            if !(ptr as usize).is_multiple_of(512) || !len.is_multiple_of(512) {
                return Err(io::Error::other("tampon non aligné (NO_BUFFERING)"));
            }
            Ok(())
        }
    }

    impl BlockDevice for MemDisk {
        fn size(&self) -> u64 {
            self.data.len() as u64
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
            MemDisk::check_aligned(buf.as_ptr(), buf.len())?;
            self.writes += 1;
            if self.fail_all_after.is_some_and(|n| self.writes > n)
                || MemDisk::touches(&self.bad_write, off, buf.len())
            {
                return Err(io::Error::other("write error"));
            }
            self.data[off as usize..off as usize + buf.len()].copy_from_slice(buf);
            for &s in &self.silent_corrupt {
                let p = (s * 512) as usize;
                if p >= off as usize && p < off as usize + buf.len() {
                    self.data[p] ^= 0xFF;
                }
            }
            Ok(())
        }
        fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
            MemDisk::check_aligned(buf.as_ptr(), buf.len())?;
            if MemDisk::touches(&self.bad_read, off, buf.len()) {
                return Err(io::Error::other("read error"));
            }
            buf.copy_from_slice(&self.data[off as usize..off as usize + buf.len()]);
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub fn run(dev: &mut MemDisk, plan: &Plan) -> Outcome {
        erase(dev, plan, &AtomicBool::new(false), &mut |_| {})
    }

    fn small_plan(passes: Vec<Fill>, verify: VerifyMode) -> Plan {
        Plan {
            passes,
            verify,
            chunk_bytes: 4096,
            retries: 2,
            seed: 42,
        }
    }

    #[test]
    fn parses_fill_and_verify() {
        assert_eq!(Fill::parse("0x00").unwrap(), Fill::Byte(0));
        assert_eq!(Fill::parse("0xFF").unwrap(), Fill::Byte(255));
        assert_eq!(Fill::parse("random").unwrap(), Fill::Random);
        assert!(Fill::parse("zzz").is_err());
        assert_eq!(VerifyMode::parse("LAST").unwrap(), VerifyMode::Last);
        assert!(VerifyMode::parse("x").is_err());
        assert_eq!(Fill::Byte(0).final_label(), "Zéros");
    }

    #[test]
    fn random_stream_is_reproducible_and_position_indexed() {
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        fill_buf(Fill::Random, 7, 4096, &mut a);
        fill_buf(Fill::Random, 7, 4096, &mut b);
        assert_eq!(a, b);
        // Remplir en deux morceaux donne le même flux qu'en un seul.
        let mut whole = [0u8; 64];
        fill_buf(Fill::Random, 7, 4096, &mut whole);
        let mut half = [0u8; 32];
        fill_buf(Fill::Random, 7, 4096 + 32, &mut half);
        assert_eq!(&whole[32..], &half);
        let mut other = [0u8; 64];
        fill_buf(Fill::Random, 8, 4096, &mut other);
        assert_ne!(a, other);
    }

    #[test]
    fn aligned_buffer_is_aligned() {
        let b = AlignedBuf::new(8192);
        assert_eq!(b.as_slice().as_ptr() as usize % 4096, 0);
        assert_eq!(b.as_slice().len(), 8192);
    }

    #[test]
    fn dod_leaves_final_random_pass_and_verifies() {
        let mut d = MemDisk::new(64 * 1024);
        let plan = small_plan(
            vec![Fill::Byte(0), Fill::Byte(0xFF), Fill::Random],
            VerifyMode::Last,
        );
        let o = run(&mut d, &plan);
        assert_eq!(o.bytes_erased, 64 * 1024);
        assert_eq!(o.passes_completed, 3);
        assert_eq!(o.verify, VerifyResult::Passed);
        assert_eq!(o.errors, ErrorCounts::default());
        assert!(!o.aborted);
        let mut expect = vec![0u8; 64 * 1024];
        fill_buf(Fill::Random, plan.pass_seed(2), 0, &mut expect);
        assert_eq!(d.data, expect);
    }

    #[test]
    fn zero_pass_zeroes_everything() {
        let mut d = MemDisk::new(32 * 1024);
        let o = run(&mut d, &small_plan(vec![Fill::Byte(0)], VerifyMode::Last));
        assert!(d.data.iter().all(|&b| b == 0));
        assert_eq!(o.verify, VerifyResult::Passed);
    }

    #[test]
    fn no_verify_is_reported_as_not_requested() {
        let mut d = MemDisk::new(8192);
        let o = run(&mut d, &small_plan(vec![Fill::Byte(0)], VerifyMode::None));
        assert_eq!(o.verify, VerifyResult::NotRequested);
    }

    #[test]
    fn verification_detects_silent_corruption() {
        let mut d = MemDisk::new(64 * 1024);
        d.silent_corrupt.insert(10);
        let o = run(&mut d, &small_plan(vec![Fill::Byte(0)], VerifyMode::Last));
        assert_eq!(o.verify, VerifyResult::Failed);
        assert_eq!(o.errors.verify, 1);
        assert_eq!(o.errors.pass, 0);
    }

    #[test]
    fn bad_sector_is_counted_skipped_and_run_continues() {
        let mut d = MemDisk::new(64 * 1024);
        d.bad_write.insert(20);
        let o = run(&mut d, &small_plan(vec![Fill::Byte(0)], VerifyMode::None));
        assert_eq!(o.errors.pass, 1);
        assert!(o.errors.retries > 0);
        assert_eq!(o.bytes_erased, 64 * 1024 - 512);
        assert!(!o.aborted);
        // Le reste du disque est bien effacé.
        assert!(d.data[..20 * 512].iter().all(|&b| b == 0));
        assert!(d.data[21 * 512..].iter().all(|&b| b == 0));
    }

    #[test]
    fn memdisk_rejects_unaligned_buffers() {
        let mut d = MemDisk::new(4096);
        let v = vec![0u8; 1024 + 1];
        // Décalage de 1 octet : forcément non aligné, quelle que soit l'adresse du Vec.
        let p = v.as_ptr() as usize;
        let start = if p.is_multiple_of(512) { 1 } else { 0 };
        assert!(d.write_at(0, &v[start..start + 512]).is_err());
        let b = AlignedBuf::new(512);
        assert!(d.write_at(0, b.as_slice()).is_ok());
        assert!(d.write_at(0, &b.as_slice()[..100]).is_err());
    }

    #[test]
    fn sector_retry_writes_from_aligned_buffer() {
        // Un secteur défectueux force la reprise secteur par secteur. Avec une copie `to_vec()`
        // (non alignée), MemDisk refuserait TOUS les secteurs du bloc et la couverture chuterait.
        let mut d = MemDisk::new(64 * 1024);
        d.bad_write.insert(9);
        let o = run(&mut d, &small_plan(vec![Fill::Byte(0)], VerifyMode::None));
        assert_eq!(o.errors.pass, 1);
        assert_eq!(o.bytes_erased, 64 * 1024 - 512);
        assert!(
            d.data[8 * 512..9 * 512].iter().all(|&b| b == 0),
            "voisins du secteur défectueux effacés"
        );
    }

    #[test]
    fn verify_reads_sector_by_sector_into_aligned_buffer() {
        // Lecture groupée impossible (un secteur illisible) : relecture secteur par secteur alignée.
        let mut d = MemDisk::new(32 * 1024);
        d.bad_read.insert(5);
        let o = run(&mut d, &small_plan(vec![Fill::Byte(0)], VerifyMode::Last));
        assert_eq!(o.errors.verify, 1, "seul le secteur 5 est en erreur");
    }

    #[test]
    fn verify_aborts_after_too_many_unreadable_sectors() {
        let sectors = MAX_CONSECUTIVE_BAD_SECTORS as usize + 200;
        let mut d = MemDisk::new(sectors * 512);
        d.bad_read = (0..sectors as u64).collect();
        let plan = Plan {
            retries: 0,
            ..small_plan(vec![Fill::Byte(0)], VerifyMode::Last)
        };
        let o = run(&mut d, &plan);
        assert!(o.aborted);
        assert!(o
            .abort_reason
            .as_deref()
            .unwrap_or("")
            .contains("vérification"));
        assert_eq!(o.verify, VerifyResult::Incomplete);
        assert!(o.errors.verify > MAX_CONSECUTIVE_BAD_SECTORS);
    }

    #[test]
    fn bytes_erased_is_final_pass_coverage_not_best() {
        // Passe 1 propre, passe 2 avec un secteur défectueux : la passe finale fait foi.
        let mut d = MemDisk::new(64 * 1024);
        let plan = small_plan(vec![Fill::Byte(0), Fill::Byte(0xFF)], VerifyMode::None);
        // Le secteur 3 devient défectueux après la première passe (16 blocs de 4 Kio par passe).
        let mut writes = 0u64;
        let mut dev = BadAfter {
            inner: &mut d,
            after: 16,
            sector: 3,
            writes: &mut writes,
        };
        let o = erase(&mut dev, &plan, &AtomicBool::new(false), &mut |_| {});
        assert_eq!(o.passes_completed, 2);
        assert_eq!(o.bytes_erased, 64 * 1024 - 512);
    }

    #[test]
    fn bytes_erased_is_min_of_started_passes_when_interrupted() {
        let mut d = MemDisk::new(64 * 1024);
        let cancel = AtomicBool::new(false);
        let mut calls = 0;
        let o = erase(
            &mut d,
            &small_plan(vec![Fill::Byte(0), Fill::Byte(1)], VerifyMode::None),
            &cancel,
            &mut |_| {
                calls += 1;
                if calls == 20 {
                    cancel.store(true, Ordering::Relaxed); // pendant la 2e passe
                }
            },
        );
        assert!(o.aborted);
        assert!(o.bytes_erased < 64 * 1024, "{}", o.bytes_erased);
    }

    #[test]
    fn small_device_still_gets_a_speed_sample() {
        let mut d = MemDisk::new(16 * 1024);
        let o = run(&mut d, &small_plan(vec![Fill::Byte(0)], VerifyMode::None));
        assert!(!o.speed_samples.is_empty());
        assert!(o
            .speed_samples
            .iter()
            .all(|s| s.0.is_finite() && s.1.is_finite()));
        assert!(o.max_mb_s > 0.0);
    }

    #[test]
    fn file_device_refuses_empty_file() {
        let path = std::env::temp_dir().join(format!("diskerase-empty-{}.img", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        assert!(FileDevice::open(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    /// Enveloppe : rend un secteur défectueux en écriture après `after` écritures.
    struct BadAfter<'a> {
        inner: &'a mut MemDisk,
        after: u64,
        sector: u64,
        writes: &'a mut u64,
    }

    impl BlockDevice for BadAfter<'_> {
        fn size(&self) -> u64 {
            self.inner.size()
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
            *self.writes += 1;
            if *self.writes > self.after {
                self.inner.bad_write.insert(self.sector);
            }
            self.inner.write_at(off, buf)
        }
        fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
            self.inner.read_at(off, buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn unreadable_sector_counts_as_verify_error() {
        let mut d = MemDisk::new(32 * 1024);
        d.bad_read.insert(3);
        let o = run(&mut d, &small_plan(vec![Fill::Byte(0)], VerifyMode::Last));
        assert_eq!(o.verify, VerifyResult::Failed);
        assert_eq!(o.errors.verify, 1);
    }

    #[test]
    fn dead_disk_aborts_instead_of_looping() {
        let mut d = MemDisk::new(4 * 1024 * 1024);
        d.fail_all_after = Some(0);
        let o = run(
            &mut d,
            &Plan {
                chunk_bytes: 1 << 20,
                ..small_plan(vec![Fill::Byte(0)], VerifyMode::None)
            },
        );
        assert!(o.aborted);
        assert!(o.abort_reason.is_some());
        assert!(o.bytes_erased < o.size);
    }

    #[test]
    fn cancel_stops_cleanly_and_is_reported() {
        let mut d = MemDisk::new(64 * 1024);
        let cancel = AtomicBool::new(false);
        let mut calls = 0;
        let o = erase(
            &mut d,
            &small_plan(vec![Fill::Byte(0), Fill::Byte(1)], VerifyMode::Last),
            &cancel,
            &mut |_| {
                calls += 1;
                if calls == 3 {
                    cancel.store(true, Ordering::Relaxed);
                }
            },
        );
        assert!(o.aborted);
        assert!(o.passes_completed < 2);
        assert_eq!(o.verify, VerifyResult::Incomplete);
    }

    #[test]
    fn progress_reaches_total_each_pass() {
        let mut d = MemDisk::new(16 * 1024);
        let mut last = Vec::new();
        erase(
            &mut d,
            &small_plan(vec![Fill::Byte(0)], VerifyMode::None),
            &AtomicBool::new(false),
            &mut |p| last.push((p.done, p.total)),
        );
        assert_eq!(last.last(), Some(&(16 * 1024, 16 * 1024)));
    }

    #[test]
    fn file_device_roundtrip() {
        let path = std::env::temp_dir().join(format!("diskerase-fd-{}.img", std::process::id()));
        std::fs::write(&path, vec![0xAAu8; 64 * 1024]).unwrap();
        let mut dev = FileDevice::open(&path).unwrap();
        let o = erase(
            &mut dev,
            &small_plan(vec![Fill::Byte(0)], VerifyMode::Last),
            &AtomicBool::new(false),
            &mut |_| {},
        );
        assert_eq!(o.verify, VerifyResult::Passed);
        assert!(std::fs::read(&path).unwrap().iter().all(|&b| b == 0));
        let _ = std::fs::remove_file(&path);
    }
}
