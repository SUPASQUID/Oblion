//! Vérification après effacement : relecture complète d'une passe et comparaison
//! avec le motif attendu (régénéré, jamais stocké). L'échantillonnage SSD arrive à l'étape 3.
//!
//! Toutes les lectures se font dans le tampon aligné unique `rbuf` (exigence NO_BUFFERING).

use crate::erase_hdd::{fill_buf, AlignedBuf, Job, Phase, Plan, MAX_CONSECUTIVE_BAD_SECTORS};

impl<'a> Job<'a> {
    /// Relit tout le disque et compare à la passe `index`. Renvoie false si interrompue.
    /// Chaque secteur différent ou illisible ajoute une erreur de vérification ; trop de
    /// secteurs illisibles d'affilée arrêtent l'effacement (disque débranché ou mort).
    pub(crate) fn verify_pass(&mut self, plan: &Plan, index: usize, rbuf: &mut AlignedBuf) -> bool {
        let fill = plan.passes[index];
        let seed = plan.pass_seed(index);
        let (size, ss) = (self.size, self.ss as usize);
        let mut expected = vec![0u8; self.chunk];
        let mut unreadable_run = 0u64;
        let mut off = 0u64;
        while off < size {
            if self.stopped() {
                return false;
            }
            let n = (self.chunk as u64).min(size - off) as usize;
            fill_buf(fill, seed, off, &mut expected[..n]);
            if self.read_retry(off, &mut rbuf.as_mut_slice()[..n]) {
                unreadable_run = 0;
                for s in (0..n).step_by(ss) {
                    let e = (s + ss).min(n);
                    if rbuf.as_slice()[s..e] != expected[s..e] {
                        self.errors.verify += 1;
                    }
                }
            } else {
                // Lecture groupée impossible : secteur par secteur, dans le même tampon aligné.
                for s in (0..n).step_by(ss) {
                    let e = (s + ss).min(n);
                    if self.read_retry(off + s as u64, &mut rbuf.as_mut_slice()[s..e]) {
                        unreadable_run = 0;
                        if rbuf.as_slice()[s..e] != expected[s..e] {
                            self.errors.verify += 1;
                        }
                    } else {
                        self.errors.verify += 1;
                        unreadable_run += 1;
                        if unreadable_run > MAX_CONSECUTIVE_BAD_SECTORS {
                            self.abort_reason = Some(
                                "Trop de secteurs illisibles d'affilée pendant la vérification : disque inaccessible ou débranché"
                                    .into(),
                            );
                            return false;
                        }
                    }
                }
            }
            off += n as u64;
            self.advance(Phase::Verify, index, off, size, n as u64);
        }
        true
    }
}
