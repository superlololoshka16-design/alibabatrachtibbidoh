use zaic::gen::*;

use zaic::gen::*;
use std::collections::HashSet;

#[test]
fn permuted_dimensions_pairwise_distinct() {
    let snaps: Vec<Snap> = (0..10).map(snap).collect();
    for (name, key) in [
        ("screen", Box::new(|s: &Snap| format!("{}x{}", s.screen.0, s.screen.1)) as Box<dyn Fn(&Snap) -> String>),
        ("gpu", Box::new(|s: &Snap| s.gpu_model.to_string())),
        ("tz", Box::new(|s: &Snap| s.tz.to_string())),
        ("lang", Box::new(|s: &Snap| s.lang.to_string())),
        ("cores", Box::new(|s: &Snap| s.cores.to_string())),
        ("mem", Box::new(|s: &Snap| s.mem.to_string())),
    ] {
        let set: HashSet<String> = snaps.iter().map(|s| key(s)).collect();
        assert_eq!(set.len(), 10, "размерность {} пересекается", name);
    }

    let ids: HashSet<String> = snaps
        .iter()
        .map(|s| format!("{:?}|{:?}|{}|{}|{}", s.os, s.screen, s.gpu_model, s.tz, s.cores))
        .collect();
    assert_eq!(ids.len(), 10);
}

#[test]
fn coherent_geometry() {
    for i in 0..10 {
        let sn = snap(i);
        assert!(sn.avail.1 < sn.screen.1, "avail < screen");
        assert!(sn.inner.0 <= sn.avail.0 && sn.inner.1 <= sn.avail.1);
        assert!(sn.outer.0 >= sn.inner.0 && sn.outer.1 >= sn.inner.1);
        assert_eq!(sn.depth, 24);
        assert!(sn.dpr >= 1.0 && sn.dpr <= 2.0);

        assert_eq!(
            sn.os.platform(),
            match sn.os {
                Os::Win => "Win32",
                Os::Mac => "MacIntel",
                Os::Linux => "Linux x86_64",
            }
        );
    }
}

#[test]
fn deterministic_and_spread() {
    for i in 0..10 {
        assert_eq!(snap(i).gpu_angle, snap(i).gpu_angle);
    }
    let a = snap(0);
    let b = snap(9);
    assert_ne!((a.screen.0, a.screen.1), (b.screen.0, b.screen.1));
    assert_ne!(a.tz, b.tz);
}
