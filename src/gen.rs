pub struct Sm(u64);

impl Sm {
    pub fn new(seed: u64) -> Sm {
        Sm(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

pub fn dimension<T: Copy>(xs: &[T], i: usize, master: u64) -> T {
    let mut r = Sm::new(master | 1);
    let mut idx: Vec<usize> = (0..xs.len()).collect();
    for j in (1..idx.len()).rev() {
        let k = r.below((j as u64) + 1) as usize;
        idx.swap(j, k);
    }
    xs[idx[i % xs.len()]]
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Os {
    Win,
    Mac,
    Linux,
}

impl Os {
    pub fn platform(self) -> &'static str {
        match self {
            Os::Win => "Win32",
            Os::Mac => "MacIntel",
            Os::Linux => "Linux x86_64",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Os::Win => "Windows",
            Os::Mac => "Mac OS",
            Os::Linux => "Linux",
        }
    }
    pub fn version(self) -> &'static str {
        match self {
            Os::Win => "10",
            Os::Mac => "10.15.7",
            Os::Linux => "",
        }
    }
    pub fn ua(self) -> String {
        match self {
            Os::Win => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36".into(),
            Os::Mac => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36".into(),
            Os::Linux => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36".into(),
        }
    }
}

pub const SCREENS: &[(u32, u32)] = &[
    (1920, 1080), (2560, 1440), (3840, 2160), (1440, 900), (1680, 1050),
    (2560, 1600), (1920, 1200), (1366, 768), (3072, 1920), (3440, 1440),
    (1280, 800), (1512, 982), (2880, 1800), (4096, 2304), (2048, 1152),
];

pub const TZS: &[(&str, i32)] = &[
    ("America/New_York", 240), ("Europe/Berlin", -60), ("Europe/London", 0),
    ("America/Los_Angeles", 420), ("Europe/Moscow", -180), ("Asia/Singapore", -480),
    ("America/Chicago", 300), ("Europe/Paris", -60), ("Asia/Tokyo", -540),
    ("Australia/Sydney", -600), ("America/Denver", 360), ("Europe/Madrid", -60),
    ("Asia/Dubai", -240), ("America/Toronto", 240), ("Europe/Amsterdam", -60),
    ("Asia/Seoul", -540), ("America/Vancouver", 420), ("Europe/Warsaw", -60),
];

pub const LANGS: &[&str] = &[
    "en-US", "en-GB", "de-DE", "fr-FR", "es-ES", "ja-JP", "ko-KR", "pt-BR",
    "nl-NL", "it-IT", "pl-PL", "sv-SE", "en-AU", "tr-TR", "da-DK",
    "en-CA", "ru-RU", "en-SG", "fi-FI", "nb-NO",
];

pub const CORES: &[u32] = &[4, 6, 8, 10, 12, 14, 16, 20, 24, 32];
pub const MEMS: &[u32] = &[8, 12, 16, 24, 32, 48, 64, 96, 128, 256];

const GPUS: &[(&str, &str, u32, u8)] = &[
    ("Google Inc. (NVIDIA)", "NVIDIA GeForce RTX 4070", 16384, b'w'),
    ("Google Inc. (NVIDIA)", "NVIDIA GeForce RTX 4060", 16384, b'w'),
    ("Google Inc. (NVIDIA)", "NVIDIA GeForce RTX 5090", 32768, b'w'),
    ("Google Inc. (NVIDIA)", "NVIDIA GeForce RTX 3080", 16384, b'w'),
    ("Google Inc. (NVIDIA)", "NVIDIA GeForce GTX 1660", 16384, b'w'),
    ("Google Inc. (Intel)", "Intel(R) Iris(R) Xe Graphics", 8192, b'w'),
    ("Google Inc. (Intel)", "Intel(R) UHD Graphics 770", 8192, b'w'),
    ("Google Inc. (Intel)", "Intel(R) UHD Graphics 630", 8192, b'w'),
    ("Google Inc. (AMD)", "AMD Radeon RX 7800 XT", 16384, b'w'),
    ("Google Inc. (AMD)", "AMD Radeon RX 6700 XT", 16384, b'w'),
    ("Google Inc. (Apple)", "Apple M3", 16384, b'm'),
    ("Google Inc. (Apple)", "Apple M2", 16384, b'm'),
    ("Google Inc. (Apple)", "Apple M1 Pro", 16384, b'm'),
    ("Google Inc. (Apple)", "Apple M4", 16384, b'm'),
    ("Google Inc. (Intel)", "Intel(R) Iris(TM) Plus Graphics 645", 8192, b'm'),
    ("Mesa", "llvmpipe (LLVM 15.0.7, 256 bits)", 8192, b'l'),
    ("Google Inc. (AMD)", "AMD Radeon RX 6600", 16384, b'l'),
    ("Mesa", "Intel(R) UHD Graphics (CMLT-SGT)", 8192, b'l'),
    ("Mesa/X.org", "AMD RENOIR (DRM 3.54)", 16384, b'l'),
    ("Google Inc. (NVIDIA)", "NVIDIA GeForce RTX 4080", 16384, b'w'),
];

pub fn angle_string(vendor: &str, model: &str, os: Os) -> String {
    let brand = vendor
        .split('(')
        .nth(1)
        .and_then(|s| s.split(')').next())
        .unwrap_or(vendor);
    match os {
        Os::Win => format!(
            "ANGLE ({}, {} Direct3D11 vs_5_0 ps_5_0, D3D11)",
            brand, model
        ),
        Os::Mac => format!("ANGLE ({}, {})", brand, model),
        Os::Linux => format!("ANGLE ({}, {} (llvmpipe)", brand, model),
    }
}

pub struct Snap {
    pub idx: usize,
    pub os: Os,
    pub screen: (u32, u32),
    pub avail: (u32, u32),
    pub inner: (u32, u32),
    pub outer: (u32, u32),
    pub dpr: f64,
    pub depth: u32,
    pub cores: u32,
    pub mem: u32,
    pub lang: &'static str,
    pub tz: &'static str,
    pub tzo: i32,
    pub gpu_vendor: &'static str,
    pub gpu_model: &'static str,
    pub gpu_angle: String,
    pub max_tex: u32,
    pub touch: bool,
    pub fonts_count: u32,
    pub seed: u64,
}

pub fn seed_of(idx: usize) -> u64 {
    0xC0FF_EE20_2600_0001u64
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add((idx as u64).wrapping_mul(0x517C_C1B7_2722_0A95))
        .rotate_left(17)
        ^ (idx as u64).wrapping_mul(0x2545_F491_4F6C_DD1D)
}

const M_OS: u64 = 0x9E37_79B9_7F4A_7C15;
const M_SCREEN: u64 = 0xF00D_BEEF_CAFE_0001;
const M_GPU: u64 = 0x517C_C1B7_2722_0A95;
const M_TZ: u64 = 0x2545_F491_4F6C_DD1D;
const M_LANG: u64 = 0x1000_0000_0000_001B;
const M_CORES: u64 = 0x8E37_E9C_7F4A_7C15;
const M_MEM: u64 = 0xDECA_FBAD_1234_5678;

pub fn snap(idx: usize) -> Snap {
    let seed = seed_of(idx);
    let mut r = Sm::new(seed | 1);
    let gpu = dimension(GPUS, idx, M_GPU);

    let os_family = gpu.3;
    let os = match os_family {
        b'm' => Os::Mac,
        b'l' => {
            if r.below(3) == 0 {
                Os::Win
            } else {
                Os::Linux
            }
        }
        _ => {
            if r.below(6) == 0 {
                Os::Linux
            } else {
                Os::Win
            }
        }
    };

    let (gpu_vendor, gpu_model, max_tex) = if os == Os::Mac
        && gpu.3 != b'm'
    {
        let mac = dimension(
            &GPUS.iter().filter(|g| g.3 == b'm').copied().collect::<Vec<_>>(),
            idx,
            M_GPU ^ 0xABCD,
        );
        (mac.0, mac.1, mac.2)
    } else {
        (gpu.0, gpu.1, gpu.2)
    };
    let (sw, sh) = dimension(SCREENS, idx, M_SCREEN);

    let panel = match os {
        Os::Win => 40 + 8 * r.below(3) as u32,
        Os::Mac => 24 + 24 * r.below(2) as u32,
        Os::Linux => 24 + 40 * r.below(2) as u32,
    };
    let (aw, ah) = (sw, sh - panel);
    let scale = match r.below(3) {
        0 => 0.70 + r.unit() * 0.06,
        1 => 0.84 + r.unit() * 0.05,
        _ => 0.93 + r.unit() * 0.04,
    };
    let iw = (((aw as f64 * scale) as u32).max(640)) & !1u32;
    let ih = (((ah as f64 * scale) as u32).max(480)) & !1u32;
    let frame = 6 + 2 * r.below(3) as u32;
    let (ow, oh) = (iw + 2 * frame, ih + 2 * frame + 8);
    let dpr = match r.below(5) {
        0 => 1.25,
        1 => 1.5,
        2 => 2.0,
        _ => 1.0,
    };
    let cores = dimension(CORES, idx, M_CORES);
    let mem = dimension(MEMS, idx, M_MEM);
    let (tz, tzo) = dimension(TZS, idx, M_TZ);
    let lang = dimension(LANGS, idx, M_LANG);
    let fonts_count = match os {
        Os::Win => 50 + (idx as u32 % 3) * 4 + r.below(3) as u32,
        Os::Mac => 66 + (idx as u32 % 4) * 3 + r.below(3) as u32,
        Os::Linux => 60 + (idx as u32 % 5) * 3 + r.below(4) as u32,
    };
    Snap {
        idx,
        os,
        screen: (sw, sh),
        avail: (aw, ah),
        inner: (iw, ih),
        outer: (ow, oh),
        dpr,
        depth: 24,
        cores,
        mem,
        lang,
        tz,
        tzo,
        gpu_vendor,
        gpu_model,
        gpu_angle: angle_string(gpu_vendor, gpu_model, os),
        max_tex,
        touch: false,
        fonts_count,
        seed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
