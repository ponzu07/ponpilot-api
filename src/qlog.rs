use std::io::Read;

const MAX_DECOMPRESSED: u64 = 32 << 20;
const STATES: [&str; 5] = [
    "disabled",
    "preEnabled",
    "enabled",
    "softDisabling",
    "overriding",
];

#[derive(Default)]
pub struct Segment {
    pub start_millis: i64,
    pub start_offset: i64,
    pub end_offset: i64,
    pub distance_m: f64,
    pub coords: Vec<(i64, f64, f64)>,
    pub states: Vec<(i64, &'static str, bool, u16)>,
}

struct Sub<'a> {
    seg: &'a [u8],
    data: usize,
    dw: usize,
    pw: usize,
}

impl<'a> Sub<'a> {
    fn at(seg: &'a [u8], word: usize) -> Option<Self> {
        let p = u64::from_le_bytes(seg.get(word * 8..word * 8 + 8)?.try_into().ok()?);
        if p & 3 != 0 {
            return None;
        }
        let data = (word + 1).checked_add_signed(((p as u32 as i32) >> 2) as isize)?;
        let (dw, pw) = ((p >> 32) as u16 as usize, (p >> 48) as u16 as usize);
        (data + dw + pw <= seg.len() / 8).then_some(Self { seg, data, dw, pw })
    }

    fn ptr(&self, i: usize) -> Option<Self> {
        (i < self.pw)
            .then(|| Self::at(self.seg, self.data + self.dw + i))
            .flatten()
    }

    fn raw<const N: usize>(&self, byte: usize) -> [u8; N] {
        let mut o = [0; N];
        if byte + N <= self.dw * 8 {
            o.copy_from_slice(&self.seg[self.data * 8 + byte..][..N]);
        }
        o
    }

    fn u16(&self, b: usize) -> u16 {
        u16::from_le_bytes(self.raw(b))
    }
    fn u64(&self, b: usize) -> u64 {
        u64::from_le_bytes(self.raw(b))
    }
    fn f32(&self, b: usize) -> f32 {
        f32::from_le_bytes(self.raw(b))
    }
    fn f64(&self, b: usize) -> f64 {
        f64::from_le_bytes(self.raw(b))
    }
    fn bit(&self, b: usize) -> bool {
        self.raw::<1>(b / 8)[0] >> (b % 8) & 1 != 0
    }
}

fn frame(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let n = u32::from_le_bytes(buf.get(..4)?.try_into().ok()?) as usize + 1;
    let head = (n / 2 + 1) * 8;
    let mut total = 0usize;
    for i in 0..n {
        let words = u32::from_le_bytes(buf.get(4 + i * 4..8 + i * 4)?.try_into().ok()?) as usize;
        total = total.checked_add(words * 8)?;
    }
    let first = u32::from_le_bytes(buf.get(4..8)?.try_into().ok()?) as usize * 8;
    Some((
        buf.get(head..head.checked_add(first)?)?,
        buf.get(head.checked_add(total)?..)?,
    ))
}

pub fn parse(zst: &[u8]) -> Option<Segment> {
    let mut buf = Vec::new();
    ruzstd::decoding::StreamingDecoder::new(zst)
        .ok()?
        .take(MAX_DECOMPRESSED)
        .read_to_end(&mut buf)
        .ok()?;

    let mut out = Segment::default();
    let (mut origin, mut prev, mut last) = (None, None, None);
    let mut cur = &buf[..];
    while let Some((seg, rest)) = frame(cur) {
        cur = rest;
        let Some(ev) = Sub::at(seg, 0) else { continue };
        let (mono, disc) = (ev.u64(0) as i64, ev.u16(8));
        let Some(d) = ev.ptr(0) else { continue };
        if disc == 0 {
            origin = Some(mono);
            out.start_millis = (d.u64(8) / 1_000_000) as i64;
            continue;
        }
        let off = mono.wrapping_sub(origin?);
        match disc {
            21 => {
                let v = f64::from(d.f32(0));
                if let (Some(t), true) = (prev, v.is_finite()) {
                    out.distance_m += v * off.wrapping_sub(t) as f64 / 1e9;
                }
                prev = Some(off);
            }
            20 | 47 => {
                if d.bit(480) {
                    out.coords
                        .push(((off as f64 / 1e9).round() as i64, d.f64(8), d.f64(16)));
                }
            }
            71 => match d.u16(0) {
                0 | 1 => out.end_offset = off / 1_000_000,
                2 => out.start_offset = off / 1_000_000,
                _ => {}
            },
            128 => {
                let now = (
                    *STATES.get(d.u16(0) as usize).unwrap_or(&"disabled"),
                    d.bit(16),
                    d.u16(4),
                );
                if last != Some(now) {
                    out.states.push((off / 1_000_000, now.0, now.1, now.2));
                    last = Some(now);
                }
            }
            _ => {}
        }
    }
    origin.is_some().then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/qlog/rivian0.qlog.zst");

    #[test]
    fn parses_real_qlog() {
        let s = parse(FIXTURE).unwrap();
        assert_eq!(s.start_millis, 1740392928021);
        assert_eq!((s.start_offset, s.end_offset), (0, 61428));
        assert!((s.distance_m - 746.383270).abs() < 1e-4, "{}", s.distance_m);

        assert_eq!(s.coords.len(), 48);
        assert_eq!(s.coords[0].0, 14, "最初の fix は route 開始から 14 秒後");
        assert!((s.coords[0].1 - 32.750254201494016).abs() < 1e-12);
        assert!((s.coords[0].2 - -117.19483179167581).abs() < 1e-12);
        assert_eq!(s.coords[47].0, 61);
        assert!(
            s.coords.windows(2).all(|w| w[1].0 == w[0].0 + 1),
            "1 Hz で連続している"
        );

        assert_eq!(
            s.states,
            [
                (3836, "disabled", false, 1),
                (8939, "disabled", false, 0),
                (54840, "overriding", true, 0),
                (55439, "enabled", true, 0),
            ]
        );
    }

    #[test]
    fn skips_multi_segment_messages() {
        let mut buf = Vec::new();
        buf.extend(1u32.to_le_bytes()); // セグメント数 - 1
        buf.extend(1u32.to_le_bytes()); // セグメント 0: 1 語
        buf.extend(1u32.to_le_bytes()); // セグメント 1: 1 語
        buf.extend([0u8; 4]); // 8 バイト境界へのパディング
        buf.extend([0u8; 16]); // 本体 2 語
        buf.extend(0u32.to_le_bytes()); // 2 通目: 1 セグメント
        buf.extend(1u32.to_le_bytes());
        buf.extend([0u8; 8]);

        let (first, rest) = frame(&buf).unwrap();
        assert_eq!(first.len(), 8, "返るのはセグメント 0 だけ");
        assert_eq!(rest.len(), 16, "2 通目の先頭に進んでいる");
        assert_eq!(frame(rest).unwrap().1.len(), 0);
    }

    #[test]
    fn degrades_instead_of_hanging_or_panicking() {
        assert!(parse(b"").is_none());
        assert!(parse(b"not zstd at all").is_none());
        assert!(parse(&FIXTURE[..FIXTURE.len() / 2]).is_none(), "切り詰め");
        assert!(Sub::at(&2u64.to_le_bytes(), 0).is_none(), "far pointer");
    }
}
