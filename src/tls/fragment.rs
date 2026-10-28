//! TLS record fragmentation: one record → several valid records.
//! Servers reassemble TLS records transparently; DPI often only inspects
//! the first record, so slicing the handshake defeats SNI extraction.

/// Fragment a full TLS record (header + payload) into records with at most
/// `max_payload` payload bytes each.
///
/// Returns `(fragments, map)` where `map[orig_index] = new_index` maps byte
/// positions of the original record into the concatenated output.
/// Fragmenting preserves the byte stream of the handshake payload; only the
/// record headers change. Original header bytes (0..5) map into the new
/// header region (approximate — split logic never cuts there).
pub fn fragment_record(rec: &[u8], max_payload: usize) -> (Vec<Vec<u8>>, Vec<usize>) {
    debug_assert!(rec.len() >= 5, "not a TLS record");
    if max_payload == 0 || rec.len() <= 5 {
        return (vec![rec.to_vec()], identity_map(rec.len()));
    }

    let payload = &rec[5..];
    if payload.is_empty() {
        return (vec![rec.to_vec()], identity_map(rec.len()));
    }

    let mut frags: Vec<Vec<u8>> = Vec::new();
    let mut starts: Vec<usize> = Vec::new(); // payload start offset of each frag
    let mut pos = 0usize;
    while pos < payload.len() {
        let take = max_payload.min(payload.len() - pos);
        starts.push(pos);
        let mut f = Vec::with_capacity(5 + take);
        f.push(0x16); // handshake (original content type assumed 0x16)
        f.extend_from_slice(&rec[1..3]); // keep record version (0x0301/0x0303)
        f.extend_from_slice(&(take as u16).to_be_bytes());
        f.extend_from_slice(&payload[pos..pos + take]);
        frags.push(f);
        pos += take;
    }

    // Build orig→new map.
    let mut map = vec![0usize; rec.len()];
    // Original header: map into the beginning of the output (positions 0..5).
    for i in 0..5.min(rec.len()) {
        map[i] = i;
    }
    let mut new_payload_cursor = 5usize; // bytes consumed in output so far
    for (i, &s) in starts.iter().enumerate() {
        let flen = 5 + {
            // frag payload length
            if i + 1 < starts.len() {
                starts[i + 1] - s
            } else {
                payload.len() - s
            }
        };
        for (k, _) in frags[i].iter().enumerate().skip(5) {
            let orig = 5 + s + (k - 5);
            map[orig] = new_payload_cursor + (k - 5);
        }
        let _ = flen;
        new_payload_cursor += frags[i].len() - 5;
        // header of next frag will be inserted at new_payload_cursor
        if i + 1 < starts.len() {
            new_payload_cursor += 5; // next record header
        }
    }

    (frags, map)
}

fn identity_map(len: usize) -> Vec<usize> {
    (0..len).collect()
}

/// Map an offset from the original record into the fragmented byte stream.
pub fn map_offset(map: &[usize], off: usize) -> usize {
    if off >= map.len() {
        return map.len().saturating_sub(1);
    }
    map[off]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_client_hello;
    use crate::tls::{parse_sni, record_total_len};

    fn concat(frags: &[Vec<u8>]) -> Vec<u8> {
        frags.iter().flat_map(|f| f.iter().copied()).collect()
    }

    #[test]
    fn payload_preserved() {
        let rec = build_client_hello("example.com");
        let (frags, map) = fragment_record(&rec, 64);
        assert!(frags.len() > 1, "should produce several records");

        // payload of original == concat of payloads of frags
        let orig_payload = &rec[5..];
        let mut payloads = Vec::new();
        for f in &frags {
            let l = u16::from_be_bytes([f[3], f[4]]) as usize;
            assert_eq!(l, f.len() - 5);
            payloads.extend_from_slice(&f[5..]);
        }
        assert_eq!(payloads, orig_payload);
        assert_eq!(map.len(), rec.len(), "map indexes original coordinates");
    }

    #[test]
    fn each_fragment_is_valid_record() {
        let rec = build_client_hello("long-subdomain.example.com");
        let (frags, _) = fragment_record(&rec, 32);
        for f in &frags {
            assert_eq!(f[0], 0x16);
            let l = u16::from_be_bytes([f[3], f[4]]) as usize;
            assert_eq!(l, f.len() - 5);
            assert!(l <= 32);
        }
    }

    #[test]
    fn map_points_at_same_byte_content() {
        let rec = build_client_hello("mapped.example.com");
        let (frags, map) = fragment_record(&rec, 40);
        let joined = concat(&frags);
        // hostname must survive mapping
        let sni = parse_sni(&rec).unwrap().unwrap();
        let new_off = map_offset(&map, sni.hostname_start);
        assert_eq!(
            &joined[new_off..new_off + sni.hostname_len],
            sni.hostname.as_bytes()
        );
        // spot-check a payload byte
        let o = 7usize;
        assert_eq!(joined[map[o]], rec[o]);
    }

    #[test]
    fn identity_when_too_small() {
        let rec = build_client_hello("a.co");
        let (frags, map) = fragment_record(&rec, 0);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], rec);
        assert_eq!(map, identity_map(rec.len()));
        assert_eq!(record_total_len(&rec), Some(rec.len()));
    }

    #[test]
    fn fragments_parse_as_records() {
        let rec = build_client_hello("frag.example.org");
        let (frags, _) = fragment_record(&rec, 48);
        for f in &frags {
            assert!(record_total_len(f) == Some(f.len()));
        }
    }
}
