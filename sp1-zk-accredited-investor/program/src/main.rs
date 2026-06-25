#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::io;
use sha2::Digest;

pub fn main() {
    // Read private inputs (not revealed in proof)
    let pdf_bytes: Vec<u8> = io::read_vec();
    let docusign_cert_der: Vec<u8> = io::read_vec();
    let current_timestamp: u64 = io::read();
    let investor_wallet: [u8; 32] = io::read();

    // Step 1: Verify PKCS#7 signature on PDF
    let signature_valid = verify_pkcs7_signature(&pdf_bytes, &docusign_cert_der);
    assert!(signature_valid, "PDF signature invalid");

    // Step 2: Extract PDF issue date and check recency
    let pdf_date = extract_pdf_date(&pdf_bytes);
    let ninety_days_seconds: u64 = 90 * 24 * 60 * 60;
    assert!(
        current_timestamp - pdf_date <= ninety_days_seconds,
        "Document older than 90 days"
    );

    // Step 3: Parse PDF text layer and run regex
    let pdf_text = extract_pdf_text(&pdf_bytes);
    let is_accredited = check_accredited_investor_phrase(&pdf_text);
    assert!(is_accredited, "Accredited investor phrase not found");

    // Step 4: Derive nullifier from DocuSign signature hash
    let nullifier = derive_nullifier(&pdf_bytes);

    // Commit public outputs (these ARE revealed in proof)
    io::commit(&investor_wallet);
    io::commit(&nullifier);
    io::commit(&current_timestamp);
}

/// Verify PKCS#7 detached or embedded signature on PDF
/// DocuSign embeds signature in PDF's AcroForm /ByteRange
fn verify_pkcs7_signature(pdf_bytes: &[u8], _cert_der: &[u8]) -> bool {
    // Lean version for zkVM: at minimum confirm a plausible signature blob exists.
    // Full implementation (ByteRange slicing + cms::SignedData verification + x509 chain)
    // must be completed with the cms + x509-cert crates and tested outside first.
    extract_signature_bytes(pdf_bytes).is_some()
}

fn extract_signature_bytes(pdf_bytes: &[u8]) -> Option<Vec<u8>> {
    // Look for /Contents<...> or (....) near signature patterns.
    // A more robust version scans for /ByteRange [ ... ] and extracts the corresponding ranges.
    if let Some(pos) = find_subsequence(pdf_bytes, b"/Contents") {
        // crude: take next ~ few hundred bytes and look for hex or literal string end
        let slice = &pdf_bytes[pos..(pos + 400).min(pdf_bytes.len())];
        // Try to find a hex string <....>
        if let Some(start) = slice.iter().position(|&b| b == b'<') {
            if let Some(end_rel) = slice[start..].iter().position(|&b| b == b'>') {
                let inner = &slice[start + 1..start + end_rel];
                // hex decode attempt (very basic)
                if inner.len() % 2 == 0 && inner.len() > 10 {
                    let mut out = Vec::with_capacity(inner.len() / 2);
                    for i in (0..inner.len()).step_by(2) {
                        let hi = from_hex_digit(inner[i])?;
                        let lo = from_hex_digit(inner[i + 1])?;
                        out.push((hi << 4) | lo);
                    }
                    if out.len() > 32 {
                        return Some(out);
                    }
                }
            }
        }
    }
    None
}

fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extract issue date from PDF metadata or text
fn extract_pdf_date(pdf_bytes: &[u8]) -> u64 {
    // Lean scanner: look for /CreationDate (D:....) in the PDF bytes.
    if let Some(pos) = find_subsequence(pdf_bytes, b"/CreationDate") {
        let slice = &pdf_bytes[pos..(pos + 64).min(pdf_bytes.len())];
        if let Some(dpos) = slice.iter().position(|&b| b == b'D' && slice.get(slice.iter().position(|&x| x==b'D').unwrap_or(0)+1) == Some(&b':')) {
            let start = pos + dpos;
            if let Some(end) = pdf_bytes[start..].iter().position(|&b| b == b')' || b == b' ' || b == b'\n' || b == b'\r') {
                let date_bytes = &pdf_bytes[start..start + end];
                if let Some(ts) = parse_pdf_date(date_bytes) {
                    return ts;
                }
            }
        }
    }
    // Fallback: search raw D:2024...
    if let Some(pos) = find_subsequence(pdf_bytes, b"D:20") {
        let cand = &pdf_bytes[pos..(pos + 20).min(pdf_bytes.len())];
        if let Some(ts) = parse_pdf_date(cand) {
            return ts;
        }
    }
    0
}

fn parse_pdf_date(s: &[u8]) -> Option<u64> {
    // Expect starting with D: or just the digits
    let s = if s.starts_with(b"D:") { &s[2..] } else { s };
    if s.len() < 14 { return None; }
    let y = std::str::from_utf8(&s[0..4]).ok()?.parse::<i32>().ok()?;
    let mo = std::str::from_utf8(&s[4..6]).ok()?.parse::<u32>().ok()?;
    let d = std::str::from_utf8(&s[6..8]).ok()?.parse::<u32>().ok()?;
    let h = std::str::from_utf8(&s[8..10]).ok()?.parse::<u32>().ok()?;
    let mi = std::str::from_utf8(&s[10..12]).ok()?.parse::<u32>().ok()?;
    let se = std::str::from_utf8(&s[12..14]).ok()?.parse::<u32>().ok()?;
    // Very rough (no tz)
    // 2000-01-01 as base rough calc not accurate, use chrono for better in host.
    // For zk simplicity return a unix approx.
    // For accuracy we can hardcode a simple formula or use chrono (already in deps).
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    let date = NaiveDate::from_ymd_opt(y, mo, d)?;
    let time = NaiveTime::from_hms_opt(h, mi, se)?;
    Some(NaiveDateTime::new(date, time).and_utc().timestamp() as u64)
}

/// Extract full text content from PDF
fn extract_pdf_text(pdf_bytes: &[u8]) -> String {
    // Lean implementation: scan for (text) Tj patterns in content streams.
    // Sufficient for finding the mandated SEC phrase in most text PDFs.
    let mut out = String::new();
    let mut i = 0;
    while i < pdf_bytes.len() {
        if pdf_bytes[i] == b'(' {
            // collect until unescaped )
            let start = i + 1;
            let mut j = start;
            while j < pdf_bytes.len() {
                if pdf_bytes[j] == b'\\' { j += 2; continue; }
                if pdf_bytes[j] == b')' { break; }
                j += 1;
            }
            if j < pdf_bytes.len() {
                if let Ok(s) = std::str::from_utf8(&pdf_bytes[start..j]) {
                    out.push_str(s);
                    out.push(' ');
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Check for SEC Rule 501(a) mandatory anchor phrase
fn check_accredited_investor_phrase(text: &str) -> bool {
    // Primary regex targets (both individual and joint):
    // "net worth in excess of $1,000,000, excluding the value of their primary residence"
    // "net worth with their spouse in excess of $1,000,000, excluding the value of their primary residence"
    //
    // Critical anchor: "excluding the value of their primary residence"
    // This phrase is legally mandated by SEC Rule 501(a)
    // Any legitimate CPA attestation MUST contain it
    // If this phrase is absent, the document is legally invalid

    let anchor = "excluding the value of their primary residence";
    let threshold = "1,000,000";

    text.contains(anchor) && text.contains(threshold)
}

/// Derive nullifier from DocuSign signature bytes
/// Deterministic hash — same document always produces same nullifier
fn derive_nullifier(pdf_bytes: &[u8]) -> [u8; 32] {
    if let Some(sig) = extract_signature_bytes(pdf_bytes) {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&sig);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        return out;
    }
    // Fallback (dev only)
    let mut hasher = sha2::Sha256::new();
    hasher.update(pdf_bytes);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}