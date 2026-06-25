//! Local (non-zkVM) implementations of the PDF parsing, date extraction,
//! text extraction, signature verification, and nullifier derivation.
//!
//! These are developed and unit-tested **outside** the zkVM first (Day 1).
//! Once working on real DocuSign PDFs, they are ported (with minimal changes)
//! into program/src/main.rs for proving.
//!
//! WARNING: Full robust PKCS#7 + PDF ByteRange verification + text extraction
//! from arbitrary PDFs is non-trivial. Start with a real signed test PDF.

use lopdf::{Document, Object};
use sha2::{Digest, Sha256};
use std::io::Cursor;

/// Try to extract the raw signature bytes from a DocuSign-style PDF signature field.
/// Looks for /Contents under a signature annotation or AcroForm field.
/// This is a heuristic; real impl must also respect /ByteRange for what was actually signed.
pub fn extract_signature_bytes(pdf_bytes: &[u8]) -> Option<Vec<u8>> {
    let doc = Document::load_from(Cursor::new(pdf_bytes)).ok()?;
    // Walk AcroForm or Fields
    if let Ok(root) = doc.trailer.get(b"Root").and_then(|r| doc.get_object(r.as_reference().ok()?)) {
        if let Ok(acroform) = root.as_dict().and_then(|d| d.get(b"AcroForm")).and_then(|a| doc.get_object(a.as_reference().ok()?)) {
            if let Ok(fields) = acroform.as_dict().and_then(|d| d.get(b"Fields")) {
                if let Ok(arr) = fields.as_array() {
                    for f in arr {
                        if let Ok(field_ref) = f.as_reference() {
                            if let Ok(field) = doc.get_object(field_ref) {
                                if let Ok(dict) = field.as_dict() {
                                    // Look for /FT == /Sig and /Contents
                                    if let Ok(ft) = dict.get(b"FT").and_then(|o| o.as_name()) {
                                        if ft == b"Sig" || ft == b"Sig ".iter().copied().collect::<Vec<_>>().as_slice() {
                                            if let Ok(contents) = dict.get(b"Contents") {
                                                if let Ok(bytes) = contents.as_str() {
                                                    return Some(bytes.to_vec());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Fallback: scan for common signature object patterns (last resort)
    None
}

/// Derive nullifier (same logic must be used inside zkVM).
pub fn derive_nullifier(pdf_bytes: &[u8]) -> [u8; 32] {
    if let Some(sig) = extract_signature_bytes(pdf_bytes) {
        let mut hasher = Sha256::new();
        hasher.update(&sig);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        return out;
    }
    // Fallback: hash whole PDF (for dev only; not secure for real use)
    let mut hasher = Sha256::new();
    hasher.update(pdf_bytes);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Very basic PDF date extraction from /CreationDate in info or trailer.
/// Format often: D:20240601120000-07'00' or similar.
pub fn extract_pdf_date(pdf_bytes: &[u8]) -> Option<u64> {
    let doc = Document::load_from(Cursor::new(pdf_bytes)).ok()?;
    // Try /Info dict
    if let Ok(info_ref) = doc.trailer.get(b"Info").and_then(|i| i.as_reference()) {
        if let Ok(info) = doc.get_object(info_ref) {
            if let Ok(dict) = info.as_dict() {
                if let Ok(date_obj) = dict.get(b"CreationDate").or_else(|_| dict.get(b"ModDate")) {
                    if let Ok(date_str) = date_obj.as_str() {
                        return parse_pdf_date(date_str);
                    }
                }
            }
        }
    }
    None
}

fn parse_pdf_date(s: &[u8]) -> Option<u64> {
    // Naive parser for "D:YYYYMMDDHHmmSSOHH'mm'"
    let s = std::str::from_utf8(s).ok()?.trim_start_matches("D:");
    // Take first 14 chars as YYYYMMDDHHmmSS
    if s.len() < 14 {
        return None;
    }
    let y = s[0..4].parse::<i32>().ok()?;
    let m = s[4..6].parse::<u32>().ok()?;
    let d = s[6..8].parse::<u32>().ok()?;
    let hh = s[8..10].parse::<u32>().ok()?;
    let mm = s[10..12].parse::<u32>().ok()?;
    let ss = s[12..14].parse::<u32>().ok()?;

    // Very rough unix timestamp (ignores TZ for MVP)
    // Use chrono if available
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    let date = NaiveDate::from_ymd_opt(y, m, d)?;
    let time = NaiveTime::from_hms_opt(hh, mm, ss)?;
    let dt = NaiveDateTime::new(date, time);
    Some(dt.and_utc().timestamp() as u64)
}

/// Basic text extraction: collect strings from content streams.
/// This is a minimal implementation sufficient to find the anchor phrase in many text-based attestation PDFs.
pub fn extract_pdf_text(pdf_bytes: &[u8]) -> String {
    let mut text = String::new();
    if let Ok(doc) = Document::load_from(Cursor::new(pdf_bytes)) {
        for page_id in doc.page_iter() {
            if let Ok(page) = doc.get_page_content(page_id) {
                // page is the raw content bytes for this page
                // Simple scan for ( ... ) Tj strings or <...> hex
                let content = String::from_utf8_lossy(&page);
                // Very crude extraction
                for part in content.split("Tj") {
                    if let Some(start) = part.rfind('(') {
                        if let Some(end) = part[start..].find(')') {
                            let s = &part[start + 1..start + end];
                            text.push_str(s);
                            text.push(' ');
                        }
                    }
                }
            }
        }
    }
    text
}

/// The critical check (same as in zkVM).
pub fn check_accredited_investor_phrase(text: &str) -> bool {
    let anchor = "excluding the value of their primary residence";
    let threshold = "1,000,000";
    text.contains(anchor) && text.contains(threshold)
}

/// Placeholder for signature verification (full impl is complex).
/// For local testing: return true if we can at least locate a /Contents that looks like a CMS blob.
pub fn verify_pkcs7_signature_local(pdf_bytes: &[u8], _trusted_root_der: &[u8]) -> bool {
    // TODO: Real implementation:
    // 1. Find ByteRange + Contents.
    // 2. Reconstruct the exact signed data from ByteRange.
    // 3. Parse CMS with `cms` crate.
    // 4. Verify signature and cert chain to _trusted_root_der using x509-cert + rustcrypto.
    if extract_signature_bytes(pdf_bytes).is_some() {
        // At least a signature was present. Full crypto check needed.
        // For early dev we can return true to allow flow testing once other pieces work.
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phrase_check() {
        let good = "The investor has a net worth in excess of $1,000,000, excluding the value of their primary residence.";
        assert!(check_accredited_investor_phrase(good));

        let bad = "net worth over 1 million";
        assert!(!check_accredited_investor_phrase(bad));
    }

    // Add real PDF test once you have attestation.pdf in the crate root or pass bytes.
    // #[test]
    // fn test_with_real_pdf() {
    //     let bytes = std::fs::read("attestation.pdf").unwrap();
    //     let txt = extract_pdf_text(&bytes);
    //     assert!(check_accredited_investor_phrase(&txt));
    //     let _ = extract_pdf_date(&bytes);
    //     let n = derive_nullifier(&bytes);
    //     assert_ne!(n, [0u8;32]);
    // }
}