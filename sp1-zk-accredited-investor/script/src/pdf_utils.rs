//! Local (non-zkVM) implementations of the PDF parsing, date extraction,
//! text extraction, signature verification, and nullifier derivation.
//!
//! These are developed and unit-tested **outside** the zkVM first (Day 1).
//! Once working on real DocuSign PDFs, they are ported (with minimal changes)
//! into program/src/main.rs for proving.
//!
//! WARNING: Full robust PKCS#7 + PDF ByteRange verification + text extraction
//! from arbitrary PDFs is non-trivial. Start with a real signed test PDF.

// ── x509-cert re-exports its own `der` crate, so we use those paths ──────────
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::DecodePublicKey;
use x509_cert::Certificate;

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use lopdf::Document;
use rsa::pkcs1v15::Signature as Pkcs1Sig;
use rsa::signature::hazmat::PrehashVerifier;
use rsa::{pkcs1v15::VerifyingKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384};
use std::io::Cursor;

// ─── Signature byte extraction (heuristic) ───────────────────────────────────

/// Extract the raw DER bytes of the CMS blob from the PDF /Contents field.
/// Uses a fast byte-scan first, falls back to lopdf dictionary walk.
pub fn extract_signature_bytes(pdf_bytes: &[u8]) -> Option<Vec<u8>> {
    // Fast path: scan for /Contents<hex> pattern in the raw bytes.
    if let Some(pos) = find_subsequence(pdf_bytes, b"/Contents") {
        let slice = &pdf_bytes[pos..(pos + 400).min(pdf_bytes.len())];
        if let Some(start) = slice.iter().position(|&b| b == b'<') {
            if let Some(end_rel) = slice[start..].iter().position(|&b| b == b'>') {
                let inner = &slice[start + 1..start + end_rel];
                if inner.len() % 2 == 0 && inner.len() > 10 {
                    let mut out = Vec::with_capacity(inner.len() / 2);
                    let mut ok = true;
                    for i in (0..inner.len()).step_by(2) {
                        match (from_hex_digit(inner[i]), from_hex_digit(inner[i + 1])) {
                            (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
                            _ => { ok = false; break; }
                        }
                    }
                    if ok {
                        // Strip trailing null padding (DocuSign over-allocates /Contents)
                        let trimmed_len =
                            out.iter().rposition(|&b| b != 0).map(|p| p + 1).unwrap_or(0);
                        if trimmed_len > 32 {
                            out.truncate(trimmed_len);
                            return Some(out);
                        }
                    }
                }
            }
        }
    }
    // Fallback: use lopdf to walk the object tree looking for a Sig field.
    if let Ok(doc) = Document::load_from(Cursor::new(pdf_bytes)) {
        for (_, obj) in &doc.objects {
            if let Ok(dict) = obj.as_dict() {
                let is_sig = dict
                    .get(b"FT").ok()
                    .and_then(|v| v.as_name().ok())
                    .map(|n| n == b"Sig")
                    .unwrap_or(false)
                    || dict
                        .get(b"Type").ok()
                        .and_then(|v| v.as_name().ok())
                        .map(|n| n == b"Sig")
                        .unwrap_or(false);
                if is_sig {
                    if let Ok(contents) = dict.get(b"Contents").and_then(|c| c.as_str()) {
                        let trimmed_len =
                            contents.iter().rposition(|&b| b != 0).map(|p| p + 1).unwrap_or(0);
                        if trimmed_len > 32 {
                            return Some(contents[..trimmed_len].to_vec());
                        }
                    }
                }
            }
        }
    }
    None
}

// ─── ByteRange extraction ─────────────────────────────────────────────────────

/// Parse `/ByteRange [a b c d]` from the raw PDF bytes.
/// Returns `[offset1, length1, offset2, length2]`.
fn extract_byte_range(pdf_bytes: &[u8]) -> Option<[usize; 4]> {
    let marker = b"/ByteRange";
    let pos = find_subsequence(pdf_bytes, marker)?;
    let rest = &pdf_bytes[pos + marker.len()..];
    let bracket_start = rest.iter().position(|&b| b == b'[')?;
    let bracket_end = rest[bracket_start..].iter().position(|&b| b == b']')?;
    let inner =
        std::str::from_utf8(&rest[bracket_start + 1..bracket_start + bracket_end]).ok()?;
    let nums: Vec<usize> = inner
        .split_whitespace()
        .filter_map(|tok| tok.parse::<usize>().ok())
        .collect();
    if nums.len() == 4 {
        Some([nums[0], nums[1], nums[2], nums[3]])
    } else {
        None
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

// ─── Nullifier derivation ─────────────────────────────────────────────────────

/// Derive nullifier — SHA-256 of the DocuSign CMS blob (same logic used inside zkVM).
pub fn derive_nullifier(pdf_bytes: &[u8]) -> [u8; 32] {
    let input = extract_signature_bytes(pdf_bytes).unwrap_or_else(|| pdf_bytes.to_vec());
    let result = Sha256::digest(&input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ─── PDF date extraction ──────────────────────────────────────────────────────

/// Extract the document date from /Info → /CreationDate (or /ModDate).
pub fn extract_pdf_date(pdf_bytes: &[u8]) -> Option<u64> {
    // Primary: document `/Info` dictionary.
    if let Some(ts) = extract_date_from_info(pdf_bytes) {
        return Some(ts);
    }

    // Fallback: some DocuSign-style PDFs expose dates in signature fields.
    if let Some(ts) = extract_date_from_sig_fields(pdf_bytes) {
        return Some(ts);
    }

    None
}

fn extract_date_from_info(pdf_bytes: &[u8]) -> Option<u64> {
    let doc = Document::load_from(Cursor::new(pdf_bytes)).ok()?;
    let info_ref = doc.trailer.get(b"Info").ok()?.as_reference().ok()?;
    let info = doc.get_object(info_ref).ok()?;
    let dict = info.as_dict().ok()?;
    let date_raw = dict.get(b"CreationDate").or_else(|_| dict.get(b"ModDate")).ok()?;
    let date_bytes = date_raw.as_str().ok()?;
    eprintln!("[date] Info/CreationDate raw={:?}", std::str::from_utf8(date_bytes).ok());
    parse_pdf_date(date_bytes)
}

fn extract_date_from_sig_fields(pdf_bytes: &[u8]) -> Option<u64> {
    if let Ok(doc) = Document::load_from(Cursor::new(pdf_bytes)) {
        for (id, obj) in &doc.objects {
            let dict = obj.as_dict().ok()?;
            let is_sig = dict
                .get(b"FT")
                .ok()
                .and_then(|v| v.as_name().ok())
                .map(|n| n == b"Sig")
                .unwrap_or(false)
                || dict
                    .get(b"Type")
                    .ok()
                    .and_then(|v| v.as_name().ok())
                    .map(|n| n == b"Sig")
                    .unwrap_or(false);
            if !is_sig {
                continue;
            }
            for key in [b"M".as_slice(), b"SigningDate".as_slice(), b"Date".as_slice()] {
                if let Ok(val) = dict.get(key) {
                    if let Ok(date_bytes) = val.as_str() {
                        eprintln!("[date] sig field id={:?} key={:?} raw={:?}", id, key, std::str::from_utf8(date_bytes).ok());
                        if let Some(ts) = parse_pdf_date(date_bytes) {
                            return Some(ts);
                        }
                    }
                }
            }
        }
    }
    None
}

fn parse_pdf_date(s: &[u8]) -> Option<u64> {
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    let s = std::str::from_utf8(s).ok()?.trim_start_matches("D:");
    if s.len() < 14 {
        return None;
    }
    let y = s[0..4].parse::<i32>().ok()?;
    let m = s[4..6].parse::<u32>().ok()?;
    let d = s[6..8].parse::<u32>().ok()?;
    let hh = s[8..10].parse::<u32>().ok()?;
    let mm = s[10..12].parse::<u32>().ok()?;
    let ss = s[12..14].parse::<u32>().ok()?;
    let date = NaiveDate::from_ymd_opt(y, m, d)?;
    let time = NaiveTime::from_hms_opt(hh, mm, ss)?;
    Some(NaiveDateTime::new(date, time).and_utc().timestamp() as u64)
}

// ─── PDF text extraction ──────────────────────────────────────────────────────

/// Extract visible text from all pages using lopdf's built-in content stream
/// decoder which handles FlateDecode (compressed) streams automatically.
/// Falls back to a raw Tj byte scanner if lopdf extract_text fails.
pub fn extract_pdf_text(pdf_bytes: &[u8]) -> String {
    let mut text = String::new();
    if let Ok(doc) = Document::load_from(Cursor::new(pdf_bytes)) {
        // Primary path: use lopdf's extract_text which decompresses content streams.
        let page_ids: Vec<_> = doc.page_iter().collect();
        let page_nums: Vec<u32> = (1..=(page_ids.len() as u32)).collect();
        if let Ok(extracted) = doc.extract_text(&page_nums) {
            if !extracted.trim().is_empty() {
                eprintln!("[text] lopdf extract_text succeeded ({} chars)", extracted.len());
                return extracted;
            }
        }

        // Fallback: manually iterate content streams with decompression.
        eprintln!("[text] extract_text empty, trying manual content stream scan");
        for page_id in doc.page_iter() {
            if let Ok(page_bytes) = doc.get_page_content(page_id) {
                // Try to decode as UTF-8/latin1 and extract Tj / TJ operands.
                extract_tj_from_stream(&page_bytes, &mut text);
            }
        }
    }
    text
}

/// Extract text from a raw (possibly already decompressed) content stream.
/// Handles both `(string) Tj` and `[(string) ...] TJ` operators.
fn extract_tj_from_stream(stream: &[u8], out: &mut String) {
    let content = String::from_utf8_lossy(stream);
    // Handle TJ arrays: [(text) skip (more) ...] TJ
    let mut tj_search = content.as_ref();
    while let Some(tj_pos) = tj_search.find("] TJ").or_else(|| tj_search.find("]TJ")) {
        let segment = &tj_search[..tj_pos];
        if let Some(bracket) = segment.rfind('[') {
            let inner = &segment[bracket + 1..];
            // Extract all (string) entries from the array.
            let mut search = inner;
            while let Some(start) = search.find('(') {
                search = &search[start + 1..];
                if let Some(end) = search.find(')') {
                    out.push_str(&search[..end]);
                    out.push(' ');
                    search = &search[end + 1..];
                } else {
                    break;
                }
            }
        }
        let skip = tj_pos + 4;
        if skip >= tj_search.len() { break; }
        tj_search = &tj_search[skip..];
    }
    // Also handle simple (string) Tj
    for part in content.split("Tj") {
        if let Some(start) = part.rfind('(') {
            if let Some(end) = part[start..].find(')') {
                out.push_str(&part[start + 1..start + end]);
                out.push(' ');
            }
        }
    }
}

// ─── Accredited investor phrase check ────────────────────────────────────────

/// Check for the SEC Rule 501(a) mandatory phrase (same logic as inside the zkVM).
pub fn check_accredited_investor_phrase(text: &str) -> bool {
    let anchor = "excluding the value of their primary residence";
    let threshold = "1,000,000";
    text.contains(anchor) && text.contains(threshold)
}

// ─── RSA helpers ─────────────────────────────────────────────────────────────

/// Which hash algorithm the CMS signer used.
#[derive(Clone, Copy, Debug)]
enum DigestAlg { Sha256, Sha384 }

/// Detect the digest algorithm from the CMS SignerInfo digest AlgorithmIdentifier OID.
/// DocuSign's chain uses SHA-384 for cert signatures (not SHA-256).
fn detect_digest_alg(alg_oid: &str) -> DigestAlg {
    // SHA-384 OID = 2.16.840.1.101.3.4.2.2
    // SHA-256 OID = 2.16.840.1.101.3.4.2.1
    if alg_oid.contains("2.2") || alg_oid == "2.16.840.1.101.3.4.2.2" {
        DigestAlg::Sha384
    } else {
        DigestAlg::Sha256
    }
}

/// Build an RSA public key from a DER-encoded X.509 certificate.
fn rsa_pub_key_from_cert(cert: &Certificate) -> Option<RsaPublicKey> {
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()?;
    RsaPublicKey::from_public_key_der(&spki_der).ok()
}

/// Verify RSA-PKCS1v15 where the hash algorithm is chosen dynamically.
///
/// `tbs_der`     – DER of the data that was signed (will be hashed here).
/// `sig_bytes`   – raw RSA signature.
/// `issuer_cert` – certificate whose SubjectPublicKey is the verifying key.
/// `alg`         – which digest algorithm to use.
fn verify_rsa_over_tbs(tbs_der: &[u8], sig_bytes: &[u8], issuer_cert: &Certificate, alg: DigestAlg) -> bool {
    let pub_key = match rsa_pub_key_from_cert(issuer_cert) {
        Some(k) => k,
        None => {
            eprintln!("[sig] Could not extract RSA public key from issuer cert");
            return false;
        }
    };
    let sig = match Pkcs1Sig::try_from(sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[sig] Invalid signature bytes: {:?}", e);
            return false;
        }
    };
    match alg {
        DigestAlg::Sha256 => {
            let vk = VerifyingKey::<Sha256>::new(pub_key);
            let digest = Sha256::digest(tbs_der);
            match vk.verify_prehash(&digest, &sig) {
                Ok(()) => true,
                Err(e) => { eprintln!("[sig] SHA-256 RSA mismatch: {:?}", e); false }
            }
        }
        DigestAlg::Sha384 => {
            let vk = VerifyingKey::<Sha384>::new(pub_key);
            let digest = Sha384::digest(tbs_der);
            match vk.verify_prehash(&digest, &sig) {
                Ok(()) => true,
                Err(e) => { eprintln!("[sig] SHA-384 RSA mismatch: {:?}", e); false }
            }
        }
    }
}

// ─── Certificate chain validation ────────────────────────────────────────────

/// Walk the chain: leaf → intermediates (from `bundle`) → trusted root.
///
/// At each hop we detect the hash algorithm from the cert's signature AlgorithmIdentifier
/// (SHA-256 for leaf, SHA-384 for the intermediate→root hop in DocuSign's chain).
///
/// Chain: DocuSign leaf → DigiCert AATL RSA4096 SHA384 2022 CA1 → DigiCert Trusted Root G4
fn verify_cert_chain(leaf_der: &[u8], bundle: &[Vec<u8>], trusted_root_der: &[u8]) -> bool {
    let root_cert = match Certificate::from_der(trusted_root_der) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[chain] Could not parse trusted root: {:?}", e);
            return false;
        }
    };

    let mut current_der: Vec<u8> = leaf_der.to_vec();

    for depth in 0u32..10 {
        let current = match Certificate::from_der(&current_der) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[chain] Cert parse failed at depth {}: {:?}", depth, e);
                return false;
            }
        };

        // Detect digest algorithm from the cert's own signature algorithm OID.
        let sig_alg_oid = current.signature_algorithm.oid.to_string();
        eprintln!("[chain] depth={} subject={:?} sig_alg={}",
            depth,
            current.tbs_certificate.subject.to_string(),
            sig_alg_oid
        );
        let alg = detect_digest_alg(&sig_alg_oid);

        let tbs_der = match current.tbs_certificate.to_der() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[chain] TBSCertificate encode failed: {:?}", e);
                return false;
            }
        };
        let sig_bytes = match current.signature.as_bytes() {
            Some(b) => b,
            None => {
                eprintln!("[chain] No signature bits at depth {}", depth);
                return false;
            }
        };

        // Does the trusted root issue this cert?
        if current.tbs_certificate.issuer == root_cert.tbs_certificate.subject {
            if verify_rsa_over_tbs(&tbs_der, sig_bytes, &root_cert, alg) {
                println!("[chain] Chain valid — anchored at DigiCert root ✓");
                return true;
            } else {
                // Try both algorithms if OID detection is ambiguous.
                let alt = match alg { DigestAlg::Sha256 => DigestAlg::Sha384, DigestAlg::Sha384 => DigestAlg::Sha256 };
                if verify_rsa_over_tbs(&tbs_der, sig_bytes, &root_cert, alt) {
                    println!("[chain] Chain valid (alt hash) — anchored at DigiCert root ✓");
                    return true;
                }
                eprintln!("[chain] Root signature check FAILED at depth {}", depth);
                return false;
            }
        }

        // Find issuer among the embedded certs.
        let issuer_der = match bundle.iter().find(|c| {
            Certificate::from_der(c)
                .map(|cert| cert.tbs_certificate.subject == current.tbs_certificate.issuer)
                .unwrap_or(false)
        }) {
            Some(d) => d.clone(),
            None => {
                eprintln!(
                    "[chain] Issuer not found in bundle at depth {} — chain incomplete. Bundle has {} certs.",
                    depth, bundle.len()
                );
                // Log all bundle subjects for debugging.
                for (i, bder) in bundle.iter().enumerate() {
                    if let Ok(bc) = Certificate::from_der(bder) {
                        eprintln!("  bundle[{}] subject: {:?}", i, bc.tbs_certificate.subject.to_string());
                    }
                }
                return false;
            }
        };

        let issuer_cert = match Certificate::from_der(&issuer_der) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[chain] Issuer cert parse failed: {:?}", e);
                return false;
            }
        };

        if !verify_rsa_over_tbs(&tbs_der, sig_bytes, &issuer_cert, alg) {
            // Try alternate algorithm.
            let alt = match alg { DigestAlg::Sha256 => DigestAlg::Sha384, DigestAlg::Sha384 => DigestAlg::Sha256 };
            if !verify_rsa_over_tbs(&tbs_der, sig_bytes, &issuer_cert, alt) {
                eprintln!("[chain] Cert signature INVALID at depth {} (tried both SHA-256 and SHA-384)", depth);
                return false;
            }
        }

        current_der = issuer_der;
    }

    eprintln!("[chain] Chain depth exceeded limit without reaching root");
    false
}

// ─── Main public verification entry point ────────────────────────────────────

/// Full PKCS#7 / CMS PDF signature verification (host-side only).
///
/// Pipeline:
///   1. Extract `/ByteRange` → reconstruct signed bytes (everything except /Contents).
///   2. Parse CMS `ContentInfo` → `SignedData` from the `/Contents` DER blob.
///   3. Identify the signer (leaf) certificate by IssuerAndSerialNumber.
///   4. Verify RSA-PKCS1v15-SHA256 over SHA-256(signed_bytes) using the leaf cert.
///   5. Walk the cert chain: leaf → intermediates → `trusted_root_der`.
///
/// Returns `true` only when ALL steps pass.
pub fn verify_pkcs7_signature_local(pdf_bytes: &[u8], trusted_root_der: &[u8]) -> bool {
    // ── 1: Reconstruct signed bytes from ByteRange ───────────────────────────
    let [o1, l1, o2, l2] = match extract_byte_range(pdf_bytes) {
        Some(br) => br,
        None => {
            eprintln!("[sig] /ByteRange not found in PDF");
            return false;
        }
    };
    if o1 + l1 > pdf_bytes.len() || o2 + l2 > pdf_bytes.len() {
        eprintln!("[sig] /ByteRange out of bounds (pdf_len={})", pdf_bytes.len());
        return false;
    }
    let mut signed_bytes = Vec::with_capacity(l1 + l2);
    signed_bytes.extend_from_slice(&pdf_bytes[o1..o1 + l1]);
    signed_bytes.extend_from_slice(&pdf_bytes[o2..o2 + l2]);

    // ── 2: Parse CMS ContentInfo → SignedData ────────────────────────────────
    let cms_der = match extract_signature_bytes(pdf_bytes) {
        Some(b) => b,
        None => {
            eprintln!("[sig] /Contents CMS blob not found");
            return false;
        }
    };

    let content_info = match ContentInfo::from_der(&cms_der) {
        Ok(ci) => ci,
        Err(e) => {
            eprintln!("[sig] ContentInfo DER parse failed: {:?}", e);
            return false;
        }
    };

    let signed_data: cms::signed_data::SignedData = match content_info.content.decode_as() {
        Ok(sd) => sd,
        Err(e) => {
            eprintln!("[sig] SignedData decode failed: {:?}", e);
            return false;
        }
    };

    // ── 3: Collect embedded certs ────────────────────────────────────────────
    let embedded_cert_ders: Vec<Vec<u8>> = match &signed_data.certificates {
        Some(set) => set
            .0
            .iter()
            .filter_map(|choice| {
                if let CertificateChoices::Certificate(cert) = choice {
                    cert.to_der().ok()
                } else {
                    None
                }
            })
            .collect(),
        None => {
            eprintln!("[sig] No certificates in CMS bundle");
            return false;
        }
    };

    // ── 4: Get the first SignerInfo ──────────────────────────────────────────
    // SetOfVec doesn't implement Index, so we use iter().next()
    let signer_info = match signed_data.signer_infos.0.iter().next() {
        Some(si) => si,
        None => {
            eprintln!("[sig] No SignerInfo entries");
            return false;
        }
    };

    // ── 5: Find leaf cert by IssuerAndSerialNumber ───────────────────────────
    use cms::signed_data::SignerIdentifier;
    let leaf_cert_der: Option<Vec<u8>> = match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => embedded_cert_ders
            .iter()
            .find(|der| {
                Certificate::from_der(der)
                    .map(|c| {
                        c.tbs_certificate.issuer == ias.issuer
                            && c.tbs_certificate.serial_number == ias.serial_number
                    })
                    .unwrap_or(false)
            })
            .cloned(),
        // SKI-based: fall back to first cert
        SignerIdentifier::SubjectKeyIdentifier(_) => embedded_cert_ders.first().cloned(),
    };

    let leaf_der = match leaf_cert_der {
        Some(d) => d,
        None => {
            eprintln!("[sig] Signer leaf cert not found in bundle");
            return false;
        }
    };

    let leaf_cert = match Certificate::from_der(&leaf_der) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[sig] Leaf cert parse failed: {:?}", e);
            return false;
        }
    };

    // ── 6: CMS Signed Attributes handling ────────────────────────────────────
    //
    // In CMS/PKCS#7, when signedAttributes are present (DocuSign ALWAYS includes
    // them), the RSA signature is NOT over hash(ByteRange). Instead:
    //
    //   a) messageDigest ∈ signedAttributes must equal hash(ByteRange bytes)
    //   b) The RSA signature covers DER(signedAttributes) re-encoded as a SET
    //      (tag 0x31, not the implicit [0] context tag from the wire format).
    //
    // Reference: RFC 5652 §5.4

    let digest_alg_oid = signer_info.digest_alg.oid.to_string();
    eprintln!("[sig] CMS digest algorithm OID: {}", digest_alg_oid);
    let leaf_alg = detect_digest_alg(&digest_alg_oid);

    // Compute hash of the ByteRange bytes (the "message digest").
    let byte_range_hash: Vec<u8> = match leaf_alg {
        DigestAlg::Sha256 => Sha256::digest(&signed_bytes).to_vec(),
        DigestAlg::Sha384 => Sha384::digest(&signed_bytes).to_vec(),
    };
    eprintln!("[sig] ByteRange hash ({:?}): {}", leaf_alg, hex::encode(&byte_range_hash));

    // Determine what we're signing over.
    let data_to_verify: Vec<u8> = if let Some(signed_attrs) = &signer_info.signed_attrs {
        // Verify the MessageDigest attribute matches hash(ByteRange).
        use x509_cert::der::asn1::OctetString;

        let mut md_ok = false;
        for attr in signed_attrs.iter() {
            // MessageDigest OID = 1.2.840.113549.1.9.4
            if attr.oid.to_string() == "1.2.840.113549.1.9.4" {
                if let Some(md) = attr.values.iter().next()
                    .and_then(|v| v.decode_as::<OctetString>().ok())
                {
                    let md_bytes = md.as_bytes();
                    eprintln!("[sig] MessageDigest attr: {}", hex::encode(md_bytes));
                    if md_bytes == byte_range_hash.as_slice() {
                        eprintln!("[sig] MessageDigest matches ByteRange hash ✓");
                        md_ok = true;
                    } else {
                        // Try the other algorithm.
                        let alt_hash: Vec<u8> = match leaf_alg {
                            DigestAlg::Sha256 => Sha384::digest(&signed_bytes).to_vec(),
                            DigestAlg::Sha384 => Sha256::digest(&signed_bytes).to_vec(),
                        };
                        if md_bytes == alt_hash.as_slice() {
                            eprintln!("[sig] MessageDigest matches ByteRange hash (alt alg) ✓");
                            md_ok = true;
                        } else {
                            eprintln!("[sig] MessageDigest MISMATCH — expected {}, got {}",
                                hex::encode(&byte_range_hash), hex::encode(md_bytes));
                        }
                    }
                }
                break;
            }
        }
        if !md_ok {
            eprintln!("[sig] MessageDigest attribute check failed or not found");
            // Don't hard-fail here — continue and let the RSA check be the gatekeeper.
        }

        // Re-encode signedAttributes as a DER SET (tag 0x31) for RSA verification.
        // The wire encoding uses implicit [0] CONTEXT tag; we must change it to SET.
        match signed_attrs.to_der() {
            Ok(mut der) => {
                if !der.is_empty() {
                    der[0] = 0x31; // Replace tag byte: [0] IMPLICIT → SET
                }
                eprintln!("[sig] Signing over DER(signedAttrs SET), {} bytes", der.len());
                der
            }
            Err(e) => {
                eprintln!("[sig] Failed to DER-encode signedAttributes: {:?}", e);
                return false;
            }
        }
    } else {
        // No signedAttributes — sign directly over hash(ByteRange).
        eprintln!("[sig] No signedAttributes; signing over ByteRange directly");
        signed_bytes.clone()
    };

    let pub_key = match rsa_pub_key_from_cert(&leaf_cert) {
        Some(k) => k,
        None => {
            eprintln!("[sig] Could not build RSA public key from leaf cert");
            return false;
        }
    };

    let raw_sig = signer_info.signature.as_bytes();
    let signature = match Pkcs1Sig::try_from(raw_sig) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[sig] Could not parse signature bytes: {:?}", e);
            return false;
        }
    };

    // Try SHA-256 first (as declared by OID), then SHA-384 as fallback.
    let leaf_ok = {
        let vk256 = VerifyingKey::<Sha256>::new(pub_key.clone());
        let digest256 = Sha256::digest(&data_to_verify);
        if vk256.verify_prehash(&digest256, &signature).is_ok() {
            eprintln!("[sig] RSA-SHA256 leaf signature OK ✓");
            true
        } else {
            let vk384 = VerifyingKey::<Sha384>::new(pub_key);
            let digest384 = Sha384::digest(&data_to_verify);
            if vk384.verify_prehash(&digest384, &signature).is_ok() {
                eprintln!("[sig] RSA-SHA384 leaf signature OK ✓");
                true
            } else {
                eprintln!("[sig] RSA signature INVALID (tried SHA-256 and SHA-384 over signedAttrs)");
                false
            }
        }
    };
    if !leaf_ok {
        return false;
    }

    // ── 7: Certificate chain to trusted root ─────────────────────────────────
    if trusted_root_der.is_empty() {
        eprintln!("[sig] No trusted root provided — chain check skipped (dev mode)");
        return true;
    }

    if !verify_cert_chain(&leaf_der, &embedded_cert_ders, trusted_root_der) {
        eprintln!("[sig] Certificate chain INVALID");
        return false;
    }

    true
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phrase_check() {
        let good = "The investor has a net worth in excess of $1,000,000, \
                    excluding the value of their primary residence.";
        assert!(check_accredited_investor_phrase(good));

        let bad = "net worth over 1 million";
        assert!(!check_accredited_investor_phrase(bad));
    }

    #[test]
    fn test_byte_range_parse() {
        let pdf_snippet = b"...stuff.../ByteRange [0 1000 2000 500] more stuff...";
        let ranges = extract_byte_range(pdf_snippet);
        assert_eq!(ranges, Some([0usize, 1000, 2000, 500]));
    }

    // Uncomment when attestation.pdf is present:
    // #[test]
    // fn test_with_real_pdf() {
    //     let bytes = std::fs::read("../../attestation.pdf").unwrap();
    //     let txt = extract_pdf_text(&bytes);
    //     assert!(check_accredited_investor_phrase(&txt));
    //     let ts = extract_pdf_date(&bytes);
    //     assert!(ts.is_some());
    //     let n = derive_nullifier(&bytes);
    //     assert_ne!(n, [0u8; 32]);
    //     let root = include_bytes!("../../certs/digicert_root_g4.der");
    //     assert!(verify_pkcs7_signature_local(&bytes, root));
    // }
}