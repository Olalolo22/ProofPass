//! Shared cryptographic PDF verification engine for ProofPass.
//!
//! Runs identically inside the SP1 RISC-V zkVM guest (`program`) and in host unit tests (`script`).
//!
//! Security guarantees enforced inside `verify_and_extract`:
//! 1. Verifies `/ByteRange [o1 l1 o2 l2]` directly at the hinted offset, ensures the gap `[o1+l1..o2]`
//!    contains ONLY the `<hex>` CMS `/Contents` signature blob, and hashes the exact signed bytes.
//! 2. Parses CMS `ContentInfo` -> `SignedData`, strictly enforces `messageDigest == hash(ByteRange)`
//!    (hard failure on mismatch), and extracts the cryptographically signed PKCS#7 `signingTime`
//!    (`doc_timestamp`) instead of relying on unsigned metadata or an untrusted prover clock.
//! 3. Verifies RSA PKCS#1 v1.5 over `DER(SET(signedAttrs))` against the signer's leaf X.509 cert
//!    and walks the full certificate chain to the compile-time embedded trusted Root CA.
//! 4. Verifies the hinted text stream slice lies strictly inside the signed `/ByteRange`, inflates
//!    `FlateDecode` streams if compressed, extracts `TJ`/`Tj` text, and checks the policy-specific
//!    required statutory wording.
//! 5. Emits a canonical 108-byte `CommittedPublicValues` layout matching Soroban `ZkInvestorGate`
//!    bit-for-bit.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use rsa::pkcs1v15::{Signature as Pkcs1Sig, VerifyingKey};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use x509_cert::der::asn1::{GeneralizedTime, OctetString, UtcTime};
use x509_cert::der::{Decode, Encode, Tag, Tagged};
use x509_cert::spki::DecodePublicKey;
use x509_cert::Certificate;

pub const POLICY_ACCREDITED_INVESTOR: u32 = 1;
pub const POLICY_LICENSED_PHARMACIST: u32 = 2;

/// Untrusted byte-offset hints supplied by the host so the zkVM guest avoids O(N) scanning over
/// a 200+ KB PDF. Every hint is cryptographically checked against `pdf_bytes` and `/ByteRange`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofHints {
    /// Offset of `/ByteRange` inside `pdf_bytes`.
    pub byte_range_offset: u32,
    /// Offset of the first hex character inside `/Contents <...>` (strictly after `<`).
    pub contents_hex_offset: u32,
    /// Number of hex characters inside `<...>` (even length).
    pub contents_hex_len: u32,
    /// Offset of the raw PDF text stream bytes (immediately after `stream\r?\n`) inside signed `/ByteRange`.
    pub text_stream_offset: u32,
    /// Byte length of the raw text stream bytes (before `endstream`).
    pub text_stream_len: u32,
    /// True if the text stream is zlib (`FlateDecode`) compressed.
    pub text_compressed: bool,
}

/// Canonical 108-byte public output committed by SP1 (`io::commit_slice`) and reconstructed by
/// Soroban `ZkInvestorGate::encode_committed_values`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedPublicValues {
    pub wallet_hash: [u8; 32],
    pub policy_id: u32,
    pub issuer_hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub doc_timestamp: u64,
}

impl CommittedPublicValues {
    pub const BYTE_LEN: usize = 108;

    pub fn to_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut out = [0u8; Self::BYTE_LEN];
        out[0..32].copy_from_slice(&self.wallet_hash);
        out[32..36].copy_from_slice(&self.policy_id.to_le_bytes());
        out[36..68].copy_from_slice(&self.issuer_hash);
        out[68..100].copy_from_slice(&self.nullifier);
        out[100..108].copy_from_slice(&self.doc_timestamp.to_le_bytes());
        out
    }

    /// SP1 BN254 Groth16 committed values digest: `sha256(committed) & ((1 << 253) - 1)`.
    pub fn sp1_digest(&self) -> [u8; 32] {
        let mut digest: [u8; 32] = Sha256::digest(self.to_bytes()).into();
        digest[0] &= 0x1F;
        digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    UnsupportedPolicy,
    UnsupportedDigestAlgorithm,
    InvalidByteRangeHint,
    InvalidByteRangeBounds,
    InvalidContentsHint,
    InvalidContentsGap,
    InvalidHexContents,
    CmsParseFailed,
    SignedDataDecodeFailed,
    MissingCertificates,
    MissingSignerInfo,
    LeafCertNotFound,
    LeafCertParseFailed,
    MissingSignedAttributes,
    MessageDigestMissingOrMismatch,
    SigningTimeMissingOrInvalid,
    SignedAttrsEncodeFailed,
    LeafPublicKeyInvalid,
    LeafSignatureInvalid,
    CertChainInvalid,
    TextStreamOutsideByteRange,
    InvalidTextStreamBoundaries,
    TextStreamDecompressFailed,
    PolicyPhraseNotFound,
    InvalidStellarAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DigestAlg {
    Sha256,
    Sha384,
}

fn detect_digest_alg(alg_oid: &str) -> Option<DigestAlg> {
    match alg_oid {
        // SHA-256 digest OID / sha256WithRSAEncryption OID
        "2.16.840.1.101.3.4.2.1" | "1.2.840.113549.1.1.11" => Some(DigestAlg::Sha256),
        // SHA-384 digest OID / sha384WithRSAEncryption OID
        "2.16.840.1.101.3.4.2.2" | "1.2.840.113549.1.1.12" => Some(DigestAlg::Sha384),
        _ => None,
    }
}

/// Core in-guest verification routine.
///
/// Validates the full PDF cryptographic signature, X.509 chain to at least one compile-time
/// embedded root in `trusted_roots`, signed `signingTime`, and signed text stream phrase for
/// `policy_id`.
pub fn verify_and_extract(
    pdf_bytes: &[u8],
    hints: ProofHints,
    policy_id: u32,
    wallet_hash: [u8; 32],
    trusted_roots: &[&[u8]],
) -> Result<CommittedPublicValues, VerifyError> {
    if policy_id != POLICY_ACCREDITED_INVESTOR && policy_id != POLICY_LICENSED_PHARMACIST {
        return Err(VerifyError::UnsupportedPolicy);
    }

    // 1. Parse and verify `/ByteRange [o1 l1 o2 l2]` directly at `hints.byte_range_offset`.
    let [o1, l1, o2, l2] = parse_byte_range_at(pdf_bytes, hints.byte_range_offset as usize)?;
    if o1 != 0 || l1 == 0 || o1.checked_add(l1).map_or(true, |end1| end1 >= o2) {
        return Err(VerifyError::InvalidByteRangeBounds);
    }
    let end1 = o1 + l1;
    let end2 = o2
        .checked_add(l2)
        .ok_or(VerifyError::InvalidByteRangeBounds)?;
    if end2 > pdf_bytes.len() {
        return Err(VerifyError::InvalidByteRangeBounds);
    }

    // 2. Verify `/Contents <hex>` sits cleanly inside the unsigned gap `[end1..o2]`
    //    with only `<`, `>`, or ASCII whitespace surrounding the hex bytes.
    let hex_start = hints.contents_hex_offset as usize;
    let hex_len = hints.contents_hex_len as usize;
    let hex_end = hex_start
        .checked_add(hex_len)
        .ok_or(VerifyError::InvalidContentsHint)?;
    if hex_len < 64 || hex_len % 2 != 0 || hex_start < end1 || hex_end > o2 {
        return Err(VerifyError::InvalidContentsHint);
    }
    verify_gap_delimiters(&pdf_bytes[end1..hex_start], b'<')?;
    verify_gap_delimiters(&pdf_bytes[hex_end..o2], b'>')?;

    let cms_der = decode_trimmed_hex(&pdf_bytes[hex_start..hex_end])?;

    // 3. Verify the hinted text stream lies strictly inside one of the two signed ByteRange spans
    //    AND aligns with genuine PDF `stream`/`endstream` boundaries (so a prover cannot cherry-pick
    //    an arbitrary substring inside a signed uncompressed stream).
    let text_start = hints.text_stream_offset as usize;
    let text_len = hints.text_stream_len as usize;
    let text_end = text_start
        .checked_add(text_len)
        .ok_or(VerifyError::TextStreamOutsideByteRange)?;
    let in_first = text_start >= o1 && text_end <= end1;
    let in_second = text_start >= o2 && text_end <= end2;
    if text_len == 0 || (!in_first && !in_second) {
        return Err(VerifyError::TextStreamOutsideByteRange);
    }
    let (span_start, span_end) = if in_first { (o1, end1) } else { (o2, end2) };
    verify_stream_boundaries(pdf_bytes, span_start, span_end, text_start, text_end)?;

    // 4. Parse CMS ContentInfo -> SignedData.
    let content_info =
        ContentInfo::from_der(&cms_der).map_err(|_| VerifyError::CmsParseFailed)?;
    let signed_data: SignedData = content_info
        .content
        .decode_as()
        .map_err(|_| VerifyError::SignedDataDecodeFailed)?;

    let embedded_cert_ders: Vec<Vec<u8>> = match &signed_data.certificates {
        Some(set) => set
            .0
            .iter()
            .filter_map(|choice| match choice {
                CertificateChoices::Certificate(cert) => cert.to_der().ok(),
                _ => None,
            })
            .collect(),
        None => return Err(VerifyError::MissingCertificates),
    };
    if embedded_cert_ders.is_empty() {
        return Err(VerifyError::MissingCertificates);
    }

    let signer_info = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(VerifyError::MissingSignerInfo)?;

    // 5. Identify signer leaf certificate & compute `issuer_hash = SHA-256(leaf_cert_der)`.
    let leaf_der = find_leaf_cert(&signer_info.sid, &embedded_cert_ders)
        .ok_or(VerifyError::LeafCertNotFound)?;
    let leaf_cert =
        Certificate::from_der(&leaf_der).map_err(|_| VerifyError::LeafCertParseFailed)?;
    let issuer_hash: [u8; 32] = Sha256::digest(&leaf_der).into();

    // 6. Strictly verify signedAttrs: messageDigest MUST match hash(ByteRange),
    //    and signingTime MUST be present and valid.
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or(VerifyError::MissingSignedAttributes)?;

    let digest_alg_oid = signer_info.digest_alg.oid.to_string();
    let leaf_alg =
        detect_digest_alg(&digest_alg_oid).ok_or(VerifyError::UnsupportedDigestAlgorithm)?;
    let byte_range_hash = hash_byte_range(&pdf_bytes[o1..end1], &pdf_bytes[o2..end2], leaf_alg);

    let mut md_verified = false;
    let mut doc_timestamp: Option<u64> = None;

    for attr in signed_attrs.iter() {
        let oid = attr.oid.to_string();
        if oid == "1.2.840.113549.1.9.4" {
            // id-messageDigest
            if let Some(val) = attr.values.iter().next() {
                if let Ok(md) = val.decode_as::<OctetString>() {
                    if md.as_bytes() == byte_range_hash.as_slice() {
                        md_verified = true;
                    }
                }
            }
        } else if oid == "1.2.840.113549.1.9.5" {
            // id-signingTime (UTCTime or GeneralizedTime, covered by RSA signature)
            if let Some(val) = attr.values.iter().next() {
                doc_timestamp = parse_cms_signing_time(val);
            }
        }
    }

    if !md_verified {
        return Err(VerifyError::MessageDigestMissingOrMismatch);
    }
    let doc_timestamp = doc_timestamp.ok_or(VerifyError::SigningTimeMissingOrInvalid)?;

    // 7. Verify RSA PKCS#1 v1.5 signature over DER(SET(signedAttrs)) per RFC 5652 §5.4.
    let mut signed_attrs_set_der = signed_attrs
        .to_der()
        .map_err(|_| VerifyError::SignedAttrsEncodeFailed)?;
    if signed_attrs_set_der.is_empty() {
        return Err(VerifyError::SignedAttrsEncodeFailed);
    }
    signed_attrs_set_der[0] = 0x31; // Replace implicit [0] tag with EXPLICIT SET tag

    let raw_sig = signer_info.signature.as_bytes();
    if !verify_rsa_over_tbs(&signed_attrs_set_der, raw_sig, &leaf_cert, leaf_alg) {
        return Err(VerifyError::LeafSignatureInvalid);
    }

    // 8. Verify full X.509 certificate chain to at least one compile-time embedded trusted Root CA.
    let chain_ok = trusted_roots
        .iter()
        .any(|root_der| verify_cert_chain(&leaf_der, &embedded_cert_ders, root_der));
    if !chain_ok {
        return Err(VerifyError::CertChainInvalid);
    }

    // 9. Decompress (if needed) and extract visible text from the verified signed text stream,
    //    then enforce the policy-specific required wording.
    let raw_text_slice = &pdf_bytes[text_start..text_end];
    let decompressed;
    let stream_bytes: &[u8] = if hints.text_compressed {
        decompressed = miniz_oxide::inflate::decompress_to_vec_zlib(raw_text_slice)
            .map_err(|_| VerifyError::TextStreamDecompressFailed)?;
        &decompressed
    } else {
        raw_text_slice
    };

    let extracted_text = extract_pdf_stream_text(stream_bytes);
    if !check_policy_phrase(&extracted_text, policy_id) {
        return Err(VerifyError::PolicyPhraseNotFound);
    }

    // 10. Deterministic nullifier = SHA-256(trimmed CMS DER blob).
    let nullifier: [u8; 32] = Sha256::digest(&cms_der).into();

    Ok(CommittedPublicValues {
        wallet_hash,
        policy_id,
        issuer_hash,
        nullifier,
        doc_timestamp,
    })
}

/// Checks policy-specific statutory wording in extracted PDF text.
pub fn check_policy_phrase(text: &str, policy_id: u32) -> bool {
    let lower = text.to_ascii_lowercase();
    match policy_id {
        POLICY_ACCREDITED_INVESTOR => {
            lower.contains("excluding the value of their primary residence")
                && lower.contains("1,000,000")
        }
        POLICY_LICENSED_PHARMACIST => {
            lower.contains("licensed pharmacist") && lower.contains("good standing")
        }
        _ => false,
    }
}

/// Decode a Stellar G-account StrKey (`G...`, 56 chars) into the exact 32-byte `wallet_hash`
/// (`sha256(ScVal::Address(Account(Ed25519(pubkey))))`) computed by Soroban's `Address::to_xdr`.
pub fn stellar_g_address_to_wallet_hash(g_address: &str) -> Result<[u8; 32], VerifyError> {
    let bytes = base32_decode(g_address.trim()).ok_or(VerifyError::InvalidStellarAddress)?;
    // Stellar G-account StrKey = 1 version byte (6 << 3 = 48) + 32 pubkey bytes + 2 CRC16-XMODEM LE bytes
    if bytes.len() != 35 || bytes[0] != (6u8 << 3) {
        return Err(VerifyError::InvalidStellarAddress);
    }
    let expected_crc = crc16_xmodem(&bytes[..33]);
    let actual_crc = u16::from_le_bytes([bytes[33], bytes[34]]);
    if expected_crc != actual_crc {
        return Err(VerifyError::InvalidStellarAddress);
    }

    // Canonical 44-byte Soroban XDR for ScVal::Address(ScAddress::Account(PublicKey::Ed25519(pubkey)))
    let mut xdr = [0u8; 44];
    xdr[3] = 18; // ScValType::ScvAddress
    xdr[12..44].copy_from_slice(&bytes[1..33]);
    Ok(Sha256::digest(xdr).into())
}

/// Host helper: locate exact `ProofHints` for a signed PDF so the zkVM guest skips O(N) scanning.
pub fn compute_hints(pdf_bytes: &[u8], policy_id: u32) -> Result<ProofHints, VerifyError> {
    let byte_range_offset =
        find_subsequence(pdf_bytes, b"/ByteRange").ok_or(VerifyError::InvalidByteRangeHint)?;
    let [o1, l1, o2, l2] = parse_byte_range_at(pdf_bytes, byte_range_offset)?;
    let end1 = o1
        .checked_add(l1)
        .ok_or(VerifyError::InvalidByteRangeBounds)?;
    let end2 = o2
        .checked_add(l2)
        .ok_or(VerifyError::InvalidByteRangeBounds)?;
    if o1 != 0 || end1 >= o2 || end2 > pdf_bytes.len() {
        return Err(VerifyError::InvalidByteRangeBounds);
    }

    // Locate `<hex>` strictly inside the gap `[end1..o2]`.
    let gap = &pdf_bytes[end1..o2];
    let lt = gap
        .iter()
        .position(|&b| b == b'<')
        .ok_or(VerifyError::InvalidContentsGap)?;
    let gt = gap[lt + 1..]
        .iter()
        .position(|&b| b == b'>')
        .ok_or(VerifyError::InvalidContentsGap)?;
    let contents_hex_offset = end1 + lt + 1;
    let contents_hex_len = gt;

    // Locate the signed stream containing the policy phrase (try compressed FlateDecode streams
    // first, then raw uncompressed streams inside `[o1..end1]` and `[o2..end2]`).
    let signed_spans = [(o1, end1), (o2, end2)];
    for (span_start, span_end) in signed_spans {
        let mut cursor = span_start;
        while cursor < span_end {
            let Some(rel) = find_subsequence(&pdf_bytes[cursor..span_end], b"stream") else {
                break;
            };
            let s_pos = cursor + rel;
            let after_kw = s_pos + 6;
            // PDF spec: `stream` keyword must be followed by `\r\n` or `\n` (not `endstream`).
            let is_endstream = s_pos >= 3 && &pdf_bytes[s_pos - 3..s_pos] == b"end";
            if is_endstream {
                cursor = after_kw;
                continue;
            }
            let data_start = if pdf_bytes.get(after_kw..after_kw + 2) == Some(b"\r\n") {
                after_kw + 2
            } else if pdf_bytes.get(after_kw) == Some(&b'\n') {
                after_kw + 1
            } else {
                cursor = after_kw;
                continue;
            };
            let Some(end_rel) = find_subsequence(&pdf_bytes[data_start..span_end], b"endstream")
            else {
                break;
            };
            let mut data_end = data_start + end_rel;
            // Strip single trailing EOL before `endstream` per PDF spec.
            if data_end > data_start && pdf_bytes[data_end - 1] == b'\n' {
                data_end -= 1;
                if data_end > data_start && pdf_bytes[data_end - 1] == b'\r' {
                    data_end -= 1;
                }
            }
            let slice = &pdf_bytes[data_start..data_end];
            if !slice.is_empty() {
                if let Ok(dec) = miniz_oxide::inflate::decompress_to_vec_zlib(slice) {
                    let txt = extract_pdf_stream_text(&dec);
                    if check_policy_phrase(&txt, policy_id) {
                        return Ok(ProofHints {
                            byte_range_offset: byte_range_offset as u32,
                            contents_hex_offset: contents_hex_offset as u32,
                            contents_hex_len: contents_hex_len as u32,
                            text_stream_offset: data_start as u32,
                            text_stream_len: (data_end - data_start) as u32,
                            text_compressed: true,
                        });
                    }
                }
                let raw_txt = extract_pdf_stream_text(slice);
                if check_policy_phrase(&raw_txt, policy_id) {
                    return Ok(ProofHints {
                        byte_range_offset: byte_range_offset as u32,
                        contents_hex_offset: contents_hex_offset as u32,
                        contents_hex_len: contents_hex_len as u32,
                        text_stream_offset: data_start as u32,
                        text_stream_len: (data_end - data_start) as u32,
                        text_compressed: false,
                    });
                }
            }
            cursor = data_start + end_rel + 9;
        }
    }

    Err(VerifyError::PolicyPhraseNotFound)
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

fn parse_byte_range_at(pdf_bytes: &[u8], offset: usize) -> Result<[usize; 4], VerifyError> {
    let marker = b"/ByteRange";
    if offset + marker.len() > pdf_bytes.len()
        || &pdf_bytes[offset..offset + marker.len()] != marker
    {
        return Err(VerifyError::InvalidByteRangeHint);
    }
    let window_end = (offset + 128).min(pdf_bytes.len());
    let rest = &pdf_bytes[offset + marker.len()..window_end];
    let b_start = rest
        .iter()
        .position(|&b| b == b'[')
        .ok_or(VerifyError::InvalidByteRangeHint)?;
    let b_end = rest[b_start..]
        .iter()
        .position(|&b| b == b']')
        .ok_or(VerifyError::InvalidByteRangeHint)?;
    let inner = core::str::from_utf8(&rest[b_start + 1..b_start + b_end])
        .map_err(|_| VerifyError::InvalidByteRangeHint)?;
    let nums: Vec<usize> = inner
        .split_whitespace()
        .filter_map(|tok| tok.parse::<usize>().ok())
        .collect();
    if nums.len() == 4 {
        Ok([nums[0], nums[1], nums[2], nums[3]])
    } else {
        Err(VerifyError::InvalidByteRangeHint)
    }
}

fn verify_gap_delimiters(slice: &[u8], expected_delim: u8) -> Result<(), VerifyError> {
    let mut found = false;
    for &b in slice {
        if b == expected_delim && !found {
            found = true;
        } else if !b.is_ascii_whitespace() {
            return Err(VerifyError::InvalidContentsGap);
        }
    }
    if found {
        Ok(())
    } else {
        Err(VerifyError::InvalidContentsGap)
    }
}

/// Ensures `[text_start..text_end]` spans an entire PDF `stream ... endstream` object inside the
/// verified signed ByteRange span `[span_start..span_end]`, preventing a prover from slicing out a
/// misleading substring of an uncompressed signed stream.
fn verify_stream_boundaries(
    pdf_bytes: &[u8],
    span_start: usize,
    span_end: usize,
    text_start: usize,
    text_end: usize,
) -> Result<(), VerifyError> {
    let prefix_ok = if text_start >= span_start + 8
        && &pdf_bytes[text_start - 8..text_start] == b"stream\r\n"
    {
        let kw_pos = text_start - 8;
        !(kw_pos >= 3 && &pdf_bytes[kw_pos - 3..kw_pos] == b"end")
    } else if text_start >= span_start + 7 && &pdf_bytes[text_start - 7..text_start] == b"stream\n"
    {
        let kw_pos = text_start - 7;
        !(kw_pos >= 3 && &pdf_bytes[kw_pos - 3..kw_pos] == b"end")
    } else {
        false
    };
    if !prefix_ok {
        return Err(VerifyError::InvalidTextStreamBoundaries);
    }

    let suffix_start = if text_end + 2 <= span_end && &pdf_bytes[text_end..text_end + 2] == b"\r\n" {
        text_end + 2
    } else if text_end + 1 <= span_end && pdf_bytes[text_end] == b'\n' {
        text_end + 1
    } else {
        text_end
    };
    if suffix_start + 9 > span_end || &pdf_bytes[suffix_start..suffix_start + 9] != b"endstream" {
        return Err(VerifyError::InvalidTextStreamBoundaries);
    }
    Ok(())
}

fn decode_trimmed_hex(hex_bytes: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let mut out = Vec::with_capacity(hex_bytes.len() / 2);
    for pair in hex_bytes.chunks_exact(2) {
        let hi = from_hex_digit(pair[0]).ok_or(VerifyError::InvalidHexContents)?;
        let lo = from_hex_digit(pair[1]).ok_or(VerifyError::InvalidHexContents)?;
        out.push((hi << 4) | lo);
    }
    let trimmed_len = out
        .iter()
        .rposition(|&b| b != 0)
        .map(|p| p + 1)
        .unwrap_or(0);
    if trimmed_len <= 32 {
        return Err(VerifyError::InvalidHexContents);
    }
    out.truncate(trimmed_len);
    Ok(out)
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
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn hash_byte_range(part1: &[u8], part2: &[u8], alg: DigestAlg) -> Vec<u8> {
    match alg {
        DigestAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(part1);
            h.update(part2);
            h.finalize().to_vec()
        }
        DigestAlg::Sha384 => {
            let mut h = Sha384::new();
            h.update(part1);
            h.update(part2);
            h.finalize().to_vec()
        }
    }
}

fn find_leaf_cert(sid: &SignerIdentifier, bundle: &[Vec<u8>]) -> Option<Vec<u8>> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => bundle
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
        SignerIdentifier::SubjectKeyIdentifier(_) => bundle.first().cloned(),
    }
}

fn parse_cms_signing_time(val: &x509_cert::der::Any) -> Option<u64> {
    match val.tag() {
        Tag::UtcTime => {
            let utc = val.decode_as::<UtcTime>().ok()?;
            Some(utc.to_unix_duration().as_secs())
        }
        Tag::GeneralizedTime => {
            let gt = val.decode_as::<GeneralizedTime>().ok()?;
            Some(gt.to_unix_duration().as_secs())
        }
        _ => None,
    }
}

fn rsa_pub_key_from_cert(cert: &Certificate) -> Option<RsaPublicKey> {
    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der().ok()?;
    RsaPublicKey::from_public_key_der(&spki_der).ok()
}

fn verify_rsa_over_tbs(
    tbs_der: &[u8],
    sig_bytes: &[u8],
    issuer_cert: &Certificate,
    alg: DigestAlg,
) -> bool {
    let Some(pub_key) = rsa_pub_key_from_cert(issuer_cert) else {
        return false;
    };
    let Ok(sig) = Pkcs1Sig::try_from(sig_bytes) else {
        return false;
    };
    match alg {
        DigestAlg::Sha256 => {
            let vk = VerifyingKey::<Sha256>::new(pub_key);
            let digest = Sha256::digest(tbs_der);
            vk.verify_prehash(&digest, &sig).is_ok()
        }
        DigestAlg::Sha384 => {
            let vk = VerifyingKey::<Sha384>::new(pub_key);
            let digest = Sha384::digest(tbs_der);
            vk.verify_prehash(&digest, &sig).is_ok()
        }
    }
}

fn verify_cert_chain(leaf_der: &[u8], bundle: &[Vec<u8>], trusted_root_der: &[u8]) -> bool {
    let Ok(root_cert) = Certificate::from_der(trusted_root_der) else {
        return false;
    };

    let mut current_der = leaf_der.to_vec();
    for _depth in 0u32..8 {
        let Ok(current) = Certificate::from_der(&current_der) else {
            return false;
        };

        // Direct match if the leaf itself is the trusted root (e.g., self-signed test CA).
        if current_der == trusted_root_der {
            return true;
        }

        let Some(alg) = detect_digest_alg(&current.signature_algorithm.oid.to_string()) else {
            return false;
        };
        let Ok(tbs_der) = current.tbs_certificate.to_der() else {
            return false;
        };
        let Some(sig_bytes) = current.signature.as_bytes() else {
            return false;
        };

        if current.tbs_certificate.issuer == root_cert.tbs_certificate.subject {
            return verify_rsa_over_tbs(&tbs_der, sig_bytes, &root_cert, alg);
        }

        let Some(issuer_der) = bundle.iter().find(|c| {
            Certificate::from_der(c)
                .map(|cert| cert.tbs_certificate.subject == current.tbs_certificate.issuer)
                .unwrap_or(false)
        }) else {
            return false;
        };

        let Ok(issuer_cert) = Certificate::from_der(issuer_der) else {
            return false;
        };
        if !verify_rsa_over_tbs(&tbs_der, sig_bytes, &issuer_cert, alg) {
            return false;
        }
        current_der = issuer_der.clone();
    }
    false
}

/// Extract readable text from a PDF content stream (handles both `[(a)-7(b)] TJ` kerning arrays
/// and `(hello) Tj` strings cleanly without injecting bogus spaces mid-word).
pub fn extract_pdf_stream_text(stream: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    let len = stream.len();

    while i < len {
        match stream[i] {
            b'[' => {
                // Parse TJ array: concatenate all literal `(...)` chunks directly,
                // inserting a space only on large negative kerning adjustments (< -150).
                i += 1;
                let mut had_text = false;
                while i < len && stream[i] != b']' {
                    if stream[i] == b'(' {
                        i = read_pdf_literal_string(stream, i, &mut out);
                        had_text = true;
                    } else if stream[i] == b'-' || stream[i].is_ascii_digit() {
                        let num_start = i;
                        i += 1;
                        while i < len
                            && (stream[i].is_ascii_digit() || stream[i] == b'.')
                        {
                            i += 1;
                        }
                        if let Ok(s) = core::str::from_utf8(&stream[num_start..i]) {
                            if let Ok(val) = s.parse::<f32>() {
                                if val <= -180.0 && !out.ends_with(' ') {
                                    out.push(' ');
                                }
                            }
                        }
                    } else {
                        i += 1;
                    }
                }
                if had_text && !out.ends_with(' ') {
                    out.push(' ');
                }
                if i < len && stream[i] == b']' {
                    i += 1;
                }
            }
            b'(' => {
                i = read_pdf_literal_string(stream, i, &mut out);
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            _ => i += 1,
        }
    }
    out
}

fn read_pdf_literal_string(stream: &[u8], start_paren: usize, out: &mut String) -> usize {
    let mut i = start_paren + 1;
    let mut depth = 1u32;
    while i < stream.len() && depth > 0 {
        let b = stream[i];
        if b == b'\\' && i + 1 < stream.len() {
            let next = stream[i + 1];
            match next {
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'(' | b')' | b'\\' => out.push(next as char),
                _ => out.push(next as char),
            }
            i += 2;
        } else if b == b'(' {
            depth += 1;
            out.push('(');
            i += 1;
        } else if b == b')' {
            depth -= 1;
            if depth > 0 {
                out.push(')');
            }
            i += 1;
        } else {
            if b.is_ascii() {
                out.push(b as char);
            }
            i += 1;
        }
    }
    i
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;
    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'2'..=b'7' => (b - b'2' + 26) as u32,
            b'=' => break,
            _ => return None,
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGICERT_ROOT_G4: &[u8] = include_bytes!("../../certs/digicert_root_g4.der");
    const TESTNET_MOCK_PHARMACY_ROOT: &[u8] =
        include_bytes!("../../certs/testnet_mock_pharmacy_root.der");

    #[test]
    fn test_real_docusign_attestation_pdf_full_crypto_verification() {
        let pdf = std::fs::read("../script/attestation.pdf")
            .expect("attestation.pdf must exist in script/");
        let hints = compute_hints(&pdf, POLICY_ACCREDITED_INVESTOR)
            .expect("compute_hints should locate ByteRange, Contents, and FlateDecode text stream");

        assert!(hints.text_compressed, "attestation.pdf text stream is FlateDecode");
        let wallet_hash = stellar_g_address_to_wallet_hash(
            "GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P",
        )
        .expect("valid Stellar G-account");

        let committed = verify_and_extract(
            &pdf,
            hints,
            POLICY_ACCREDITED_INVESTOR,
            wallet_hash,
            &[DIGICERT_ROOT_G4],
        )
        .expect("Real DocuSign attestation.pdf MUST pass full RSA + X.509 + ByteRange + signingTime verification");

        assert_eq!(committed.policy_id, POLICY_ACCREDITED_INVESTOR);
        assert_eq!(committed.wallet_hash, wallet_hash);
        // Exact signed PKCS#7 signingTime: Jun 26 23:26:07 2026 GMT
        assert_eq!(committed.doc_timestamp, 1_782_516_367);
        // Exact DocuSign leaf cert SHA-256
        assert_eq!(
            hex::encode(committed.issuer_hash),
            "3da288f764431cb9c5898ccf3028f5f295bfb5f1ee7045a1f42c7cecdcf09600"
        );
        // Exact deterministic CMS nullifier
        assert_eq!(
            hex::encode(committed.nullifier),
            "1d345891df3edb8c58ac57900cf6c781912c5dec0684e0a65c3b0e5d25a706d4"
        );
        assert_eq!(committed.to_bytes().len(), 108);
    }

    #[test]
    fn test_mock_pharmacist_pdfs_full_crypto_verification_and_distinct_nullifiers() {
        let wallet_hash = stellar_g_address_to_wallet_hash(
            "GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P",
        )
        .unwrap();

        let paths = [
            "../script/pharmacist_license_mock.pdf",
            "../script/fixtures/pharmacist_license_mock_video.pdf",
            "../script/fixtures/pharmacist_license_mock_stage.pdf",
        ];

        let mut nullifiers = Vec::new();
        let mut shared_issuer_hash = None;

        for path in paths {
            let pdf = std::fs::read(path).unwrap_or_else(|e| panic!("missing {}: {}", path, e));
            let hints = compute_hints(&pdf, POLICY_LICENSED_PHARMACIST)
                .expect("compute_hints should locate pharmacist FlateDecode stream");
            assert!(hints.text_compressed);

            let committed = verify_and_extract(
                &pdf,
                hints,
                POLICY_LICENSED_PHARMACIST,
                wallet_hash,
                &[DIGICERT_ROOT_G4, TESTNET_MOCK_PHARMACY_ROOT],
            )
            .expect("Testnet mock pharmacist PDF must pass full RSA + X.509 + ByteRange verification");

            assert_eq!(committed.policy_id, POLICY_LICENSED_PHARMACIST);
            assert_eq!(committed.wallet_hash, wallet_hash);
            assert!(committed.doc_timestamp > 1_700_000_000);
            if let Some(prev) = shared_issuer_hash {
                assert_eq!(committed.issuer_hash, prev);
            } else {
                shared_issuer_hash = Some(committed.issuer_hash);
            }
            assert!(!nullifiers.contains(&committed.nullifier));
            nullifiers.push(committed.nullifier);
        }
        assert_eq!(nullifiers.len(), 3);
    }

    #[test]
    fn test_mock_pharmacist_pdf_rejected_for_accredited_investor_policy() {
        let pdf = std::fs::read("../script/pharmacist_license_mock.pdf").unwrap();
        let hints = compute_hints(&pdf, POLICY_LICENSED_PHARMACIST).unwrap();

        // Policy 1 only trusts production DigiCert Root G4 — mock pharmacy CA MUST fail!
        let err = verify_and_extract(
            &pdf,
            hints,
            POLICY_ACCREDITED_INVESTOR,
            [0x11u8; 32],
            &[DIGICERT_ROOT_G4],
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::CertChainInvalid);
    }

    #[test]
    fn test_text_stream_mid_slice_bypass_rejected() {
        let pdf = std::fs::read("../script/attestation.pdf").unwrap();
        let mut hints = compute_hints(&pdf, POLICY_ACCREDITED_INVESTOR).unwrap();
        // Shift offset by +1 byte inside signed ByteRange so it no longer aligns with `stream\n`
        hints.text_stream_offset += 1;
        hints.text_stream_len -= 1;

        let err = verify_and_extract(
            &pdf,
            hints,
            POLICY_ACCREDITED_INVESTOR,
            [0x11u8; 32],
            &[DIGICERT_ROOT_G4],
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::InvalidTextStreamBoundaries);
    }

    #[test]
    fn test_tampered_pdf_byte_fails_message_digest_check() {
        let mut pdf = std::fs::read("../script/attestation.pdf").unwrap();
        let hints = compute_hints(&pdf, POLICY_ACCREDITED_INVESTOR).unwrap();
        // Flip 1 byte inside signed ByteRange
        pdf[10] ^= 0x01;

        let err = verify_and_extract(
            &pdf,
            hints,
            POLICY_ACCREDITED_INVESTOR,
            [0x11u8; 32],
            &[DIGICERT_ROOT_G4],
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::MessageDigestMissingOrMismatch);
    }

    #[test]
    fn test_corrupted_rsa_signature_fails_leaf_signature_check() {
        let mut pdf = std::fs::read("../script/attestation.pdf").unwrap();
        let hints = compute_hints(&pdf, POLICY_ACCREDITED_INVESTOR).unwrap();
        // Flip one hex character near the end of the non-zero CMS signature bytes (inside RSA signature value)
        let sig_region = hints.contents_hex_offset as usize + (5979 * 2) - 20;
        pdf[sig_region] = if pdf[sig_region] == b'0' { b'1' } else { b'0' };

        let err = verify_and_extract(
            &pdf,
            hints,
            POLICY_ACCREDITED_INVESTOR,
            [0x11u8; 32],
            &[DIGICERT_ROOT_G4],
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::LeafSignatureInvalid);
    }

    #[test]
    fn test_wrong_policy_rejected_on_accredited_investor_pdf() {
        let pdf = std::fs::read("../script/attestation.pdf").unwrap();
        // Hints from policy 1 passed with policy 2 -> must fail phrase check
        let hints = compute_hints(&pdf, POLICY_ACCREDITED_INVESTOR).unwrap();

        let err = verify_and_extract(
            &pdf,
            hints,
            POLICY_LICENSED_PHARMACIST,
            [0x11u8; 32],
            &[DIGICERT_ROOT_G4, TESTNET_MOCK_PHARMACY_ROOT],
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::PolicyPhraseNotFound);
    }

    #[test]
    fn test_wrong_root_ca_rejected() {
        let pdf = std::fs::read("../script/attestation.pdf").unwrap();
        let hints = compute_hints(&pdf, POLICY_ACCREDITED_INVESTOR).unwrap();
        let other_root = include_bytes!("../../certs/docusign_root.der");

        let err = verify_and_extract(
            &pdf,
            hints,
            POLICY_ACCREDITED_INVESTOR,
            [0x11u8; 32],
            &[other_root],
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::CertChainInvalid);
    }

    #[test]
    fn test_wallet_hash_matches_soroban_xdr_convention() {
        // Must match soroban-zk-investor-gate::test::test_g_account_address_xdr_matches_canonical_44_byte_layout
        let g_addr = "GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P";
        let hash = stellar_g_address_to_wallet_hash(g_addr).unwrap();

        let mut expected_xdr = [0u8; 44];
        expected_xdr[3] = 18;
        expected_xdr[12..44].copy_from_slice(
            &hex::decode("d5e3ef90b1e33f50282e69fad818c1527a044c6340e6d4245a832b099dfdd9b8")
                .unwrap(),
        );
        let expected_hash: [u8; 32] = Sha256::digest(expected_xdr).into();
        assert_eq!(hash, expected_hash);

        // Bad checksum must be rejected
        assert_eq!(
            stellar_g_address_to_wallet_hash(
                "GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62A"
            ),
            Err(VerifyError::InvalidStellarAddress)
        );
    }

    #[test]
    fn test_pharmacist_policy_phrase_matching() {
        assert!(check_policy_phrase(
            "This certifies Dr. Ada Okafor is a Licensed Pharmacist in good standing with PCN.",
            POLICY_LICENSED_PHARMACIST
        ));
        assert!(!check_policy_phrase(
            "This certifies Tunde is a Software Engineer in good standing.",
            POLICY_LICENSED_PHARMACIST
        ));
    }
}
