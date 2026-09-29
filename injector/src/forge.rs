//! forge: host the attestation identity on behalf of a caller that controls
//! this device.
//!
//! This module runs inside keystore2 (it is part of the injector payload), so it
//! can reach the vendor KeyMint HAL exactly like keystore2 does. The fields the
//! framework normally fills in - AttestationApplicationId and the attestation ID
//! tags - are software-enforced: the TEE copies the caller's bytes verbatim into
//! the certificate it signs. Supplying them ourselves therefore yields a genuine
//! TEE-signed chain that claims the identity we choose.
//!
//! Disabled unless /data/misc/keystore/omk/forge/enabled exists. Requests and
//! responses are line oriented (key=value, hex for binary) so no new dependency
//! is required.

use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{hub, FromIBinder, Strong};

use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, IKeyMintDevice::IKeyMintDevice,
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose,
    Tag::Tag,
};

const FORGE_DIR: &str = "/data/misc/keystore/omk/forge";
const ENABLED_FILE: &str = "enabled";
const REQUEST_FILE: &str = "req.txt";
const RESPONSE_FILE: &str = "resp.txt";
const KEYMINT_SERVICE: &str = "android.hardware.security.keymint.IKeyMintDevice/default";
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Start the forge worker. Cheap and inert until the enable file exists.
pub fn start() {
    if let Err(error) = thread::Builder::new()
        .name("omk-forge".to_string())
        .spawn(run_loop)
    {
        log::warn!("event=forge cannot start worker thread: {error:#}");
    }
}

fn run_loop() {
    loop {
        thread::sleep(POLL_INTERVAL);
        if !Path::new(FORGE_DIR).join(ENABLED_FILE).exists() {
            continue;
        }
        if let Err(error) = serve_once() {
            log::warn!("event=forge request failed: {error:#}");
        }
    }
}

fn serve_once() -> Result<()> {
    let dir = Path::new(FORGE_DIR);
    let request = dir.join(REQUEST_FILE);
    if !request.is_file() {
        return Ok(());
    }
    let text = fs::read_to_string(&request).context("read forge request")?;
    let _ = fs::remove_file(&request);
    let response = match handle(&text) {
        Ok(response) => response,
        Err(error) => format!("status=error\nmessage={}\n", flatten(&format!("{error:#}"))),
    };
    if response.len() > MAX_RESPONSE_BYTES {
        bail!("forge response too large: {} bytes", response.len());
    }
    fs::write(dir.join(RESPONSE_FILE), response).context("write forge response")?;
    Ok(())
}

fn flatten(value: &str) -> String {
    value.replace('\r', " ").replace('\n', " ")
}

fn handle(text: &str) -> Result<String> {
    let mut op = String::new();
    let mut package = String::new();
    let mut version: u64 = 1;
    let mut serial: u64 = 1;
    let mut subject = String::from("CN=Android Keystore Key");
    let mut digests: Vec<Vec<u8>> = Vec::new();
    let mut challenge: Vec<u8> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "op" => op = value.to_string(),
            "package" => package = value.to_string(),
            "version" => version = value.parse().unwrap_or(1),
            "serial" => serial = value.parse().unwrap_or(1),
            "subject" => subject = value.to_string(),
            "digest" => {
                let raw = hex_decode(value).context("digest is not hex")?;
                if raw.len() != 32 {
                    bail!("digest must be 32 bytes, got {}", raw.len());
                }
                digests.push(raw);
            }
            "challenge" => challenge = hex_decode(value).context("challenge is not hex")?,
            other => log::debug!("event=forge ignoring unknown field {other}"),
        }
    }

    match op.as_str() {
        "probe" => probe(),
        "forge" => forge(&package, version, serial, &subject, &digests, &challenge),
        other => bail!("unsupported op '{}'", other),
    }
}

fn keymint_device() -> Result<Strong<dyn IKeyMintDevice>> {
    let binder = hub::default()?
        .try_get_service(KEYMINT_SERVICE)
        .ok()
        .flatten()
        .ok_or_else(|| anyhow!("KeyMint service {KEYMINT_SERVICE} is not available"))?;
    let device: Strong<dyn IKeyMintDevice> =
        FromIBinder::try_from(binder).context("bind IKeyMintDevice")?;
    if device.as_binder().as_proxy().is_none() {
        bail!("KeyMint service {KEYMINT_SERVICE} resolved to a local binder");
    }
    Ok(device)
}

/// Reachability probe: report the hardware info of the real TEE service.
fn probe() -> Result<String> {
    let device = keymint_device()?;
    let info = device
        .getHardwareInfo()
        .map_err(|status| anyhow!("getHardwareInfo failed: {status}"))?;
    let text = format!("{info:?}");
    log::info!("event=forge probe ok hwinfo={}", flatten(&text));
    Ok(format!(
        "status=ok\nreachable=direct-hal\nhwinfo={}\n",
        flatten(&text)
    ))
}

fn param(tag: Tag, value: KeyParameterValue) -> KeyParameter {
    KeyParameter { tag, value }
}

fn generate_params(
    application_id: &[u8],
    challenge: &[u8],
    serial: u64,
    subject: &str,
) -> Vec<KeyParameter> {
    let mut serial_bytes = serial.to_be_bytes().to_vec();
    while serial_bytes.len() > 1 && serial_bytes[0] == 0 {
        serial_bytes.remove(0);
    }
    vec![
        param(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        param(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        param(Tag::KEY_SIZE, KeyParameterValue::Integer(256)),
        param(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
        ),
        param(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        param(
            Tag::CERTIFICATE_SERIAL,
            KeyParameterValue::Blob(serial_bytes),
        ),
        param(
            Tag::CERTIFICATE_SUBJECT,
            KeyParameterValue::Blob(subject.as_bytes().to_vec()),
        ),
        param(
            Tag::ATTESTATION_CHALLENGE,
            KeyParameterValue::Blob(challenge.to_vec()),
        ),
        param(
            Tag::ATTESTATION_APPLICATION_ID,
            KeyParameterValue::Blob(application_id.to_vec()),
        ),
    ]
}

fn forge(
    package: &str,
    version: u64,
    serial: u64,
    subject: &str,
    digests: &[Vec<u8>],
    challenge: &[u8],
) -> Result<String> {
    if package.is_empty() {
        bail!("package is required");
    }
    if challenge.is_empty() {
        bail!("challenge is required");
    }
    let application_id =
        build_application_id(package, version, digests).context("build application id")?;
    log::info!(
        "event=forge identity package={} version={} digests={} aaid_bytes={} aaid_hex={}",
        package,
        version,
        digests.len(),
        application_id.len(),
        hex_encode(&application_id)
    );

    let device = keymint_device()?;
    let params = generate_params(&application_id, challenge, serial, subject);
    let created = device
        .generateKey(&params, None)
        .map_err(|status| anyhow!("generateKey failed: {status}"))?;
    log::info!(
        "event=forge generated certs={} blob_bytes={}",
        created.certificateChain.len(),
        created.keyBlob.len()
    );

    let mut response = String::from("status=ok\n");
    response.push_str(&format!("package={}\n", package));
    response.push_str(&format!("aaid={}\n", hex_encode(&application_id)));

    // Proof of possession: sign the challenge with the key just created, so the
    // caller can prove it holds the key behind the certificate.
    let sign_params = vec![param(
        Tag::DIGEST,
        KeyParameterValue::Digest(Digest::SHA_2_256),
    )];
    match device.begin(KeyPurpose::SIGN, &created.keyBlob, &sign_params, None) {
        Ok(begin) => match begin.operation {
            Some(operation) => match operation.finish(Some(challenge), None, None, None, None) {
                Ok(signature) => response.push_str(&format!("pop={}\n", hex_encode(&signature))),
                Err(status) => log::warn!("event=forge finish failed: {status}"),
            },
            None => log::warn!("event=forge begin returned no operation"),
        },
        Err(status) => log::warn!("event=forge begin failed: {status}"),
    }

    for certificate in created.certificateChain.iter() {
        response.push_str(&format!(
            "chain={}\n",
            hex_encode(&certificate.encodedCertificate)
        ));
    }
    Ok(response)
}

fn build_application_id(package: &str, version: u64, digests: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut record = der_tlv(0x04, package.as_bytes());
    record.extend(der_integer(version));
    let record = der_tlv(0x30, &record);
    let package_infos = der_set(&[record]);

    let mut digest_elements = Vec::new();
    for digest in digests {
        digest_elements.push(der_tlv(0x04, digest));
    }
    let signature_digests = der_set(&digest_elements);

    let mut body = package_infos;
    body.extend(signature_digests);
    Ok(der_tlv(0x30, &body))
}

/// DER SET OF: elements sorted by their encoding, as DER requires.
fn der_set(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted: Vec<&Vec<u8>> = elements.iter().collect();
    sorted.sort();
    let mut body = Vec::new();
    for element in sorted {
        body.extend(element.iter().copied());
    }
    der_tlv(0x31, &body)
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let mut bytes = Vec::new();
    let mut value = length;
    while value > 0 {
        bytes.insert(0, (value & 0xFF) as u8);
        value >>= 8;
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

fn der_integer(value: u64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && (bytes[1] & 0x80) == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    der_tlv(0x02, &bytes)
}

fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if cleaned.len() % 2 != 0 {
        bail!("hex string has odd length");
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let high = (bytes[index] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex digit"))?;
        let low = (bytes[index + 1] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex digit"))?;
        out.push(((high << 4) | low) as u8);
        index += 2;
    }
    Ok(out)
}
