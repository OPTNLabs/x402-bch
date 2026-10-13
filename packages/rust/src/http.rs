//! Framework-neutral x402 HTTP 402 and retry header boundary.

use base64::{Engine, engine::general_purpose::STANDARD};

pub const BCH_PAYMENT_REQUIRED_HEADER: &str = "PAYMENT-REQUIRED";
pub const BCH_PAYMENT_SIGNATURE_HEADER: &str = "PAYMENT-SIGNATURE";
pub const BCH_PAYMENT_RESPONSE_HEADER: &str = "PAYMENT-RESPONSE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BchHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub fn encode_bch_http_header(json: &str) -> Result<String, String> {
    if json.is_empty() {
        return Err("HTTP x402 header JSON must not be empty".to_string());
    }
    Ok(STANDARD.encode(json.as_bytes()))
}

pub fn decode_bch_http_header(header: &str) -> Result<String, String> {
    let bytes = STANDARD
        .decode(header)
        .map_err(|_| "HTTP x402 header is not valid base64".to_string())?;
    String::from_utf8(bytes)
        .map_err(|_| "HTTP x402 header is not UTF-8".to_string())
        .and_then(|value| {
            if value.is_empty() {
                Err("HTTP x402 header JSON must not be empty".to_string())
            } else {
                Ok(value)
            }
        })
}

pub fn create_bch_payment_required_response(
    requirements_json: &str,
) -> Result<BchHttpResponse, String> {
    Ok(BchHttpResponse {
        status: 402,
        headers: vec![(
            BCH_PAYMENT_REQUIRED_HEADER.to_string(),
            encode_bch_http_header(requirements_json)?,
        )],
        body: "Payment required".to_string(),
    })
}

pub fn create_bch_payment_signature_header(payload_json: &str) -> Result<(String, String), String> {
    Ok((
        BCH_PAYMENT_SIGNATURE_HEADER.to_string(),
        encode_bch_http_header(payload_json)?,
    ))
}
pub fn create_bch_payment_response(result_json: &str) -> Result<(String, String), String> {
    Ok((
        BCH_PAYMENT_RESPONSE_HEADER.to_string(),
        encode_bch_http_header(result_json)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn emits_and_decodes_payment_required() {
        let response = create_bch_payment_required_response("{\"x402Version\":2}").unwrap();
        assert_eq!(response.status, 402);
        assert_eq!(
            decode_bch_http_header(&response.headers[0].1).unwrap(),
            "{\"x402Version\":2}"
        );
    }
}
