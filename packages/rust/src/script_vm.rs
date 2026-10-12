//! Bounded BCH VM semantics shared by the portable conformance surface.
//!
//! This profile intentionally covers stack, push, equality, VERIFY, DUP, and
//! HASH160 operations with clean-stack enforcement. Transaction-dependent
//! operations such as CHECKSIG, CHECKDATASIG, and covenant introspection stay
//! behind the full BCH VM/provider boundary.

use crate::address::hash160;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BchVmResult {
    pub accepted: bool,
    pub error_code: Option<&'static str>,
}

/// Evaluate one unlocking/locking script pair under the bounded BCH profile.
pub fn evaluate_bch_vm(unlocking_script: &[u8], locking_script: &[u8]) -> BchVmResult {
    let mut stack = Vec::new();
    if let Some(error_code) = execute_script(unlocking_script, &mut stack) {
        return rejected(error_code);
    }
    if let Some(error_code) = execute_script(locking_script, &mut stack) {
        return rejected(error_code);
    }
    if stack.len() != 1 {
        return rejected("CLEANSTACK");
    }
    if is_truthy(stack.last().expect("stack length checked")) {
        accepted()
    } else {
        rejected("FALSE")
    }
}

fn execute_script(script: &[u8], stack: &mut Vec<Vec<u8>>) -> Option<&'static str> {
    let mut offset = 0;
    while offset < script.len() {
        let opcode = script[offset];
        offset += 1;
        if opcode == 0 {
            stack.push(Vec::new());
            continue;
        }
        if (1..=75).contains(&opcode) {
            let (value, next_offset) = match read_push(script, offset, usize::from(opcode)) {
                Ok(value) => value,
                Err(error_code) => return Some(error_code),
            };
            stack.push(value);
            offset = next_offset;
            continue;
        }
        if matches!(opcode, 0x4c..=0x4e) {
            let width = match opcode {
                0x4c => 1,
                0x4d => 2,
                _ => 4,
            };
            if offset + width > script.len() {
                return Some("TRUNCATED_PUSH");
            }
            let mut length = 0usize;
            for index in 0..width {
                length |= usize::from(script[offset + index]) << (8 * index);
            }
            offset += width;
            let (value, next_offset) = match read_push(script, offset, length) {
                Ok(value) => value,
                Err(error_code) => return Some(error_code),
            };
            stack.push(value);
            offset = next_offset;
            continue;
        }
        if (0x51..=0x60).contains(&opcode) {
            stack.push(vec![opcode - 0x50]);
            continue;
        }
        match opcode {
            0x69 => {
                let value = match stack.pop() {
                    Some(value) => value,
                    None => return Some("INVALID_STACK_OPERATION"),
                };
                if !is_truthy(&value) {
                    return Some("VERIFY");
                }
            }
            0x76 => {
                let value = match stack.last() {
                    Some(value) => value.clone(),
                    None => return Some("INVALID_STACK_OPERATION"),
                };
                stack.push(value);
            }
            0x87 => {
                let right = match stack.pop() {
                    Some(value) => value,
                    None => return Some("INVALID_STACK_OPERATION"),
                };
                let left = match stack.pop() {
                    Some(value) => value,
                    None => return Some("INVALID_STACK_OPERATION"),
                };
                stack.push(if left == right { vec![1] } else { Vec::new() });
            }
            0x88 => {
                let right = match stack.pop() {
                    Some(value) => value,
                    None => return Some("INVALID_STACK_OPERATION"),
                };
                let left = match stack.pop() {
                    Some(value) => value,
                    None => return Some("INVALID_STACK_OPERATION"),
                };
                if left != right {
                    return Some("EQUALVERIFY");
                }
            }
            0xa9 => {
                let value = match stack.pop() {
                    Some(value) => value,
                    None => return Some("INVALID_STACK_OPERATION"),
                };
                stack.push(hash160(&value).to_vec());
            }
            0x6a => return Some("OP_RETURN"),
            _ => return Some("BAD_OPCODE"),
        }
    }
    None
}

fn read_push(
    script: &[u8],
    offset: usize,
    length: usize,
) -> Result<(Vec<u8>, usize), &'static str> {
    if length > 520 {
        return Err("PUSH_SIZE");
    }
    let end = offset.checked_add(length).ok_or("TRUNCATED_PUSH")?;
    if end > script.len() {
        return Err("TRUNCATED_PUSH");
    }
    Ok((script[offset..end].to_vec(), end))
}

fn is_truthy(value: &[u8]) -> bool {
    for (index, byte) in value.iter().enumerate() {
        if *byte != 0 {
            return !(index == value.len() - 1 && *byte == 0x80);
        }
    }
    false
}

fn accepted() -> BchVmResult {
    BchVmResult {
        accepted: true,
        error_code: None,
    }
}

fn rejected(error_code: &'static str) -> BchVmResult {
    BchVmResult {
        accepted: false,
        error_code: Some(error_code),
    }
}

#[cfg(test)]
mod tests {
    use super::evaluate_bch_vm;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        version: u8,
        profile: String,
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        #[serde(rename = "unlockingScript")]
        unlocking_script: String,
        #[serde(rename = "lockingScript")]
        locking_script: String,
        #[serde(rename = "expectedAccepted")]
        expected_accepted: bool,
        #[serde(rename = "expectedError")]
        expected_error: Option<String>,
    }

    #[test]
    fn matches_the_shared_bch_vm_fixture() {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../spec/conformance/v1/bch-vm.json")).unwrap();
        assert_eq!(fixture.version, 1);
        assert_eq!(fixture.profile, "bch-bounded-v1");
        assert_eq!(fixture.cases.len(), 12);
        for case in fixture.cases {
            let result = evaluate_bch_vm(
                &hex::decode(case.unlocking_script).unwrap(),
                &hex::decode(case.locking_script).unwrap(),
            );
            assert_eq!(result.accepted, case.expected_accepted, "{}", case.id);
            assert_eq!(
                result.error_code.map(str::to_string),
                case.expected_error,
                "{}",
                case.id
            );
        }
    }
}
