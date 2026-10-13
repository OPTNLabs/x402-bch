"""Bounded BCH VM evaluation."""

from .crypto import _hash160

def evaluate_bch_vm(unlocking_script: bytes, locking_script: bytes) -> dict[str, bool | str | None]:
    """Evaluate the bounded BCH VM profile used by cross-language fixtures."""
    stack: list[bytes] = []
    error = _execute_bch_script(unlocking_script, stack)
    if error is None:
        error = _execute_bch_script(locking_script, stack)
    if error is None and len(stack) != 1:
        error = "CLEANSTACK"
    if error is None and not _vm_truthy(stack[0]):
        error = "FALSE"
    return {"accepted": error is None, "errorCode": error}


def _execute_bch_script(script: bytes, stack: list[bytes]) -> str | None:
    offset = 0
    while offset < len(script):
        opcode = script[offset]
        offset += 1
        if opcode == 0:
            stack.append(b"")
            continue
        if 1 <= opcode <= 75:
            value, offset, error = _read_bch_push(script, offset, opcode)
            if error is not None:
                return error
            stack.append(value)
            continue
        if opcode in (0x4C, 0x4D, 0x4E):
            width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[opcode]
            if offset + width > len(script):
                return "TRUNCATED_PUSH"
            length = int.from_bytes(script[offset : offset + width], "little")
            offset += width
            value, offset, error = _read_bch_push(script, offset, length)
            if error is not None:
                return error
            stack.append(value)
            continue
        if 0x51 <= opcode <= 0x60:
            stack.append(bytes([opcode - 0x50]))
            continue
        if opcode == 0x69:
            if not stack:
                return "INVALID_STACK_OPERATION"
            if not _vm_truthy(stack.pop()):
                return "VERIFY"
        elif opcode == 0x76:
            if not stack:
                return "INVALID_STACK_OPERATION"
            stack.append(stack[-1])
        elif opcode == 0x87:
            if len(stack) < 2:
                return "INVALID_STACK_OPERATION"
            right, left = stack.pop(), stack.pop()
            stack.append(b"\x01" if left == right else b"")
        elif opcode == 0x88:
            if len(stack) < 2:
                return "INVALID_STACK_OPERATION"
            right, left = stack.pop(), stack.pop()
            if left != right:
                return "EQUALVERIFY"
        elif opcode == 0xA9:
            if not stack:
                return "INVALID_STACK_OPERATION"
            stack.append(_hash160(stack.pop()))
        elif opcode == 0x6A:
            return "OP_RETURN"
        else:
            return "BAD_OPCODE"
    return None


def _read_bch_push(script: bytes, offset: int, length: int) -> tuple[bytes, int, str | None]:
    if length > 520:
        return b"", offset, "PUSH_SIZE"
    end = offset + length
    if end > len(script):
        return b"", offset, "TRUNCATED_PUSH"
    return script[offset:end], end, None


def _vm_truthy(value: bytes) -> bool:
    for index, item in enumerate(value):
        if item != 0:
            return not (index == len(value) - 1 and item == 0x80)
    return False
