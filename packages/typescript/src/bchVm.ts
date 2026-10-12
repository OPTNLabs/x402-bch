import { hash160 } from './crypto';

/**
 * The intentionally bounded VM profile shared by the non-VM language
 * packages. It covers BCH stack, push, equality, and HASH160 semantics with
 * clean-stack enforcement. Transaction-dependent operations such as
 * CHECKSIG, CHECKDATASIG, and covenant introspection remain outside this
 * profile and must use a full BCH VM/provider boundary.
 */
export type BchVmErrorCode =
  | 'BAD_OPCODE'
  | 'CLEANSTACK'
  | 'EQUALVERIFY'
  | 'FALSE'
  | 'INVALID_STACK_OPERATION'
  | 'OP_RETURN'
  | 'PUSH_SIZE'
  | 'TRUNCATED_PUSH'
  | 'VERIFY';

export interface BchVmResult {
  accepted: boolean;
  errorCode?: BchVmErrorCode;
}

/** Evaluate one unlocking/locking script pair under the bounded BCH profile. */
export function evaluateBchVm(unlockingScript: Uint8Array, lockingScript: Uint8Array): BchVmResult {
  const stack: Uint8Array[] = [];
  const unlockingError = executeScript(unlockingScript, stack);
  if (unlockingError !== undefined) return { accepted: false, errorCode: unlockingError };
  const lockingError = executeScript(lockingScript, stack);
  if (lockingError !== undefined) return { accepted: false, errorCode: lockingError };
  if (stack.length !== 1) return { accepted: false, errorCode: 'CLEANSTACK' };
  return isTruthy(stack[0]!) ? { accepted: true } : { accepted: false, errorCode: 'FALSE' };
}

function executeScript(script: Uint8Array, stack: Uint8Array[]): BchVmErrorCode | undefined {
  let offset = 0;
  while (offset < script.length) {
    const opcode = script[offset++]!;
    if (opcode === 0) {
      stack.push(new Uint8Array());
      continue;
    }
    if (opcode >= 1 && opcode <= 75) {
      const pushed = readPush(script, offset, opcode);
      if (typeof pushed === 'string') return pushed;
      stack.push(pushed.value);
      offset = pushed.nextOffset;
      continue;
    }
    if (opcode === 0x4c || opcode === 0x4d || opcode === 0x4e) {
      const size = opcode === 0x4c ? 1 : opcode === 0x4d ? 2 : 4;
      if (offset + size > script.length) return 'TRUNCATED_PUSH';
      let length = 0;
      for (let index = 0; index < size; index += 1)
        length += script[offset + index]! * 2 ** (8 * index);
      offset += size;
      const pushed = readPush(script, offset, length);
      if (typeof pushed === 'string') return pushed;
      stack.push(pushed.value);
      offset = pushed.nextOffset;
      continue;
    }
    if (opcode >= 0x51 && opcode <= 0x60) {
      stack.push(Uint8Array.of(opcode - 0x50));
      continue;
    }
    switch (opcode) {
      case 0x69: {
        const value = pop(stack);
        if (value === undefined) return 'INVALID_STACK_OPERATION';
        if (!isTruthy(value)) return 'VERIFY';
        break;
      }
      case 0x76: {
        const value = stack.at(-1);
        if (value === undefined) return 'INVALID_STACK_OPERATION';
        stack.push(value.slice());
        break;
      }
      case 0x87: {
        const right = pop(stack);
        const left = pop(stack);
        if (right === undefined || left === undefined) return 'INVALID_STACK_OPERATION';
        stack.push(equalBytes(left, right) ? Uint8Array.of(1) : new Uint8Array());
        break;
      }
      case 0x88: {
        const right = pop(stack);
        const left = pop(stack);
        if (right === undefined || left === undefined) return 'INVALID_STACK_OPERATION';
        if (!equalBytes(left, right)) return 'EQUALVERIFY';
        break;
      }
      case 0xa9: {
        const value = pop(stack);
        if (value === undefined) return 'INVALID_STACK_OPERATION';
        stack.push(hash160(value));
        break;
      }
      case 0x6a:
        return 'OP_RETURN';
      default:
        return 'BAD_OPCODE';
    }
  }
  return undefined;
}

function readPush(
  script: Uint8Array,
  offset: number,
  length: number,
): { value: Uint8Array; nextOffset: number } | BchVmErrorCode {
  if (length > 520) return 'PUSH_SIZE';
  if (offset + length > script.length) return 'TRUNCATED_PUSH';
  return { value: script.slice(offset, offset + length), nextOffset: offset + length };
}

function pop(stack: Uint8Array[]): Uint8Array | undefined {
  return stack.pop();
}

function isTruthy(value: Uint8Array): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== 0) {
      return !(index === value.length - 1 && value[index] === 0x80);
    }
  }
  return false;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
