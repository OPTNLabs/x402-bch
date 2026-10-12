package x402bch

// BchVmResult is the normalized result of the bounded BCH VM profile.
type BchVmResult struct {
	Accepted  bool
	ErrorCode string
}

// EvaluateBchVm covers BCH stack, push, equality, VERIFY, DUP, and HASH160
// semantics with clean-stack enforcement. Transaction-dependent operations
// remain outside this portable profile.
func EvaluateBchVm(unlockingScript, lockingScript []byte) BchVmResult {
	stack := make([][]byte, 0)
	if errorCode := executeBchScript(unlockingScript, &stack); errorCode != "" {
		return BchVmResult{ErrorCode: errorCode}
	}
	if errorCode := executeBchScript(lockingScript, &stack); errorCode != "" {
		return BchVmResult{ErrorCode: errorCode}
	}
	if len(stack) != 1 {
		return BchVmResult{ErrorCode: "CLEANSTACK"}
	}
	if bchVmTruthy(stack[0]) {
		return BchVmResult{Accepted: true}
	}
	return BchVmResult{ErrorCode: "FALSE"}
}

func executeBchScript(script []byte, stack *[][]byte) string {
	for offset := 0; offset < len(script); {
		opcode := script[offset]
		offset++
		if opcode == 0 {
			*stack = append(*stack, []byte{})
			continue
		}
		if opcode >= 1 && opcode <= 75 {
			value, next, errorCode := readBchPush(script, offset, int(opcode))
			if errorCode != "" {
				return errorCode
			}
			*stack = append(*stack, value)
			offset = next
			continue
		}
		if opcode == 0x4c || opcode == 0x4d || opcode == 0x4e {
			width := 1
			if opcode == 0x4d {
				width = 2
			} else if opcode == 0x4e {
				width = 4
			}
			if offset+width > len(script) {
				return "TRUNCATED_PUSH"
			}
			length := 0
			for index := 0; index < width; index++ {
				length |= int(script[offset+index]) << (8 * index)
			}
			offset += width
			value, next, errorCode := readBchPush(script, offset, length)
			if errorCode != "" {
				return errorCode
			}
			*stack = append(*stack, value)
			offset = next
			continue
		}
		if opcode >= 0x51 && opcode <= 0x60 {
			*stack = append(*stack, []byte{opcode - 0x50})
			continue
		}
		switch opcode {
		case 0x69:
			value, ok := bchVmPop(stack)
			if !ok {
				return "INVALID_STACK_OPERATION"
			}
			if !bchVmTruthy(value) {
				return "VERIFY"
			}
		case 0x76:
			if len(*stack) == 0 {
				return "INVALID_STACK_OPERATION"
			}
			value := append([]byte(nil), (*stack)[len(*stack)-1]...)
			*stack = append(*stack, value)
		case 0x87:
			right, okRight := bchVmPop(stack)
			left, okLeft := bchVmPop(stack)
			if !okRight || !okLeft {
				return "INVALID_STACK_OPERATION"
			}
			if string(left) == string(right) {
				*stack = append(*stack, []byte{1})
			} else {
				*stack = append(*stack, []byte{})
			}
		case 0x88:
			right, okRight := bchVmPop(stack)
			left, okLeft := bchVmPop(stack)
			if !okRight || !okLeft {
				return "INVALID_STACK_OPERATION"
			}
			if string(left) != string(right) {
				return "EQUALVERIFY"
			}
		case 0xa9:
			value, ok := bchVmPop(stack)
			if !ok {
				return "INVALID_STACK_OPERATION"
			}
			*stack = append(*stack, hash160(value))
		case 0x6a:
			return "OP_RETURN"
		default:
			return "BAD_OPCODE"
		}
	}
	return ""
}

func readBchPush(script []byte, offset, length int) ([]byte, int, string) {
	if length > 520 {
		return nil, offset, "PUSH_SIZE"
	}
	end := offset + length
	if end < offset || end > len(script) {
		return nil, offset, "TRUNCATED_PUSH"
	}
	return append([]byte(nil), script[offset:end]...), end, ""
}

func bchVmPop(stack *[][]byte) ([]byte, bool) {
	if len(*stack) == 0 {
		return nil, false
	}
	index := len(*stack) - 1
	value := (*stack)[index]
	*stack = (*stack)[:index]
	return value, true
}

func bchVmTruthy(value []byte) bool {
	for index, item := range value {
		if item != 0 {
			return !(index == len(value)-1 && item == 0x80)
		}
	}
	return false
}
