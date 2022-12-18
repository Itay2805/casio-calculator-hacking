from binaryninja import *
import codecs

from .disasm import decode_instruction, DecodedInstruction, PushRegisterList, PopRegisterList


def _prepare_flags():
    pass


class Nxu8100(Architecture):
    name = "nx-u8/100"
    endianness = Endianness.LittleEndian

    default_int_size = 1
    address_size = 3
    max_instr_length = 6
    instr_alignment = 2

    stack_pointer = "SP"
    link_reg = 'LR'
    regs = {
        # TODO: right now we mostly treat the CPU as a 16bit
        # one that has 8bit registers, but this is not the most 
        # correct in theory
        'QR0': RegisterInfo('QR0', 4, 0),
            'XR0': RegisterInfo('QR0', 4, 0),
                'ER0': RegisterInfo('QR0', 2, 0),
                    'R0': RegisterInfo('QR0', 1, 0),
                    'R1': RegisterInfo('QR0', 1, 1),
                'ER2': RegisterInfo('QR0', 2, 2),
                    'R2': RegisterInfo('QR0', 1, 2),
                    'R3': RegisterInfo('QR0', 1, 3),
            'XR4': RegisterInfo('QR0', 4, 0),
                'ER4': RegisterInfo('QR0', 2, 4),
                    'R4': RegisterInfo('QR0', 1, 4),
                    'R5': RegisterInfo('QR0', 1, 5),
                'ER6': RegisterInfo('QR0', 2, 6),
                    'R6': RegisterInfo('QR0', 1, 6),
                    'R7': RegisterInfo('QR0', 1, 7),
        'QR8': RegisterInfo('QR8', 4, 0),
            'XR8': RegisterInfo('QR8', 4, 0),
                'ER8': RegisterInfo('QR8', 2, 0),
                    'R8': RegisterInfo('QR8', 1, 0),
                    'R9': RegisterInfo('QR8', 1, 1),
                'ER10': RegisterInfo('QR8', 2, 2),
                    'R10': RegisterInfo('QR8', 1, 2),
                    'R11': RegisterInfo('QR8', 1, 3),
            'XR12': RegisterInfo('QR8', 4, 0),
                'ER12': RegisterInfo('QR8', 2, 4),
                    'R12': RegisterInfo('QR8', 1, 4),
                    'R13': RegisterInfo('QR8', 1, 5),
                'ER14': RegisterInfo('QR8', 2, 6),
                    'R14': RegisterInfo('QR8', 1, 6),
                    'R15': RegisterInfo('QR8', 1, 7),

        'SP': RegisterInfo('SP', 2),
        'EA': RegisterInfo('EA', 2),

        'PC': RegisterInfo('PC', 3),
        'LR': RegisterInfo('LR', 3),

        'DSR': RegisterInfo('DSR', 1),

        'PSW': RegisterInfo('PSW', 1),        
    }
    flags = {
        'C', # Carry
        'Z', # Zero
        'S', # Sign
        'OV', # Overflow
        'HC' # Half carry
    }
    flag_roles = {
        'C': FlagRole.CarryFlagRole,
        'Z': FlagRole.ZeroFlagRole,
        'S': FlagRole.NegativeSignFlagRole,
        'OV': FlagRole.OverflowFlagRole,
        'HC': FlagRole.HalfCarryFlagRole,
    }
    flag_write_types = [
        '',
        'CZSOVHC',
        'ZS',
        'C',
        'CZSHC',
        'Z',
        'ZSOVHC'
    ]
    flags_written_by_flag_write_type = {
        'CZSOVHC': ['C', 'Z', 'S', 'OV', 'HC'],
        'ZS': ['Z', 'S'],
        'C': ['C'],
        'CZSHC': ['C', 'Z', 'S', 'HC'],
        'Z': ['Z'],
        'ZSOVHC': ['Z', 'S', 'OV', 'HC'],
    }
    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_UGE: ['C'],
        LowLevelILFlagCondition.LLFC_ULT: ['C'],
        LowLevelILFlagCondition.LLFC_UGT: ['C', 'Z'],
        LowLevelILFlagCondition.LLFC_ULE: ['Z', 'C'],
        LowLevelILFlagCondition.LLFC_SGE: ['OV', 'S'],
        LowLevelILFlagCondition.LLFC_SLT: ['OV', 'S'],
        LowLevelILFlagCondition.LLFC_SGT: ['OV', 'S', 'Z'],
        LowLevelILFlagCondition.LLFC_SLE: ['OV', 'S', 'Z'],
        LowLevelILFlagCondition.LLFC_NE: ['Z'],
        LowLevelILFlagCondition.LLFC_E: ['Z'],
        LowLevelILFlagCondition.LLFC_NO: ['OV'],
        LowLevelILFlagCondition.LLFC_O: ['OV'],
        LowLevelILFlagCondition.LLFC_POS: ['S'],
        LowLevelILFlagCondition.LLFC_NEG: ['S'],
    }

    intrinsics = {
        # TODO: any instrinsics in here
    }

    def get_instruction_info(self, data: bytes, addr: int) -> Optional[InstructionInfo]:
        try:
            decoded = decode_instruction(data, addr)
        except Exception as e:
            b = codecs.encode(data, 'hex')
            log_error(f'Got an error parsing bytes `{b}` --- \n', str)
            return

        if decoded:
            # Build the instruction info
            info = InstructionInfo()
            info.length = decoded.length

            m: str = decoded.mnemonic
            opr = decoded.instruction.first_operand
            if m == 'B':
                if opr == 'Cadr':
                    value = decoded.operands[0]
                    info.add_branch(BranchType.UnconditionalBranch, value)
                else:
                    info.add_branch(BranchType.IndirectBranch)

            elif m == 'BL':
                # NOTE: because there is no indirect call, we are just going to treat this instruction
                #       as if it has no branch
                if opr == 'Cadr':
                    value = decoded.operands[0]
                    info.add_branch(BranchType.CallDestination, value)

            elif m == 'BAL':
                value = decoded.operands[0]
                info.add_branch(BranchType.UnconditionalBranch, value)

            elif m == 'RT' or m == 'RTI':
                info.add_branch(BranchType.FunctionReturn)
 
            elif m == 'POP':
                value = decoded.operands[0]
                if opr == 'register_list' and value & PopRegisterList.PC:
                    info.add_branch(BranchType.FunctionReturn)

            elif m == 'SWI':
                info.add_branch(BranchType.SystemCall)

            elif m.startswith('B') and m != 'BRK':
                # Now we only have conditional branches left
                value = decoded.operands[0]
                info.add_branch(BranchType.TrueBranch, value)
                info.add_branch(BranchType.FalseBranch, addr + decoded.length)

            return info

    def _operand_text(self, format: str, value, tokens: List[InstructionTextToken], decoded: DecodedInstruction):
        if format == 'Radr' or format == 'Dadr':
            tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, ''))

            # DSR prefix
            if decoded.dsr_format == 'Rd':
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{decoded.dsr_operand}'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))
            elif decoded.dsr_format == '#imm8':
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{decoded.dsr_operand}', value=decoded.dsr_operand))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))
            elif decoded.dsr_format == 'DSR':
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'DSR'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))

            tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f'{value:04x}', value=value))
            tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ''))

        elif format == 'Cadr':
            tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f'{value:04x}', value=value))
        
        elif format == 'Dbitadr':
            tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f'{value[0]:04x}', value=value[0]))
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f'.'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(value[1]), value=value[1]))

        elif format == '[EA]':
            tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, ''))

            if decoded.dsr_format == 'Rd':
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{decoded.dsr_operand}'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))
            elif decoded.dsr_format == '#imm8':
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{decoded.dsr_operand}', value=decoded.dsr_operand))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))
            elif decoded.dsr_format == 'DSR':
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'DSR'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))

            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f'['))
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, 'EA'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ']'))
        elif format == '[EA+]':
            tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, ''))

            if decoded.dsr_format == 'Rd':
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{decoded.dsr_operand}'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))
            elif decoded.dsr_format == '#imm8':
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{decoded.dsr_operand}', value=decoded.dsr_operand))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))
            elif decoded.dsr_format == 'DSR':
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'DSR'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))

            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f'['))
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, 'EA'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '+'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ']'))
        elif format.startswith('Disp'):
            tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, ''))

            # DSR prefix
            if decoded.dsr_format == 'Rd':
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{decoded.dsr_operand}'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))
            elif decoded.dsr_format == '#imm8':
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{decoded.dsr_operand}', value=decoded.dsr_operand))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))
            elif decoded.dsr_format == 'DSR':
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'DSR'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))

            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(value[0]), value=value[0]))
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '['))
            if 'BP' in format:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, 'ER12'))
            elif 'FP' in format:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, 'ER14'))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'ER{value[1]*2}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ']'))
        elif format.startswith('[ER'):
            tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, ''))

            if decoded.dsr_format == 'Rd':
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{decoded.dsr_operand}'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))
            elif decoded.dsr_format == '#imm8':
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f'{decoded.dsr_operand}', value=decoded.dsr_operand))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))
            elif decoded.dsr_format == 'DSR':
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'DSR'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ':'))

            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f'['))
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'ER{value}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ']'))
        elif format.startswith('R'):
            if 'bit_offset' in format:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{value[0]}'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f'.'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(value[1]), value=value[1]))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{value}'))
        elif format.startswith('ER'):
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'ER{value}'))
        elif format.startswith('XR'):
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'XR{value}'))
        elif format.startswith('QR'):
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'QR{value}'))
        elif format.startswith('#'):
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '#'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(value), value=value))
        elif format in ['SP', 'PSW']:
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, value))
        elif format == 'register_list':
            first = False
            if decoded.mnemonic == 'PUSH':
                if PushRegisterList.ELR in value:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'ELR'))
                    first = True
                if PushRegisterList.EPSW in value:
                    if first:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f', '))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'EPSW'))
                    first = True
                if PushRegisterList.LR in value:
                    if first:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f', '))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'LR'))
                    first = True
                if PushRegisterList.EA in value:
                    if first:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f', '))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'EA'))

            else:
                if PopRegisterList.EA in value:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'EA'))
                    first = True
                if PopRegisterList.LR in value:
                    if first:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f', '))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'LR'))
                    first = True
                if PopRegisterList.PSW in value:
                    if first:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f', '))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'PSW'))
                    first = True
                if PopRegisterList.PC in value:
                    if first:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f', '))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'PC'))
        else:
            log_error(f'Invalid operand format: {format}')

    def get_instruction_text(self, data: bytes, addr: int) -> Optional[Tuple[List['function.InstructionTextToken'], int]]:
        decoded = decode_instruction(data, addr)
        if decoded:
            tokens = []

            tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, text=decoded.mnemonic))

            inst = decoded.instruction
            if inst.first_operand:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
                self._operand_text(inst.first_operand, decoded.operands[0], tokens, decoded)

            if inst.second_operand:
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ', '))
                self._operand_text(inst.second_operand, decoded.operands[1], tokens, decoded)

            return (tokens, decoded.length)

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: lowlevelil.LowLevelILFunction) -> Optional[int]:
        decoded = decode_instruction(data, addr)
        if decoded:
            inst = decoded.instruction
            oprs = decoded.operands

            def full_adr(sr, adr):
                return il.or_expr(3, il.shift_left(3, sr, il.const(1, 16)), adr)

            def dsr_prefix(adr):
                if decoded.dsr_format == 'Rd':
                    r = il.reg(1, f'R{decoded.dsr_operand}')
                    il.append(il.set_reg(1, 'DSR', r))
                elif decoded.dsr_format == '#imm8':
                    r = il.const(1, decoded.dsr_operand)
                    il.append(il.set_reg(1, 'DSR', r))
                elif decoded.dsr_format == 'DSR':
                    r = il.reg(1, 'DSR')
                else:
                    return adr
                return full_adr(r, adr)

            flags = ''.join(inst.flags)

            _ = None
            if decoded.mnemonic == '':
                assert False

            if decoded.mnemonic == 'ADD':
                if inst.first_operand == 'ERn':
                    sz = 2
                    opr1 = f'ER{oprs[0]}'
                    if inst.second_operand == 'ERm':
                        opr2 = il.reg(2, f'ER{oprs[1]}')
                    else:
                        opr2 = il.const(1, oprs[1])
                elif inst.first_operand == 'Rn':
                    sz = 1
                    opr1 = f'R{oprs[0]}'
                    if inst.second_operand == 'Rm':
                        opr2 = il.reg(1, f'R{oprs[1]}')
                    else:
                        opr2 = il.const(1, oprs[1])
                elif inst.first_operand == 'SP':
                    sz = 2
                    opr1 = 'SP'
                    opr2 = il.const(1, oprs[1])
                else:
                    assert False
                _ = il.set_reg(sz, opr1, il.add(sz, il.reg(sz, opr1), opr2, flags))

            elif decoded.mnemonic == 'ADDC':
                opr1 = il.reg(1, f'R{oprs[0]}')
                if inst.second_operand == 'Rm':
                    opr2 = il.reg(1, f'R{oprs[1]}')
                else:
                    opr2 = il.const(1, oprs[1])
                _ = il.set_reg(1, f'R{oprs[0]}', il.add_carry(1, opr1, opr2, il.flag('C')))

            elif decoded.mnemonic == 'AND':
                opr1 = il.reg(1, f'R{oprs[0]}')
                if inst.second_operand == 'Rm':
                    opr2 = il.reg(1, f'R{oprs[1]}')
                else:
                    opr2 = il.const(1, oprs[1])
                _ = il.set_reg(1, f'R{oprs[0]}', il.and_expr(1, opr1, opr2))

            elif decoded.mnemonic == 'B':
                if inst.first_operand == 'ERn':
                    # preserve the segment
                    addr &= 0xF0000
                    r = il.reg(2, f'ER{oprs[0]}')
                    adr = il.or_expr(3, addr, r)
                    _ = il.jump(adr)
                else:
                    _ = il.jump(il.const(3, oprs[0]))

            elif decoded.mnemonic in [
                'BGE',
                'BLT',
                'BGT',
                'BLE',
                'BGES',
                'BLTS',
                'BGTS',
                'BLES',
                'BNE',
                'BEQ',
                'BNV',
                'BOV',
                'BPS',
                'BNS',
            ]:
                target = oprs[0]
                next_pc = addr + decoded.length
                trueLabel = il.get_label_for_address(self, target)
                falseLabel= il.get_label_for_address(self, next_pc)

                conds = {
                    'BGE': LowLevelILFlagCondition.LLFC_UGE,
                    'BLT': LowLevelILFlagCondition.LLFC_ULT,
                    'BGT': LowLevelILFlagCondition.LLFC_UGT,
                    'BLE': LowLevelILFlagCondition.LLFC_ULE,
                    'BGES': LowLevelILFlagCondition.LLFC_SGE,
                    'BLTS': LowLevelILFlagCondition.LLFC_SLT,
                    'BGTS': LowLevelILFlagCondition.LLFC_SGT,
                    'BLES': LowLevelILFlagCondition.LLFC_SLE,
                    'BNE': LowLevelILFlagCondition.LLFC_NE,
                    'BEQ': LowLevelILFlagCondition.LLFC_E,
                    'BNV': LowLevelILFlagCondition.LLFC_NO,
                    'BOV': LowLevelILFlagCondition.LLFC_O,
                    'BPS': LowLevelILFlagCondition.LLFC_POS,
                    'BNS': LowLevelILFlagCondition.LLFC_NEG,
                }
                cond = il.flag_condition(conds[inst.mnemonic])

                if trueLabel and falseLabel:
                    _ = il.if_expr(cond, trueLabel, falseLabel)

                else:
                    trueCode = LowLevelILLabel()
                    falseCode = LowLevelILLabel()

                    if trueLabel:
                        il.append(il.if_expr(cond, trueLabel, falseCode))
                        il.mark_label(falseCode)
                        il.append(il.jump(il.const_pointer(2, next_pc)))

                    elif falseLabel:
                        il.append(il.if_expr(cond, trueCode, falseLabel))
                        il.mark_label(trueCode)
                        il.append(il.jump(il.const_pointer(2, target)))
                        
                    else:
                        il.append(il.if_expr(cond, trueCode, falseCode))
                        il.mark_label(trueCode)
                        il.append(il.jump(il.const_pointer(2, target)))
                        il.mark_label(falseCode)
                        il.append(il.jump(il.const_pointer(2, next_pc)))

            elif decoded.mnemonic == 'BAL':
                target = oprs[0]
                label = il.get_label_for_address(self, target)
                if label:
                    _ = il.goto(label)
                else:
                    _ = il.jump(il.const_pointer(2, target))

            elif decoded.mnemonic == 'BL':                
                if inst.first_operand == 'ERn':
                    # preserve the segment
                    addr &= 0xF0000
                    r = il.reg(2, f'ER{oprs[0]}')
                    adr = il.or_expr(3, addr, r)
                    _ = il.call(adr)
                else:
                    _ = il.call(il.const_pointer(3, oprs[0]))

            elif decoded.mnemonic == 'BRK':
                _ = il.breakpoint()
            
            elif decoded.mnemonic == 'CMP':
                if inst.first_operand == 'ERn':
                    sz = 2
                    opr1 = il.reg(2, f'ER{oprs[0]}')
                    if inst.second_operand == 'ERm':
                        opr2 = il.reg(2, f'ER{oprs[1]}')
                    else:
                        opr2 = il.const(1, oprs[1])
                elif inst.first_operand == 'Rn':
                    sz = 1
                    opr1 = il.reg(1, f'R{oprs[0]}')
                    if inst.second_operand == 'Rm':
                        opr2 = il.reg(1, f'R{oprs[1]}')
                    else:
                        opr2 = il.const(1, oprs[1])
                else:
                    assert False

                # TODO: update flags
                _ = il.sub(sz, opr1, opr2, flags)

            elif decoded.mnemonic == 'CMPC':
                opr1 = il.reg(1, f'R{oprs[0]}')
                if inst.second_operand == 'Rm':
                    opr2 = il.reg(1, f'R{oprs[1]}')
                else:
                    opr2 = il.const(1, oprs[1])
                _ = il.sub_borrow(1, opr1, opr2, il.flag('C'), flags)
    
            elif decoded.mnemonic == 'CPLC':
                _ = il.set_flag('C', il.not_expr(1, il.flag('C')))
            
            elif decoded.mnemonic == 'DEC':
                adr = il.reg(2, 'EA')
                adr = dsr_prefix(adr)
                _ = il.store(1, adr, il.sub(1, il.load(1, adr), il.const(1, 1)))

            elif decoded.mnemonic == 'DIV':
                opr1 = il.reg(2, f'ER{oprs[0]}')
                opr2 = il.reg(1, f'R{oprs[1]}')
                d = il.div_unsigned(2, opr1, opr2)
                m = il.mod_unsigned(1, opr1, opr2)
                _ = il.set_reg(2, f'ER{oprs[0]}', d)
                il.append(_)
                _ = il.set_reg(1, f'R{oprs[1]}', m)

            elif decoded.mnemonic == 'EXTBW':
                opr1 = il.reg(1, f'ER{oprs[0]}')
                _ = il.set_reg(2, f'ER{oprs[0]}', il.sign_extend(2, opr1))
            
            elif decoded.mnemonic == 'INC':
                adr = il.reg(2, 'EA')
                adr = dsr_prefix(adr)
                _ = il.store(1, adr, il.add(1, il.load(1, adr), il.const(1, 1)))

            elif decoded.mnemonic in ['L', 'ST']:
                # Figure the value
                if inst.first_operand == 'ERn':
                    value = f'ER{oprs[0]}'
                    sz = 2
                elif inst.first_operand == 'QRn':
                    value = f'QR{oprs[0]}'
                    sz = 8
                elif inst.first_operand == 'Rn':
                    value = f'R{oprs[0]}'
                    sz = 1
                elif inst.first_operand == 'XRn':
                    value = f'XR{oprs[0]}'
                    sz = 4

                # Figure the address
                if inst.second_operand == '[EA]':
                    adr = il.reg(2, 'EA')
                elif inst.second_operand == '[EA+]':
                    adr = il.reg(2, 'EA')
                elif inst.second_operand == '[ERm]':
                    adr = il.reg(2, f'ER{oprs[1]}')
                elif inst.second_operand == 'Disp16[ERm]':
                    base = il.const(2, oprs[1][0])
                    reg = il.reg(2, f'ER{oprs[1][1]}')
                    adr = il.add(2, base, reg)
                elif inst.second_operand == 'Disp6[BP]':
                    base = il.const(1, oprs[1][0])
                    reg = il.reg(2, 'ER12')
                    adr = il.add(2, base, reg)
                elif inst.second_operand == 'Disp6[FP]':
                    base = il.const(1, oprs[1][0])
                    reg = il.reg(2, 'ER14')
                    adr = il.add(2, base, reg)
                elif inst.second_operand == 'Dadr':
                    adr = il.const(1, oprs[1])
                else:
                    assert False, f"Invalid L operand {inst.second_operand}"

                # Handle prefix
                adr = dsr_prefix(adr)

                # Handle opcode
                if inst.mnemonic == 'L':
                    _ = il.set_reg(sz, value, il.load(sz, adr))
                else:
                    _ = il.store(sz, adr, il.reg(sz, value))

                # Handle increment EA
                if inst.second_operand == '[EA+]':
                    il.append(_)
                    _ = il.set_reg(2, 'EA', il.add(2, il.reg(2, 'EA'), il.const(1, 1)))

            elif decoded.mnemonic == 'LEA':
                if inst.first_operand == '[ERm]':
                    _ = il.set_reg(2, 'EA', il.reg(2, f'ER{oprs[0]}'))
                elif inst.first_operand == 'Dadr':
                    _ = il.set_reg(2, 'EA', il.const(2, oprs[0]))
                elif inst.first_operand == 'Disp16[ERm]':
                    _ = il.set_reg(2, 'EA', il.add(2, il.reg(2, f'ER{oprs[0][1]}'), il.const(2, oprs[0][0])))
                else:
                    assert False, f'LEA with invalid operand {inst.first_operand}'

            elif decoded.mnemonic == 'MOV':
                if inst.first_operand == 'PSW':
                    log_warn('TODO: handle PSW properly')
                    _ = il.unimplemented()

                elif inst.first_operand == 'ERn':
                    if inst.second_operand == 'ERm':
                        opr2 = il.reg(2, f'ER{oprs[1]}')
                    elif inst.second_operand == '#imm7':
                        opr2 = il.const(1, oprs[1])
                    elif inst.second_operand == 'SP':
                        opr2 = il.reg(2, 'SP')
                    else:
                        assert False, f'MOV ERn with invalid second operand {inst.second_operand}'
                    _ = il.set_reg(2, f'ER{oprs[0]}', opr2)

                elif inst.first_operand == 'Rn':
                    if inst.second_operand == 'Rm':
                        opr2 = il.reg(1, f'R{oprs[1]}')
                    elif inst.second_operand == '#imm8':
                        opr2 = il.const(1, oprs[1])
                    elif inst.second_operand == 'PSW':
                        opr2 = il.reg(1, 'PSW')
                    else:
                        assert False, f'MOV Rn with invalid second operand {inst.second_operand}'
                    _ = il.set_reg(1, f'R{oprs[0]}', opr2)

                elif inst.first_operand == 'SP':
                    er = il.reg(2, f'ER{oprs[1]}')
                    _ = il.set_reg(2, 'SP', er)

                else:
                    assert False, f'MOV with invalid operand {inst.first_operand}'

            elif decoded.mnemonic == 'MUL':
                opr1 = il.reg(1, f'R{oprs[0]}')
                opr2 = il.reg(1, f'R{oprs[1]}')
                _ = il.set_reg(2, f'ER{oprs[0]}', il.mult(2, opr1, opr2))

            elif decoded.mnemonic == 'NEG':
                r = il.reg(1, f'R{oprs[0]}')
                _ = il.set_reg(1, f'R{oprs[0]}', il.neg_expr(1, r))

            elif decoded.mnemonic == 'NOP':
                _ = il.nop()

            elif decoded.mnemonic == 'OR':
                opr1 = il.reg(1, f'R{oprs[0]}')
                if inst.second_operand == 'Rm':
                    opr2 = il.reg(1, f'R{oprs[1]}')
                else:
                    opr2 = il.const(1, oprs[1])
                _ = il.set_reg(1, f'R{oprs[0]}', il.or_expr(1, opr1, opr2))

            elif decoded.mnemonic == 'RC':
                _ = il.set_flag('C', il.const(1, 0))

            elif decoded.mnemonic == 'RT':
                _ = il.ret(il.reg(3, 'LR'))

            elif decoded.mnemonic == 'SC':
                _ = il.set_flag('C', il.const(1, 1))

            elif decoded.mnemonic == 'SUB':
                opr1 = il.reg(1, f'R{oprs[0]}')
                opr2 = il.reg(1, f'R{oprs[1]}')
                _ = il.set_reg(1, f'R{oprs[0]}', il.sub(1, opr1, opr2))

            elif decoded.mnemonic == 'SUBC':
                opr1 = il.reg(1, f'R{oprs[0]}')
                opr2 = il.reg(1, f'R{oprs[1]}')
                _ = il.set_reg(1, f'R{oprs[0]}', il.sub_borrow(1, opr1, opr2, il.flag('C')))

            elif decoded.mnemonic == 'TB':
                if inst.first_operand == 'Dbitadr':
                    val = il.load(1, il.const_pointer(2, oprs[0][0]))
                else:
                    val = il.reg(1, f'R{oprs[0][0]}')
                _ = il.set_flag('Z', il.not_expr(1, il.test_bit(1, val, il.const(1, oprs[0][1]))))

            elif decoded.mnemonic == 'XOR':
                opr1 = il.reg(1, f'R{oprs[0]}')
                if inst.second_operand == 'Rm':
                    opr2 = il.reg(1, f'R{oprs[1]}')
                else:
                    opr2 = il.const(1, oprs[1])
                _ = il.set_reg(1, f'R{oprs[0]}', il.xor_expr(1, opr1, opr2))
            
            else:
                _ = il.unimplemented()
            
            if _ is not None:
                il.append(_)

            return decoded.length
    
    # def convert_to_nop(self, data: bytes, addr: int = 0) -> Optional[bytes]:
    #     return super().convert_to_nop(data, addr)

    # def is_always_branch_patch_available(self, data: bytes, addr: int = 0) -> bool:
    #     return super().is_always_branch_patch_available(data, addr)

    # def always_branch(self, data: bytes, addr: int = 0) -> Optional[bytes]:
    #     return super().always_branch(data, addr)

    # def is_invert_branch_patch_available(self, data: bytes, addr: int = 0) -> bool:
    #     return super().is_invert_branch_patch_available(data, addr)

    # def invert_branch(self, data: bytes, addr: int = 0) -> Optional[bytes]:
    #     return super().invert_branch(data, addr)



