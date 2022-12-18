from binaryninja import *
import codecs

from .disasm import decode_instruction, DecodedInstruction, PushRegisterList, PopRegisterList


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

        'CSR': RegisterInfo('CSR', 1),

        'PC': RegisterInfo('PC', 2),
        'LR': RegisterInfo('LR', 2),

        'PSW': RegisterInfo('PSW', 1),        
    }
    flags = {
        'C', # Carry
        'Z', # Zero
        'S', # Sign
        'OV', # Overflow
        'MIE', # Master Interrupt Enable
        'HC' # Half carry
    }
    flag_roles = {
        'C': FlagRole.CarryFlagRole,
        'Z': FlagRole.ZeroFlagRole,
        'S': FlagRole.NegativeSignFlagRole,
        'OV': FlagRole.OverflowFlagRole,
        'MIE': FlagRole.SpecialFlagRole,
        'HC': FlagRole.HalfCarryFlagRole,
    }
    flag_write_types = [
        ''
    ]
    flags_written_by_flag_write_type = {
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
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'ER{value*2}'))
            tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ']'))
        elif format.startswith('R'):
            if 'bit_offset' in format:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{value[0]}'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, f'.'))
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(value[1]), value=value[1]))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{value}'))
        elif format.startswith('ER'):
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'ER{value*2}'))
        elif format.startswith('XR'):
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'XR{value*4}'))
        elif format.startswith('QR'):
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, f'QR{value*8}'))
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
        return None
    
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



