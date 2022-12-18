from dataclasses import dataclass
from enum import Flag, auto
from struct import Struct
from typing import List


WORD = Struct('<H')


class PopRegisterList(Flag):
    EA = auto()
    LR = auto()
    PSW = auto()
    PC = auto()


class PushRegisterList(Flag):
    ELR = auto()
    EPSW = auto()
    LR = auto()
    EA = auto()


@dataclass
class Instruction:
    mnemonic: str
    first_operand: str or None
    second_operand: str or None
    flags: List[str]
    first_word: str
    second_word: str or None

C = 'C'
Z = 'Z'
S = 'S'
OV = 'OV'
MIE = 'MIE'
HC = 'HC'

INSTRUCTION_TABLE = [
    # DSR Prefix
    Instruction('DSR<-', '#imm8',   None, [], '1110_0011_iiii_iiii', None),
    Instruction('DSR<-', 'Rd',      None, [], '1001_0000_dddd_1111', None),
    Instruction('DSR<-', 'DSR',     None, [], '1111_1110_1001_1111', None),

    # Arithmetic Instructions
    Instruction('ADD',  'Rn', 'Rm',     [C, Z, S, OV, HC], '1000_nnnn_mmmm_0001', None),
    Instruction('ADD',  'Rn', '#imm8',  [C, Z, S, OV, HC], '0001_nnnn_iiii_iiii', None),
    Instruction('ADD',  'ERn', 'ERm',   [C, Z, S, OV, HC], '1111_nnn0_mmm0_0110', None),
    Instruction('ADD',  'ERn', '#imm7', [C, Z, S, OV, HC], '1110_nnn0_1iii_iiii', None),
    Instruction('ADDC', 'Rn', 'Rm',     [C, Z, S, OV, HC], '1000_nnnn_mmmm_0110', None),
    Instruction('ADDC', 'Rn', '#imm8',  [C, Z, S, OV, HC], '0110_nnnn_iiii_iiii', None),
    Instruction('AND',  'Rn', 'Rm',     [Z, S],            '1000_nnnn_mmmm_0010', None),
    Instruction('AND',  'Rn', '#imm8',  [Z, S],            '0010_nnnn_iiii_iiii', None),
    Instruction('CMP',  'Rn', 'Rm',     [C, Z, S, OV, HC], '1000_nnnn_mmmm_0111', None),
    Instruction('CMP',  'Rn', '#imm8',  [C, Z, S, OV, HC], '0111_nnnn_iiii_iiii', None),
    Instruction('CMPC', 'Rn', 'Rm',     [C, Z, S, OV, HC], '1000_nnnn_mmmm_0101', None),
    Instruction('CMPC', 'Rn', '#imm8',  [C, Z, S, OV, HC], '0101_nnnn_iiii_iiii', None),
    Instruction('MOV',  'ERn', 'ERm',   [Z, S],            '1111_nnn0_mmm0_0101', None),
    Instruction('MOV',  'ERn', '#imm7', [Z, S],            '1110_nnn0_0iii_iiii', None),
    Instruction('MOV',  'Rn', 'Rm',     [Z, S],            '1000_nnnn_mmmm_0000', None),
    Instruction('MOV',  'Rn', '#imm8',  [Z, S],            '0000_nnnn_iiii_iiii', None),
    Instruction('OR',   'Rn', 'Rm',     [Z, S],            '1000_nnnn_mmmm_0011', None),
    Instruction('OR',   'Rn', '#imm8',  [Z, S],            '0011_nnnn_iiii_iiii', None),
    Instruction('XOR',  'Rn', 'Rm',     [Z, S],            '1000_nnnn_mmmm_0100', None),
    Instruction('XOR',  'Rn', '#imm8',  [Z, S],            '0100_nnnn_iiii_iiii', None),
    Instruction('CMP',  'ERn', 'ERm',   [C, Z, S, OV, HC], '1111_nnn0_mmm0_0111', None),
    Instruction('SUB',  'Rn', 'Rm',     [C, Z, S, OV, HC], '1000_nnnn_mmmm_1000', None),
    Instruction('SUBC', 'Rn', 'Rm',     [C, Z, S, OV, HC], '1000_nnnn_mmmm_1001', None),

    # Shift Instructions
    Instruction('SLL',  'Rn', 'Rm',         [C], '1000_nnnn_mmmm_1010', None),
    Instruction('SLL',  'Rn', '#width',     [C], '1001_nnnn_0www_1010', None),
    Instruction('SLLC', 'Rn', 'Rm',         [C], '1000_nnnn_mmmm_1011', None),
    Instruction('SLLC', 'Rn', '#width',     [C], '1001_nnnn_0www_1011', None),
    Instruction('SRA',  'Rn', 'Rm',         [C], '1000_nnnn_mmmm_1110', None),
    Instruction('SRA',  'Rn', '#width',     [C], '1001_nnnn_0www_1110', None),
    Instruction('SRL',  'Rn', 'Rm',         [C], '1000_nnnn_mmmm_1100', None),
    Instruction('SRL',  'Rn', '#width',     [C], '1001_nnnn_0www_1100', None),
    Instruction('SRLC', 'Rn', 'Rm',         [C], '1000_nnnn_mmmm_1101', None),
    Instruction('SRLC', 'Rn', '#width',     [C], '1001_nnnn_0www_1101', None),

    # Load/Store Instructions
    Instruction('L',  'ERn', '[EA]',        [Z, S], '1001_nnn0_0011_0010', None),
    Instruction('L',  'ERn', '[EA+]',       [Z, S], '1001_nnn0_0101_0010', None),
    Instruction('L',  'ERn', '[ERm]',       [Z, S], '1001_nnn0_mmm0_0010', None),
    Instruction('L',  'ERn', 'Disp16[ERm]', [Z, S], '1010_nnn0_mmm0_1000', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('L',  'ERn', 'Disp6[BP]',   [Z, S], '1011_nnn0_00DD_DDDD', None),
    Instruction('L',  'ERn', 'Disp6[FP]',   [Z, S], '1011_nnn0_01DD_DDDD', None),
    Instruction('L',  'ERn', 'Dadr',        [Z, S], '1001_nnn0_0001_0010', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('L',  'Rn', '[EA]',         [Z, S], '1001_nnnn_0011_0000', None),
    Instruction('L',  'Rn', '[EA+]',        [Z, S], '1001_nnnn_0101_0000', None),
    Instruction('L',  'Rn', '[ERm]',        [Z, S], '1001_nnnn_mmm0_0000', None),
    Instruction('L',  'Rn', 'Disp16[ERm]',  [Z, S], '1001_nnnn_mmm0_1000', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('L',  'Rn', 'Disp6[BP]',    [Z, S], '1101_nnnn_00DD_DDDD', None),
    Instruction('L',  'Rn', 'Disp6[FP]',    [Z, S], '1101_nnnn_01DD_DDDD', None),
    Instruction('L',  'Rn', 'Dadr',         [Z, S], '1001_nnnn_0001_0000', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('L',  'XRn', '[EA]',        [Z, S], '1001_nn00_0011_0100', None),
    Instruction('L',  'XRn', '[EA+]',       [Z, S], '1001_nn00_0101_0100', None),
    Instruction('L',  'QRn', '[EA]',        [Z, S], '1001_n000_0011_0110', None),
    Instruction('L',  'QRn', '[EA+]',       [Z, S], '1001_n000_0101_0110', None),
    Instruction('ST', 'ERn', '[EA]',        [Z, S], '1001_nnn0_0011_0011', None),
    Instruction('ST', 'ERn', '[EA+]',       [Z, S], '1001_nnn0_0101_0011', None),
    Instruction('ST', 'ERn', '[ERm]',       [Z, S], '1001_nnn0_mmm0_0011', None),
    Instruction('ST', 'ERn', 'Disp16[ERm]', [Z, S], '1010_nnn0_mmm0_1001', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('ST', 'ERn', 'Disp6[BP]',   [Z, S], '1011_nnn0_10DD_DDDD', None),
    Instruction('ST', 'ERn', 'Disp6[FP]',   [Z, S], '1011_nnn0_11DD_DDDD', None),
    Instruction('ST', 'ERn', 'Dadr',        [Z, S], '1001_nnn0_0001_0011', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('ST', 'Rn', '[EA]',         [Z, S], '1001_nnnn_0011_0001', None),
    Instruction('ST', 'Rn', '[EA+]',        [Z, S], '1001_nnnn_0101_0001', None),
    Instruction('ST', 'Rn', '[ERm]',        [Z, S], '1001_nnnn_mmm0_0001', None),
    Instruction('ST', 'Rn', 'Disp16[ERm]',  [Z, S], '1001_nnnn_mmm0_1001', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('ST', 'Rn', 'Disp6[BP]',    [Z, S], '1101_nnnn_10DD_DDDD', None),
    Instruction('ST', 'Rn', 'Disp6[FP]',    [Z, S], '1101_nnnn_11DD_DDDD', None),
    Instruction('ST', 'Rn', 'Dadr',         [Z, S], '1001_nnnn_0001_0001', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('ST', 'XRn', '[EA]',        [Z, S], '1001_nn00_0011_0101', None),
    Instruction('ST', 'XRn', '[EA+]',       [Z, S], '1001_nn00_0101_0101', None),
    Instruction('ST', 'QRn', '[EA]',        [Z, S], '1001_n000_0011_0111', None),
    Instruction('ST', 'QRn', '[EA+]',       [Z, S], '1001_n000_0101_0111', None),

    # Control Register Access Instructions
    Instruction('ADD', 'SP', '#signed8',    [], '1110_0001_iiii_iiii', None),
    Instruction('MOV', 'ECSR', 'Rm',        [], '1010_0000_mmmm_1111', None),
    Instruction('MOV', 'ELR', 'ERm',        [], '1010_mmm0_0000_1101', None),
    Instruction('MOV', 'EPSW', 'Rm',        [], '1010_0000_mmmm_1100', None),
    Instruction('MOV', 'ERn', 'ELR',        [], '1010_nnn0_0000_0101', None),
    Instruction('MOV', 'ERn', 'SP',         [], '1010_nnn0_0001_1010', None),
    Instruction('MOV', 'PSW', 'Rm',         [], '1010_0000_mmmm_1011', None),
    Instruction('MOV', 'PSW', '#unsigned8', [], '1110_1001_iiii_iiii', None),
    Instruction('MOV', 'Rn', 'ECSR',        [], '1010_nnnn_0000_0111', None),
    Instruction('MOV', 'Rn', 'EPSW',        [], '1010_nnnn_0000_0100', None),
    Instruction('MOV', 'Rn', 'PSW',         [], '1010_nnnn_0000_0011', None),
    Instruction('MOV', 'SP', 'ERm',         [], '1010_0001_mmm0_1010', None),

    # PUSH/POP Instructions
    Instruction('PUSH', 'ERn',           None, [], '1111_nnn0_0101_1110', None),
    Instruction('PUSH', 'QRn',           None, [], '1111_n000_0111_1110', None),
    Instruction('PUSH', 'Rn',            None, [], '1111_nnnn_0100_1110', None),
    Instruction('PUSH', 'XRn',           None, [], '1111_nn00_0110_1110', None),
    Instruction('PUSH', 'register_list', None, [], '1111_lepa_1100_1110', None),
    Instruction('POP',  'ERn',           None, [], '1111_nnn0_0001_1110', None),
    Instruction('POP',  'QRn',           None, [], '1111_n000_0011_1110', None),
    Instruction('POP',  'Rn',            None, [], '1111_nnnn_0000_1110', None),
    Instruction('POP',  'XRn',           None, [], '1111_nn00_0010_1110', None),
    Instruction('POP',  'register_list', None, [], '1111_lepa_1000_1110', None),

    # Coprocessor Data Transfer Instructions
    # TODO: this is right now not supported at all

    # EA Register Data Transfer Instructions
    Instruction('LEA', '[ERm]',       None, [], '1111_0000_mmm0_1010', None),
    Instruction('LEA', 'Disp16[ERm]', None, [], '1111_0000_mmm0_1011', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('LEA', 'Dadr',        None, [], '1111_0000_0000_1100', 'DDDD_DDDD_DDDD_DDDD'),
    
    # ALU Instructions
    Instruction('DAA', 'Rn', None, [C, Z, S, HC],     '1000_nnnn_0001_1111', None),
    Instruction('DAS', 'Rn', None, [C, Z, S, HC],     '1000_nnnn_0011_1111', None),
    Instruction('NEG', 'Rn', None, [C, Z, S, OV, HC], '1000_nnnn_0101_1111', None),

    # Bit Access Instructions
    Instruction('SB', 'Rn.bit_offset',  None, [Z], '1010_nnnn_0bbb_0000', None),
    Instruction('SB', 'Dbitadr',        None, [Z], '1010_0000_1bbb_0000', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('RB', 'Rn.bit_offset',  None, [Z], '1010_nnnn_0bbb_0010', None),
    Instruction('RB', 'Dbitadr',        None, [Z], '1010_0000_1bbb_0010', 'DDDD_DDDD_DDDD_DDDD'),
    Instruction('TB', 'Rn.bit_offset',  None, [Z], '1010_nnnn_0bbb_0001', None),
    Instruction('TB', 'Dbitadr',        None, [Z], '1010_0000_1bbb_0001', 'DDDD_DDDD_DDDD_DDDD'),

    # PSW Access Instructions
    Instruction('EI',   None, None, [MIE], '1110_1101_0000_1000', None),
    Instruction('DI',   None, None, [MIE], '1110_1011_1111_0111', None),
    Instruction('SC',   None, None, [C],   '1110_1101_1000_0000', None),
    Instruction('RC',   None, None, [C],   '1110_1011_0111_1111', None),
    Instruction('CPLC', None, None, [C],   '1111_1110_1100_1111', None),

    # Conditional Relative Branch Instructions
    Instruction('BGE',  'Radr', None, [], '1100_0000_rrrr_rrrr', None),
    Instruction('BLT',  'Radr', None, [], '1100_0001_rrrr_rrrr', None),
    Instruction('BGT',  'Radr', None, [], '1100_0010_rrrr_rrrr', None),
    Instruction('BLE',  'Radr', None, [], '1100_0011_rrrr_rrrr', None),
    Instruction('BGES', 'Radr', None, [], '1100_0100_rrrr_rrrr', None),
    Instruction('BLTS', 'Radr', None, [], '1100_0101_rrrr_rrrr', None),
    Instruction('BGTS', 'Radr', None, [], '1100_0110_rrrr_rrrr', None),
    Instruction('BLES', 'Radr', None, [], '1100_0111_rrrr_rrrr', None),
    Instruction('BNE',  'Radr', None, [], '1100_1000_rrrr_rrrr', None),
    Instruction('BEQ',  'Radr', None, [], '1100_1001_rrrr_rrrr', None),
    Instruction('BNV',  'Radr', None, [], '1100_1010_rrrr_rrrr', None),
    Instruction('BOV',  'Radr', None, [], '1100_1011_rrrr_rrrr', None),
    Instruction('BPS',  'Radr', None, [], '1100_1100_rrrr_rrrr', None),
    Instruction('BNS',  'Radr', None, [], '1100_1101_rrrr_rrrr', None),
    Instruction('BAL',  'Radr', None, [], '1100_1110_rrrr_rrrr', None),

    # Sign Extension Instruction
    # This format needed to be fixed to properly fit to our parser
    # Instruction('EXTBW', 'ERn', None, [Z, S], '1000_nnn1_nnn0_1111', None),
    Instruction('EXTBW', 'ERn', None, [Z, S], '1000_mmm1_nnn0_1111', None),

    # Software Interrupt Instructions
    Instruction('SWI', '#snum', None, [MIE], '1110_0101_00ii_iiii', None),
    Instruction('BRK', None,    None, [],    '1111_1111_1111_1111', None),

    # Branch Instructions
    Instruction('B',  'Cadr', None, [], '1111_gggg_0000_0000', 'CCCC_CCCC_CCCC_CCCC'),
    Instruction('B',  'ERn',  None, [], '1111_0000_nnn0_0010', None),
    Instruction('BL', 'Cadr', None, [], '1111_gggg_0000_0001', 'CCCC_CCCC_CCCC_CCCC'),
    Instruction('BL', 'ERn',  None, [], '1111_0000_nnn0_0011', None),

    # Multiplication and Division Instructions
    Instruction('MUL', 'ERn', 'Rm', [Z],                   '1111_nnn0_mmmm_0100', None),
    Instruction('DIV', 'ERn', 'Rm', [C, Z],                '1111_nnn0_mmmm_1001', None),

    # Miscellaneous
    Instruction('INC', '[EA]', None, [Z, S, OV, HC],         '1111_1110_0010_1111', None),
    Instruction('DEC', '[EA]', None, [Z, S, OV, HC],         '1111_1110_0011_1111', None),
    Instruction('RT' , None,   None, [],                     '1111_1110_0001_1111', None),
    Instruction('RTI', None,   None, [C, Z, S, OV, MIE, HC], '1111_1110_0000_1111', None),
    Instruction('NOP', None,   None, [],                     '1111_1110_1000_1111', None),
]


LOOKUP_TABLE = [None] * 0x10000


def _create_lookup_table():
    # Create a quick mask table to quickly figure 
    # if a word is for the instruction
    mask_table = []
    for inst in INSTRUCTION_TABLE:
        wanted = 0
        mask = 0
        for c in inst.first_word:
            if c == '_':
                continue
        
            mask <<= 1
            wanted <<= 1

            if c == '1':
                mask |= 1
                wanted |= 1
            elif c == '0':
                mask |= 1
        mask_table.append((mask, wanted))

    # now generate the lookup table
    # TODO: maybe pre-decode it as well? should save some time 
    for word in range(0xFFFF + 1):
        for i, (mask, wanted) in enumerate(mask_table):
            if (word & mask) == wanted:
                LOOKUP_TABLE[word] = INSTRUCTION_TABLE[i]


_create_lookup_table()


class DecodedInstruction:

    def __init__(self, inst: Instruction) -> None:
        self.instruction = inst
        self.length = 0
        self.operands = []
        self.dsr_operand = None
        self.dsr_format = None

    @property
    def mnemonic(self) -> str:
        return self.instruction.mnemonic

    def __repr__(self) -> str:
        return f"DecodedInstruction(instruction={repr(self.instruction)}, length={self.length}, operands={repr(self.operands)}, dsr_operand={self.dsr_operand}, dsr_format={self.dsr_format})"


def _operand_values(m, format: str, word: int):
    offset = 15
    for c in format:
        if c == '_':
            continue

        if c not in '10':
            if c in m:
                value = m[c]
            else:
                value = 0
            value <<= 1
            value |= 1 if (word & (1 << offset)) else 0
            m[c] = value

        offset -= 1


def twos_comp(val, bits):
    if (val & (1 << (bits - 1))) != 0:
        val = val - (1 << bits)
    return val


def _figure_operand(mnemonic: str, format: str, m, next_pc: int):
    if format == 'Radr':
        r = twos_comp(m['r'], 8)
        return next_pc + (r << 1)
    elif format == 'Dadr':
        return m['D']
    elif format == 'Dbitadr':
        return (m['D'], m['b'])
    elif format == 'Cadr':
        return m['C'] | (m['g'] << 16)
    elif format in ['[EA+]', '[EA]']:
        return None
    elif format.startswith('[ER'):
        return m[format[3:-1]] * 2
    elif format.startswith('Disp'):
        arr = [m['D']]
        if '[ER' in format:
            arr.append(m[format[format.index('[')+3:-1]] * 2)
        return arr
    elif format.startswith('R'):
        if '.bit_offset' in format:
            return (m[format[1:format.index('.')]], m['b'])
        else:
            return m[format[1:]]
    elif format.startswith('ER'):
        return m[format[2:]] * 2
    elif format.startswith('XR'):
        return m[format[2:]] * 4
    elif format.startswith('QR'):
        return m[format[2:]] * 8
    elif format in ['SP', 'PSW', 'DSR']:
        return format
    elif format in ['#imm8', '#imm7', '#unsigned8', '#snum']:
        return m['i']
    elif format in ['#width']:
        return m['w']
    elif format == '#signed8':
        return twos_comp(m['i'], 8)
    elif format == 'register_list':
        if mnemonic == 'POP':
            flags = PopRegisterList(0)
            if m['a'] == 1:
                flags |= PopRegisterList.EA
            if m['p'] == 1:
                flags |= PopRegisterList.PC
            if m['e'] == 1:
                flags |= PopRegisterList.PSW
            if m['l'] == 1:
                flags |= PopRegisterList.LR
        else:
            flags = PushRegisterList(0)
            if m['a'] == 1:
                flags |= PushRegisterList.EA
            if m['p'] == 1:
                flags |= PushRegisterList.ELR
            if m['e'] == 1:
                flags |= PushRegisterList.EPSW
            if m['l'] == 1:
                flags |= PushRegisterList.LR
        return flags
    else:
        assert False, f"Invalid format {format}"


def decode_instruction(data: bytes, addr: int) -> DecodedInstruction or None:
    # TODO: match against DSR prefixes

    offset = 0
    def fetch_word():
        nonlocal offset
        word = WORD.unpack_from(data, offset)[0]
        offset += 2
        return word

    def peek_word():
        if len(data) - offset >= 2: 
            return WORD.unpack_from(data, offset)[0]
        else:
            return None

    # fetch it 
    first_word = fetch_word()

    # Check which instruction that is 
    inst: Instruction or None = LOOKUP_TABLE[first_word]
    if inst is None:
        return None

    dsr_format = None
    dsr_operand = None
    if inst.mnemonic == 'DSR<-':
        next_word = peek_word()
        if next_word is not None:
            next_inst: Instruction or None = LOOKUP_TABLE[next_word]
            if next_inst is None:
                return None
            
            # combine DSR prefix into the load/store instruction
            if next_inst.mnemonic in ['L', 'ST']:

                # Finish the parsing of the dsr, so we can put it into the L/ST instruction
                m = {}
                _operand_values(m, inst.first_word, first_word)
                dsr_operand = _figure_operand(inst.mnemonic, inst.first_operand, m, addr)
                dsr_format = inst.first_operand

                # Continue with parsing the L/ST instruction
                inst = next_inst
                first_word = next_word

                # skip the next_inst which is now the current inst 
                offset += 2

    d = DecodedInstruction(inst)
    d.dsr_format = dsr_format
    d.dsr_operand = dsr_operand

    # get the operand variables 
    # TODO: maybe do this in the lookup instead? can save quite a bit of string processing
    m = {}
    _operand_values(m, inst.first_word, first_word)
    if inst.second_word is not None:
        second_word = fetch_word()
        _operand_values(m, inst.second_word, second_word)

    # TODO: decode operands properly

    # now fixup the operand values
    next_pc = addr + offset
    if inst.first_operand is not None:
        d.operands.append(_figure_operand(inst.mnemonic, inst.first_operand, m, next_pc))   
        if inst.second_operand is not None:
            d.operands.append(_figure_operand(inst.mnemonic, inst.second_operand, m, next_pc))

    d.length = offset
    return d


# print(decode_instruction(b'\x6f\x90', 0xbee))
