use failure::Error;

use super::{inst_table::InstructionTable, AddressMode, Mnemonic};

fn add_alu_op(
    mnemonic: Mnemonic,
    opcode_base: u8,
    table: &mut InstructionTable,
) -> Result<(), Error> {
    let opcode_base = opcode_base & 0xe0;

    table.add_op(mnemonic, opcode_base | 0x11, AddressMode::IndirectIndexed)?;
    table.add_op(mnemonic, opcode_base | 0x01, AddressMode::IndexedIndirect)?;
    table.add_op(mnemonic, opcode_base | 0x12, AddressMode::Indirect)?;
    table.add_op(mnemonic, opcode_base | 0x19, AddressMode::AbsoluteY)?;
    table.add_op(mnemonic, opcode_base | 0x1d, AddressMode::AbsoluteX)?;
    table.add_op(mnemonic, opcode_base | 0x0d, AddressMode::Absolute)?;
    table.add_op(mnemonic, opcode_base | 0x15, AddressMode::ZeroPageX)?;
    table.add_op(mnemonic, opcode_base | 0x05, AddressMode::ZeroPage)?;
    table.add_op(mnemonic, opcode_base | 0x09, AddressMode::Immediate)?;

    Ok(())
}

fn add_limited_alu_op(
    mnemonic: Mnemonic,
    opcode_base: u8,
    table: &mut InstructionTable,
) -> Result<(), Error> {
    let opcode_base = opcode_base & 0xe0;

    table.add_op(mnemonic, opcode_base | 0x1e, AddressMode::AbsoluteX)?;
    table.add_op(mnemonic, opcode_base | 0x0e, AddressMode::Absolute)?;
    table.add_op(mnemonic, opcode_base | 0x16, AddressMode::ZeroPageX)?;
    table.add_op(mnemonic, opcode_base | 0x06, AddressMode::ZeroPage)?;
    table.add_op(mnemonic, opcode_base | 0xa, AddressMode::Accumulator)?;

    Ok(())
}

fn add_bit_op(mnemonic: Mnemonic, table: &mut InstructionTable) -> Result<(), Error> {
    table.add_op(mnemonic, 0x3c, AddressMode::AbsoluteX)?;
    table.add_op(mnemonic, 0x2c, AddressMode::Absolute)?;
    table.add_op(mnemonic, 0x34, AddressMode::ZeroPageX)?;
    table.add_op(mnemonic, 0x24, AddressMode::ZeroPage)?;
    table.add_op(mnemonic, 0x89, AddressMode::Immediate)?;

    Ok(())
}

pub(super) fn get_huc6280_instruction_table() -> Result<InstructionTable, Error> {
    let mut table = InstructionTable::new();
    add_alu_op(Mnemonic::Adc, 0x60, &mut table)?;
    add_alu_op(Mnemonic::And, 0x20, &mut table)?;
    add_limited_alu_op(Mnemonic::Asl, 0x00, &mut table)?;

    for i in 0..8 {
        table.add_op(
            Mnemonic::Bbr(i),
            0x0f | (i << 4),
            AddressMode::ZeroPageRelative,
        )?;
    }

    for i in 0..8 {
        table.add_op(
            Mnemonic::Bbs(i),
            0x8f | (i << 4),
            AddressMode::ZeroPageRelative,
        )?;
    }

    table.add_op(Mnemonic::Bcc, 0x90, AddressMode::Relative)?;
    table.add_op(Mnemonic::Bcs, 0xb0, AddressMode::Relative)?;
    table.add_op(Mnemonic::Beq, 0xf0, AddressMode::Relative)?;

    add_bit_op(Mnemonic::Bit, &mut table)?;

    table.add_op(Mnemonic::Bmi, 0x30, AddressMode::Relative)?;
    table.add_op(Mnemonic::Bne, 0xd0, AddressMode::Relative)?;
    table.add_op(Mnemonic::Bpl, 0x10, AddressMode::Relative)?;
    table.add_op(Mnemonic::Bra, 0x80, AddressMode::Relative)?;

    table.add_op(Mnemonic::Brk, 0x00, AddressMode::Implied)?;

    table.add_op(Mnemonic::Bsr, 0x44, AddressMode::Relative)?;
    table.add_op(Mnemonic::Bvc, 0x50, AddressMode::Relative)?;
    table.add_op(Mnemonic::Bvs, 0x70, AddressMode::Relative)?;

    table.add_op(Mnemonic::Cla, 0x62, AddressMode::Implied)?;
    table.add_op(Mnemonic::Clc, 0x18, AddressMode::Implied)?;
    table.add_op(Mnemonic::Cld, 0xd8, AddressMode::Implied)?;
    table.add_op(Mnemonic::Cli, 0x58, AddressMode::Implied)?;
    table.add_op(Mnemonic::Clv, 0xb8, AddressMode::Implied)?;
    table.add_op(Mnemonic::Clx, 0x82, AddressMode::Implied)?;
    table.add_op(Mnemonic::Cly, 0xc2, AddressMode::Implied)?;

    add_alu_op(Mnemonic::Cmp, 0xc0, &mut table)?;

    table.add_op(Mnemonic::Cpx, 0xec, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Cpx, 0xe4, AddressMode::ZeroPage)?;
    table.add_op(Mnemonic::Cpx, 0xe0, AddressMode::Immediate)?;

    table.add_op(Mnemonic::Cpy, 0xcc, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Cpy, 0xc4, AddressMode::ZeroPage)?;
    table.add_op(Mnemonic::Cpy, 0xc0, AddressMode::Immediate)?;

    table.add_op(Mnemonic::Csh, 0xd4, AddressMode::Implied)?;
    table.add_op(Mnemonic::Csl, 0x54, AddressMode::Implied)?;

    table.add_op(Mnemonic::Dec, 0xde, AddressMode::AbsoluteX)?;
    table.add_op(Mnemonic::Dec, 0xce, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Dec, 0xd6, AddressMode::ZeroPageX)?;
    table.add_op(Mnemonic::Dec, 0xc6, AddressMode::ZeroPage)?;

    table.add_op(Mnemonic::Dex, 0xca, AddressMode::Implied)?;
    table.add_op(Mnemonic::Dey, 0x88, AddressMode::Implied)?;

    add_alu_op(Mnemonic::Eor, 0x40, &mut table)?;

    // Inc is almost a limited ALU op but it's accumulator mode
    // opcode does not follow the pattern
    table.add_op(Mnemonic::Inc, 0xfe, AddressMode::AbsoluteX)?;
    table.add_op(Mnemonic::Inc, 0xee, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Inc, 0xf6, AddressMode::ZeroPageX)?;
    table.add_op(Mnemonic::Inc, 0xe6, AddressMode::ZeroPage)?;
    table.add_op(Mnemonic::Inc, 0x1a, AddressMode::Accumulator)?;

    table.add_op(Mnemonic::Inx, 0xe8, AddressMode::Implied)?;
    table.add_op(Mnemonic::Iny, 0xc8, AddressMode::Implied)?;

    table.add_op(Mnemonic::Jmp, 0x7c, AddressMode::IndexedIndirect16)?;
    table.add_op(Mnemonic::Jmp, 0x6c, AddressMode::Indirect)?;
    table.add_op(Mnemonic::Jmp, 0x4c, AddressMode::Absolute)?;

    table.add_op(Mnemonic::Jsr, 0x20, AddressMode::Absolute)?;

    add_alu_op(Mnemonic::Lda, 0xa0, &mut table)?;

    table.add_op(Mnemonic::Ldx, 0xbe, AddressMode::AbsoluteY)?;
    table.add_op(Mnemonic::Ldx, 0xae, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Ldx, 0xb6, AddressMode::ZeroPageY)?;
    table.add_op(Mnemonic::Ldx, 0xa6, AddressMode::ZeroPage)?;
    table.add_op(Mnemonic::Ldx, 0xa2, AddressMode::Immediate)?;

    table.add_op(Mnemonic::Ldy, 0xbc, AddressMode::AbsoluteX)?;
    table.add_op(Mnemonic::Ldy, 0xac, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Ldy, 0xb4, AddressMode::ZeroPageX)?;
    table.add_op(Mnemonic::Ldy, 0xa4, AddressMode::ZeroPage)?;
    table.add_op(Mnemonic::Ldy, 0xa0, AddressMode::Immediate)?;

    add_limited_alu_op(Mnemonic::Lsr, 0x40, &mut table)?;

    table.add_op(Mnemonic::Nop, 0xea, AddressMode::Implied)?;

    add_alu_op(Mnemonic::Ora, 0x00, &mut table)?;

    table.add_op(Mnemonic::Pha, 0x48, AddressMode::Implied)?;
    table.add_op(Mnemonic::Php, 0x08, AddressMode::Implied)?;
    table.add_op(Mnemonic::Phx, 0xda, AddressMode::Implied)?;
    table.add_op(Mnemonic::Phy, 0x5a, AddressMode::Implied)?;
    table.add_op(Mnemonic::Pla, 0x68, AddressMode::Implied)?;
    table.add_op(Mnemonic::Plp, 0x28, AddressMode::Implied)?;
    table.add_op(Mnemonic::Plx, 0xfa, AddressMode::Implied)?;
    table.add_op(Mnemonic::Ply, 0x7a, AddressMode::Implied)?;

    for i in 0..8 {
        table.add_op(Mnemonic::Rmb(i), 0x07 | (i << 4), AddressMode::ZeroPage)?;
    }

    add_limited_alu_op(Mnemonic::Rol, 0x20, &mut table)?;
    add_limited_alu_op(Mnemonic::Ror, 0x60, &mut table)?;

    table.add_op(Mnemonic::Rti, 0x40, AddressMode::Implied)?;
    table.add_op(Mnemonic::Rts, 0x60, AddressMode::Implied)?;
    table.add_op(Mnemonic::Sax, 0x22, AddressMode::Implied)?;
    table.add_op(Mnemonic::Say, 0x42, AddressMode::Implied)?;

    add_alu_op(Mnemonic::Sbc, 0xe0, &mut table)?;

    table.add_op(Mnemonic::Sec, 0x38, AddressMode::Implied)?;
    table.add_op(Mnemonic::Sed, 0xf8, AddressMode::Implied)?;
    table.add_op(Mnemonic::Sei, 0x78, AddressMode::Implied)?;
    table.add_op(Mnemonic::Set, 0xf4, AddressMode::Implied)?;

    for i in 0..8 {
        table.add_op(Mnemonic::Smb(i), 0x87 | (i << 4), AddressMode::ZeroPage)?;
    }

    for i in 0..3 {
        table.add_op(Mnemonic::St(i), 0x03 | (i << 4), AddressMode::Immediate)?;
    }

    // STA is like a normal alu op excpet it does not have an absolute mode.
    // Since It's the only instruction like this, we just code it out here.
    table.add_op(Mnemonic::Sta, 0x91, AddressMode::IndirectIndexed)?;
    table.add_op(Mnemonic::Sta, 0x81, AddressMode::IndexedIndirect)?;
    table.add_op(Mnemonic::Sta, 0x92, AddressMode::Indirect)?;
    table.add_op(Mnemonic::Sta, 0x99, AddressMode::AbsoluteY)?;
    table.add_op(Mnemonic::Sta, 0x9d, AddressMode::AbsoluteX)?;
    table.add_op(Mnemonic::Sta, 0x8d, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Sta, 0x95, AddressMode::ZeroPageX)?;
    table.add_op(Mnemonic::Sta, 0x85, AddressMode::ZeroPage)?;

    table.add_op(Mnemonic::Stx, 0x8e, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Stx, 0x96, AddressMode::ZeroPageX)?;
    table.add_op(Mnemonic::Stx, 0x86, AddressMode::ZeroPage)?;

    table.add_op(Mnemonic::Sty, 0x8c, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Sty, 0x94, AddressMode::ZeroPageX)?;
    table.add_op(Mnemonic::Sty, 0x84, AddressMode::ZeroPage)?;

    table.add_op(Mnemonic::Stz, 0x9e, AddressMode::AbsoluteX)?;
    table.add_op(Mnemonic::Stz, 0x9c, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Stz, 0x74, AddressMode::ZeroPageX)?;
    table.add_op(Mnemonic::Stz, 0x64, AddressMode::ZeroPage)?;

    table.add_op(Mnemonic::Sxy, 0x02, AddressMode::Implied)?;

    table.add_op(Mnemonic::Tai, 0xf3, AddressMode::BlockTransfer)?;

    table.add_op(Mnemonic::Tam, 0x53, AddressMode::Immediate)?;

    table.add_op(Mnemonic::Tax, 0xaa, AddressMode::Implied)?;
    table.add_op(Mnemonic::Tay, 0xa8, AddressMode::Implied)?;

    table.add_op(Mnemonic::Tdd, 0xc3, AddressMode::BlockTransfer)?;
    table.add_op(Mnemonic::Tia, 0xe3, AddressMode::BlockTransfer)?;
    table.add_op(Mnemonic::Tii, 0x73, AddressMode::BlockTransfer)?;
    table.add_op(Mnemonic::Tin, 0xd3, AddressMode::BlockTransfer)?;

    table.add_op(Mnemonic::Tma, 0x43, AddressMode::Immediate)?;

    table.add_op(Mnemonic::Trb, 0x1c, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Trb, 0x14, AddressMode::ZeroPage)?;

    table.add_op(Mnemonic::Tsb, 0x0c, AddressMode::Absolute)?;
    table.add_op(Mnemonic::Tsb, 0x04, AddressMode::ZeroPage)?;

    table.add_op(Mnemonic::Tst, 0xb3, AddressMode::ImmediateAbsoluteX)?;
    table.add_op(Mnemonic::Tst, 0x93, AddressMode::ImmediateAbsolute)?;
    table.add_op(Mnemonic::Tst, 0xa3, AddressMode::ImmediateZeroPageX)?;
    table.add_op(Mnemonic::Tst, 0x83, AddressMode::ImmediateZeroPage)?;

    table.add_op(Mnemonic::Tsx, 0xba, AddressMode::Implied)?;
    table.add_op(Mnemonic::Txa, 0x8a, AddressMode::Implied)?;
    table.add_op(Mnemonic::Txs, 0x9a, AddressMode::Implied)?;
    table.add_op(Mnemonic::Tya, 0x98, AddressMode::Implied)?;

    Ok(table)
}
