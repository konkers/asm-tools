use nom::{character::complete::space0, IResult};

use super::{
    addr_mode_absolute, addr_mode_absolute_x, addr_mode_absolute_y, addr_mode_accumulator,
    addr_mode_block_transfer, addr_mode_immediate, addr_mode_immediate_absolute,
    addr_mode_immediate_absolute_x, addr_mode_immediate_zero_page, addr_mode_immediate_zero_page_x,
    addr_mode_implied, addr_mode_indexed_indirect, addr_mode_indexed_indirect16,
    addr_mode_indirect, addr_mode_indirect_indexed, addr_mode_relative, addr_mode_zero_page,
    addr_mode_zero_page_relative, addr_mode_zero_page_x, addr_mode_zero_page_y, mnemonic, Address,
    Instruction, Mnemonic,
};

fn op<M: 'static + Fn(&str) -> IResult<&str, Address>>(
    m: Mnemonic,
    opcode: u8,
    addr_mode: &'static M,
) -> Box<dyn Fn(&str) -> IResult<&str, Instruction>> {
    let matcher = mnemonic(m.clone());
    Box::new(move |i: &str| -> IResult<&str, Instruction> {
        let (i, _) = matcher(i)?;
        let (i, _) = space0(i)?;
        let (i, addr) = addr_mode(i)?;

        Ok((
            i,
            Instruction {
                mnemonic: m.clone(),
                opcode: opcode,
                addr,
            },
        ))
    })
}

fn add_alu_op(
    mnemonic: Mnemonic,
    opcode_base: u8,
    table: &mut Vec<Box<dyn Fn(&str) -> IResult<&str, Instruction>>>,
) {
    let opcode_base = opcode_base & 0xe0;

    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x11,
        &addr_mode_indirect_indexed,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x01,
        &addr_mode_indexed_indirect,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x12,
        &addr_mode_indirect,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x19,
        &addr_mode_absolute_y,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x1d,
        &addr_mode_absolute_x,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x0d,
        &addr_mode_absolute,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x15,
        &addr_mode_zero_page_x,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x05,
        &addr_mode_zero_page,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x09,
        &addr_mode_immediate,
    ));
}

fn add_limited_alu_op(
    mnemonic: Mnemonic,
    opcode_base: u8,
    table: &mut Vec<Box<dyn Fn(&str) -> IResult<&str, Instruction>>>,
) {
    let opcode_base = opcode_base & 0xe0;

    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x1e,
        &addr_mode_absolute_x,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x0e,
        &addr_mode_absolute,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x16,
        &addr_mode_zero_page_x,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x06,
        &addr_mode_zero_page,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0xa,
        &addr_mode_accumulator,
    ));
}

fn add_limited_immediate_op(
    mnemonic: Mnemonic,
    opcode_base: u8,
    immediate_opcode: u8,
    table: &mut Vec<Box<dyn Fn(&str) -> IResult<&str, Instruction>>>,
) {
    let opcode_base = opcode_base & 0xe8;

    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x18,
        &addr_mode_absolute_x,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x08,
        &addr_mode_absolute,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x10,
        &addr_mode_zero_page_x,
    ));
    table.push(op(
        mnemonic.clone(),
        opcode_base | 0x00,
        &addr_mode_zero_page,
    ));
    table.push(op(mnemonic.clone(), immediate_opcode, &addr_mode_immediate));
}

fn add_bit_op(
    mnemonic: Mnemonic,
    table: &mut Vec<Box<dyn Fn(&str) -> IResult<&str, Instruction>>>,
) {
    table.push(op(mnemonic.clone(), 0x3c, &addr_mode_absolute_x));
    table.push(op(mnemonic.clone(), 0x2c, &addr_mode_absolute));
    table.push(op(mnemonic.clone(), 0x34, &addr_mode_zero_page_x));
    table.push(op(mnemonic.clone(), 0x24, &addr_mode_zero_page));
    table.push(op(mnemonic.clone(), 0x89, &addr_mode_immediate));
}

pub(super) fn get_huc6280_instruction_table() -> Vec<Box<dyn Fn(&str) -> IResult<&str, Instruction>>>
{
    let mut table = Vec::new();
    add_alu_op(Mnemonic::Adc, 0x60, &mut table);
    add_alu_op(Mnemonic::And, 0x20, &mut table);
    add_limited_alu_op(Mnemonic::Asl, 0x00, &mut table);

    for i in 0..8 {
        table.push(op(
            Mnemonic::Bbr(i),
            0x0f | (i << 4),
            &addr_mode_zero_page_relative,
        ));
    }

    for i in 0..8 {
        table.push(op(
            Mnemonic::Bbs(i),
            0x8f | (i << 4),
            &addr_mode_zero_page_relative,
        ));
    }

    table.push(op(Mnemonic::Bcc, 0x90, &addr_mode_relative));
    table.push(op(Mnemonic::Bcs, 0xb0, &addr_mode_relative));
    table.push(op(Mnemonic::Beq, 0xf0, &addr_mode_relative));

    add_bit_op(Mnemonic::Bit, &mut table);

    table.push(op(Mnemonic::Bmi, 0x30, &addr_mode_relative));
    table.push(op(Mnemonic::Bne, 0xd0, &addr_mode_relative));
    table.push(op(Mnemonic::Bpl, 0x10, &addr_mode_relative));
    table.push(op(Mnemonic::Bra, 0x80, &addr_mode_relative));

    table.push(op(Mnemonic::Brk, 0x00, &addr_mode_implied));

    table.push(op(Mnemonic::Bsr, 0x44, &addr_mode_relative));
    table.push(op(Mnemonic::Bvc, 0x50, &addr_mode_relative));
    table.push(op(Mnemonic::Bvs, 0x70, &addr_mode_relative));

    table.push(op(Mnemonic::Cla, 0x62, &addr_mode_implied));
    table.push(op(Mnemonic::Clc, 0x18, &addr_mode_implied));
    table.push(op(Mnemonic::Cld, 0xd8, &addr_mode_implied));
    table.push(op(Mnemonic::Cli, 0x58, &addr_mode_implied));
    table.push(op(Mnemonic::Clv, 0xb8, &addr_mode_implied));
    table.push(op(Mnemonic::Clx, 0x82, &addr_mode_implied));
    table.push(op(Mnemonic::Cly, 0xc2, &addr_mode_implied));

    add_alu_op(Mnemonic::Cmp, 0xc0, &mut table);

    table.push(op(Mnemonic::Cpx, 0xec, &addr_mode_absolute));
    table.push(op(Mnemonic::Cpx, 0xe4, &addr_mode_zero_page));
    table.push(op(Mnemonic::Cpx, 0xe0, &addr_mode_immediate));

    table.push(op(Mnemonic::Cpy, 0xcc, &addr_mode_absolute));
    table.push(op(Mnemonic::Cpy, 0xc4, &addr_mode_zero_page));
    table.push(op(Mnemonic::Cpy, 0xc0, &addr_mode_immediate));

    table.push(op(Mnemonic::Csh, 0xd4, &addr_mode_implied));
    table.push(op(Mnemonic::Csl, 0x54, &addr_mode_implied));

    table.push(op(Mnemonic::Dec, 0xde, &addr_mode_absolute_x));
    table.push(op(Mnemonic::Dec, 0xce, &addr_mode_absolute));
    table.push(op(Mnemonic::Dec, 0xd6, &addr_mode_zero_page_x));
    table.push(op(Mnemonic::Dec, 0xc6, &addr_mode_zero_page));

    table.push(op(Mnemonic::Dex, 0xca, &addr_mode_implied));
    table.push(op(Mnemonic::Dey, 0x88, &addr_mode_implied));

    add_alu_op(Mnemonic::Eor, 0x40, &mut table);

    // Inc is almost a limited ALU op but it's accumulator mode
    // opcode does not follow the pattern
    table.push(op(Mnemonic::Inc, 0xfe, &addr_mode_absolute_x));
    table.push(op(Mnemonic::Inc, 0xee, &addr_mode_absolute));
    table.push(op(Mnemonic::Inc, 0xf6, &addr_mode_zero_page_x));
    table.push(op(Mnemonic::Inc, 0xe6, &addr_mode_zero_page));
    table.push(op(Mnemonic::Inc, 0x1a, &addr_mode_accumulator));

    table.push(op(Mnemonic::Inx, 0xe8, &addr_mode_implied));
    table.push(op(Mnemonic::Iny, 0xc8, &addr_mode_implied));

    table.push(op(Mnemonic::Jmp, 0x7c, &addr_mode_indexed_indirect16));
    table.push(op(Mnemonic::Jmp, 0x6c, &addr_mode_indirect));
    table.push(op(Mnemonic::Jmp, 0x4c, &addr_mode_absolute));

    table.push(op(Mnemonic::Jsr, 0x20, &addr_mode_absolute));

    add_alu_op(Mnemonic::Lda, 0xa0, &mut table);

    table.push(op(Mnemonic::Ldx, 0xbe, &addr_mode_absolute_y));
    table.push(op(Mnemonic::Ldx, 0xae, &addr_mode_absolute));
    table.push(op(Mnemonic::Ldx, 0xb6, &addr_mode_zero_page_y));
    table.push(op(Mnemonic::Ldx, 0xa6, &addr_mode_zero_page));
    table.push(op(Mnemonic::Ldx, 0xa2, &addr_mode_immediate));

    table.push(op(Mnemonic::Ldy, 0xbc, &addr_mode_absolute_x));
    table.push(op(Mnemonic::Ldy, 0xac, &addr_mode_absolute));
    table.push(op(Mnemonic::Ldy, 0xb4, &addr_mode_zero_page_x));
    table.push(op(Mnemonic::Ldy, 0xa4, &addr_mode_zero_page));
    table.push(op(Mnemonic::Ldy, 0xa0, &addr_mode_immediate));

    add_limited_alu_op(Mnemonic::Lsr, 0x40, &mut table);

    table.push(op(Mnemonic::Nop, 0xea, &addr_mode_implied));

    add_alu_op(Mnemonic::Ora, 0x00, &mut table);

    table.push(op(Mnemonic::Pha, 0x48, &addr_mode_implied));
    table.push(op(Mnemonic::Php, 0x08, &addr_mode_implied));
    table.push(op(Mnemonic::Phx, 0xda, &addr_mode_implied));
    table.push(op(Mnemonic::Phy, 0x5a, &addr_mode_implied));
    table.push(op(Mnemonic::Pla, 0x68, &addr_mode_implied));
    table.push(op(Mnemonic::Plp, 0x28, &addr_mode_implied));
    table.push(op(Mnemonic::Plx, 0xfa, &addr_mode_implied));
    table.push(op(Mnemonic::Ply, 0x7a, &addr_mode_implied));

    for i in 0..8 {
        table.push(op(Mnemonic::Rmb(i), 0x07 | (i << 4), &addr_mode_zero_page));
    }

    add_limited_alu_op(Mnemonic::Rol, 0x20, &mut table);
    add_limited_alu_op(Mnemonic::Ror, 0x60, &mut table);

    table.push(op(Mnemonic::Rti, 0x40, &addr_mode_implied));
    table.push(op(Mnemonic::Rts, 0x60, &addr_mode_implied));
    table.push(op(Mnemonic::Sax, 0x22, &addr_mode_implied));
    table.push(op(Mnemonic::Say, 0x42, &addr_mode_implied));

    add_alu_op(Mnemonic::Sbc, 0xe0, &mut table);

    table.push(op(Mnemonic::Sec, 0x38, &addr_mode_implied));
    table.push(op(Mnemonic::Sed, 0xf8, &addr_mode_implied));
    table.push(op(Mnemonic::Sei, 0x78, &addr_mode_implied));
    table.push(op(Mnemonic::Set, 0xf4, &addr_mode_implied));

    for i in 0..8 {
        table.push(op(Mnemonic::Smb(i), 0x87 | (i << 4), &addr_mode_zero_page));
    }

    for i in 0..3 {
        table.push(op(Mnemonic::St(i), 0x03 | (i << 4), &addr_mode_immediate));
    }

    // STA is like a normal alu op excpet it does not have an absolute mode.
    // Since It's the only instruction like this, we just code it out here.
    table.push(op(Mnemonic::Sta, 0x91, &addr_mode_indirect_indexed));
    table.push(op(Mnemonic::Sta, 0x81, &addr_mode_indexed_indirect));
    table.push(op(Mnemonic::Sta, 0x92, &addr_mode_indirect));
    table.push(op(Mnemonic::Sta, 0x99, &addr_mode_absolute_y));
    table.push(op(Mnemonic::Sta, 0x9d, &addr_mode_absolute_x));
    table.push(op(Mnemonic::Sta, 0x8d, &addr_mode_absolute));
    table.push(op(Mnemonic::Sta, 0x95, &addr_mode_zero_page_x));
    table.push(op(Mnemonic::Sta, 0x85, &addr_mode_zero_page));

    table.push(op(Mnemonic::Stx, 0x8e, &addr_mode_absolute));
    table.push(op(Mnemonic::Stx, 0x96, &addr_mode_zero_page_x));
    table.push(op(Mnemonic::Stx, 0x86, &addr_mode_zero_page));

    table.push(op(Mnemonic::Sty, 0x8c, &addr_mode_absolute));
    table.push(op(Mnemonic::Sty, 0x94, &addr_mode_zero_page_x));
    table.push(op(Mnemonic::Sty, 0x84, &addr_mode_zero_page));

    table.push(op(Mnemonic::Stz, 0x9e, &addr_mode_absolute_x));
    table.push(op(Mnemonic::Stz, 0x9c, &addr_mode_absolute));
    table.push(op(Mnemonic::Stz, 0x74, &addr_mode_zero_page_x));
    table.push(op(Mnemonic::Stz, 0x64, &addr_mode_zero_page));

    table.push(op(Mnemonic::Sxy, 0x02, &addr_mode_implied));

    table.push(op(Mnemonic::Tai, 0xf3, &addr_mode_block_transfer));

    table.push(op(Mnemonic::Tam, 0x53, &addr_mode_immediate));

    table.push(op(Mnemonic::Tax, 0xaa, &addr_mode_implied));
    table.push(op(Mnemonic::Tay, 0xa8, &addr_mode_implied));

    table.push(op(Mnemonic::Tdd, 0xc3, &addr_mode_block_transfer));
    table.push(op(Mnemonic::Tia, 0xe3, &addr_mode_block_transfer));
    table.push(op(Mnemonic::Tii, 0x73, &addr_mode_block_transfer));
    table.push(op(Mnemonic::Tin, 0xd3, &addr_mode_block_transfer));

    table.push(op(Mnemonic::Tma, 0x43, &addr_mode_immediate));

    table.push(op(Mnemonic::Trb, 0x1c, &addr_mode_absolute));
    table.push(op(Mnemonic::Trb, 0x14, &addr_mode_zero_page));

    table.push(op(Mnemonic::Tsb, 0x0c, &addr_mode_absolute));
    table.push(op(Mnemonic::Tsb, 0x04, &addr_mode_zero_page));

    table.push(op(Mnemonic::Tst, 0xb3, &addr_mode_immediate_absolute_x));
    table.push(op(Mnemonic::Tst, 0x93, &addr_mode_immediate_absolute));
    table.push(op(Mnemonic::Tst, 0xa3, &addr_mode_immediate_zero_page_x));
    table.push(op(Mnemonic::Tst, 0x83, &addr_mode_immediate_zero_page));

    table.push(op(Mnemonic::Tsx, 0xba, &addr_mode_implied));
    table.push(op(Mnemonic::Txa, 0x8a, &addr_mode_implied));
    table.push(op(Mnemonic::Txs, 0x9a, &addr_mode_implied));
    table.push(op(Mnemonic::Tya, 0x98, &addr_mode_implied));

    table
}
