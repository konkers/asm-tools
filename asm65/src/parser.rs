use failure::format_err;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_till, take_while, take_while_m_n},
    character::complete::{line_ending, space0, space1},
    combinator::{map_res, opt},
    error::{FromExternalError, ParseError},
    multi::separated_list0,
    IResult,
};
use nom_locate::LocatedSpan;
use num_traits::Num;
use strum::IntoStaticStr;

mod huc6280;
mod inst_table;

use huc6280::get_huc6280_instruction_table;
use inst_table::InstructionTable;

type Span<'a> = LocatedSpan<&'a str>;

#[derive(Clone, Debug, PartialEq)]
struct Error<I> {
    pub kind: ErrorKind<I>,
    errors: Vec<Error<I>>,
}

#[derive(Clone, Debug, PartialEq)]
enum ErrorKind<I> {
    Nom(I, nom::error::ErrorKind),
    UnknownMnemonic(I, String),
    UnsupportedAddressMode(I, Mnemonic, AddressMode),
    UnexpectedInput(I, String),
}

impl<I> Error<I> {
    fn unknown_mnemonic(i: I, mnemonic: String) -> nom::Err<Error<I>> {
        nom::Err::Error(Self {
            kind: ErrorKind::UnknownMnemonic(i, mnemonic),
            errors: Vec::new(),
        })
    }

    fn unsupported_address_mode(i: I, mnemonic: Mnemonic, mode: AddressMode) -> nom::Err<Error<I>> {
        nom::Err::Error(Self {
            kind: ErrorKind::UnsupportedAddressMode(i, mnemonic, mode),
            errors: Vec::new(),
        })
    }

    fn unexpected_input(i: I, input: String) -> nom::Err<Error<I>> {
        nom::Err::Error(Self {
            kind: ErrorKind::UnexpectedInput(i, input),
            errors: Vec::new(),
        })
    }
}

impl<I> nom::error::ParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self {
            kind: ErrorKind::Nom(input, kind),
            errors: Vec::new(),
        }
    }

    fn append(input: I, kind: nom::error::ErrorKind, mut other: Self) -> Self {
        other.errors.push(Self::from_error_kind(input, kind));
        other
    }
}

impl<I> From<(I, nom::error::ErrorKind)> for Error<I> {
    fn from(e: (I, nom::error::ErrorKind)) -> Error<I> {
        Error::from_error_kind(e.0, e.1)
    }
}

impl<I, E> FromExternalError<I, E> for Error<I> {
    /// Create a new error from an input position and an external error
    fn from_external_error(input: I, kind: nom::error::ErrorKind, _e: E) -> Self {
        Self::from_error_kind(input, kind)
    }
}

type ParserResult<'a, T> = IResult<Span<'a>, T, Error<Span<'a>>>;

#[derive(Clone, Copy, Debug, Eq, Hash, IntoStaticStr, PartialEq)]
pub enum Mnemonic {
    Adc,
    And,
    Asl,
    Bbr(u8),
    Bbs(u8),
    Bcc,
    Bcs,
    Beq,
    Bit,
    Bmi,
    Bne,
    Bpl,
    Bra,
    Brk,
    Bsr,
    Bvc,
    Bvs,
    Cla,
    Clc,
    Cld,
    Cli,
    Clv,
    Clx,
    Cly,
    Cmp,
    Cpx,
    Cpy,
    Csh,
    Csl,
    Dec,
    Dex,
    Dey,
    Eor,
    Inc,
    Inx,
    Iny,
    Jmp,
    Jsr,
    Lda,
    Ldx,
    Ldy,
    Lsr,
    Nop,
    Ora,
    Pha,
    Php,
    Phx,
    Phy,
    Pla,
    Plp,
    Plx,
    Ply,
    Rmb(u8),
    Rol,
    Ror,
    Rti,
    Rts,
    Sax,
    Say,
    Sbc,
    Sec,
    Sed,
    Sei,
    Set,
    Smb(u8),
    St(u8),
    Sta,
    Stx,
    Sty,
    Stz,
    Sxy,
    Tai,
    Tam,
    Tax,
    Tay,
    Tdd,
    Tia,
    Tii,
    Tin,
    Tma,
    Trb,
    Tsb,
    Tst,
    Tsx,
    Txa,
    Txs,
    Tya,
}

impl From<Mnemonic> for String {
    fn from(m: Mnemonic) -> String {
        match m {
            Mnemonic::Bbr(num)
            | Mnemonic::Bbs(num)
            | Mnemonic::Rmb(num)
            | Mnemonic::Smb(num)
            | Mnemonic::St(num) => {
                let s: &'static str = (&m).into();
                format!("{}{}", s, num)
            }
            _ => {
                let s: &'static str = (&m).into();
                s.into()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressMode {
    Implied,
    Accumulator,
    Relative,
    Immediate,
    ImmediateZeroPage,
    ImmediateZeroPageX,
    ImmediateAbsolute,
    ImmediateAbsoluteX,
    ZeroPage,
    ZeroPageX,
    ZeroPageY,
    ZeroPageRelative,
    Absolute,
    AbsoluteX,
    AbsoluteY,
    Indirect,
    IndexedIndirect,
    IndexedIndirect16,
    IndirectIndexed,
    BlockTransfer,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Address {
    Implied,
    Accumulator,
    Relative(u8),
    Immediate(u8),
    ImmediateZeroPage(u8, u8),
    ImmediateZeroPageX(u8, u8),
    ImmediateAbsolute(u8, u16),
    ImmediateAbsoluteX(u8, u16),
    ZeroPage(u8),
    ZeroPageX(u8),
    ZeroPageY(u8),
    ZeroPageRelative(u8, u8),
    Absolute(u16),
    AbsoluteX(u16),
    AbsoluteY(u16),
    Indirect(u16),
    IndexedIndirect(u8),
    IndexedIndirect16(u16),
    IndirectIndexed(u8),
    BlockTransfer(u16, u16, u16),
}

impl Address {
    fn mode(&self) -> AddressMode {
        match self {
            Self::Implied => AddressMode::Implied,
            Self::Accumulator => AddressMode::Accumulator,
            Self::Relative(_) => AddressMode::Relative,
            Self::Immediate(_) => AddressMode::Immediate,
            Self::ImmediateZeroPage(_, _) => AddressMode::ImmediateZeroPage,
            Self::ImmediateZeroPageX(_, _) => AddressMode::ImmediateZeroPageX,
            Self::ImmediateAbsolute(_, _) => AddressMode::ImmediateAbsolute,
            Self::ImmediateAbsoluteX(_, _) => AddressMode::ImmediateAbsoluteX,
            Self::ZeroPage(_) => AddressMode::ZeroPage,
            Self::ZeroPageX(_) => AddressMode::ZeroPageX,
            Self::ZeroPageY(_) => AddressMode::ZeroPageY,
            Self::ZeroPageRelative(_, _) => AddressMode::ZeroPageRelative,
            Self::Absolute(_) => AddressMode::Absolute,
            Self::AbsoluteX(_) => AddressMode::AbsoluteX,
            Self::AbsoluteY(_) => AddressMode::AbsoluteY,
            Self::Indirect(_) => AddressMode::Indirect,
            Self::IndexedIndirect(_) => AddressMode::IndexedIndirect,
            Self::IndexedIndirect16(_) => AddressMode::IndexedIndirect16,
            Self::IndirectIndexed(_) => AddressMode::IndirectIndexed,
            Self::BlockTransfer(_, _, _) => AddressMode::BlockTransfer,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Instruction {
    mnemonic: Mnemonic,
    opcode: u8,
    addr: Address,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Line {
    inst: Option<Instruction>,
    comment: Option<String>,
}

fn from_hex<T: Num>(input: Span) -> Result<T, T::FromStrRadixErr> {
    T::from_str_radix(input.fragment(), 16)
}

fn is_hex_digit(c: char) -> bool {
    c.is_digit(16)
}

fn hex_u8(i: Span) -> ParserResult<u8> {
    map_res(take_while_m_n(2, 2, is_hex_digit), from_hex)(i)
}

fn hex_u16(i: Span) -> ParserResult<u16> {
    map_res(take_while_m_n(4, 4, is_hex_digit), from_hex)(i)
}

fn parens<T, F>(f: F) -> impl Fn(Span) -> ParserResult<T>
where
    F: Fn(Span) -> ParserResult<T>,
{
    move |i: Span| {
        let (i, _) = tag("(")(i)?;
        let (i, _) = space0(i)?;
        let (i, val) = f(i)?;
        let (i, _) = space0(i)?;
        let (i, _) = tag(")")(i)?;

        Ok((i, val))
    }
}

fn comma(i: Span) -> ParserResult<()> {
    let (i, _) = space0(i)?;
    let (i, _) = tag(",")(i)?;
    let (i, _) = space0(i)?;
    Ok((i, ()))
}

fn addr_mode_implied(i: Span) -> ParserResult<Address> {
    Ok((i, Address::Implied))
}

fn addr_mode_accumulator(i: Span) -> ParserResult<Address> {
    let (i, _) = alt((tag("a"), tag("A")))(i)?;
    Ok((i, Address::Accumulator))
}

fn indexed_x(i: Span) -> ParserResult<()> {
    let (i, _) = comma(i)?;
    let (i, _) = alt((tag("x"), tag("X")))(i)?;
    Ok((i, ()))
}

fn indexed_y(i: Span) -> ParserResult<()> {
    let (i, _) = comma(i)?;
    let (i, _) = alt((tag("y"), tag("Y")))(i)?;
    Ok((i, ()))
}

fn addr_mode_immediate(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("#$")(i)?;
    let (i, addr) = hex_u8(i)?;

    Ok((i, Address::Immediate(addr)))
}

fn addr_mode_immediate_zero_page(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("#$")(i)?;
    let (i, val) = hex_u8(i)?;
    let (i, _) = comma(i)?;
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u8(i)?;

    Ok((i, Address::ImmediateZeroPage(val, addr)))
}

fn addr_mode_immediate_zero_page_x(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("#$")(i)?;
    let (i, val) = hex_u8(i)?;
    let (i, _) = comma(i)?;
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u8(i)?;
    let (i, _) = indexed_x(i)?;

    Ok((i, Address::ImmediateZeroPageX(val, addr)))
}

fn addr_mode_immediate_absolute(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("#$")(i)?;
    let (i, val) = hex_u8(i)?;
    let (i, _) = comma(i)?;
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u16(i)?;

    Ok((i, Address::ImmediateAbsolute(val, addr)))
}

fn addr_mode_immediate_absolute_x(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("#$")(i)?;
    let (i, val) = hex_u8(i)?;
    let (i, _) = comma(i)?;
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u16(i)?;
    let (i, _) = indexed_x(i)?;

    Ok((i, Address::ImmediateAbsoluteX(val, addr)))
}

fn addr_mode_zero_page(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u8(i)?;

    Ok((i, Address::ZeroPage(addr)))
}

fn addr_mode_zero_page_x(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u8(i)?;
    let (i, _) = indexed_x(i)?;

    Ok((i, Address::ZeroPageX(addr)))
}

fn addr_mode_zero_page_y(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u8(i)?;
    let (i, _) = indexed_y(i)?;

    Ok((i, Address::ZeroPageY(addr)))
}

fn addr_mode_zero_page_relative(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u8(i)?;

    let (i, _) = comma(i)?;

    let (i, _) = tag("$")(i)?;
    let (i, offset) = hex_u8(i)?;

    Ok((i, Address::ZeroPageRelative(addr, offset)))
}

fn addr_mode_absolute(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u16(i)?;

    Ok((i, Address::Absolute(addr)))
}

fn addr_mode_absolute_x(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u16(i)?;
    let (i, _) = indexed_x(i)?;

    Ok((i, Address::AbsoluteX(addr)))
}

fn addr_mode_absolute_y(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("$")(i)?;
    let (i, addr) = hex_u16(i)?;
    let (i, _) = indexed_y(i)?;

    Ok((i, Address::AbsoluteY(addr)))
}

fn addr_mode_indirect(i: Span) -> ParserResult<Address> {
    parens(|i: Span| {
        let (i, _) = tag("$")(i)?;
        let (i, addr) = hex_u16(i)?;

        Ok((i, Address::Indirect(addr)))
    })(i)
}

fn addr_mode_indexed_indirect(i: Span) -> ParserResult<Address> {
    parens(|i: Span| {
        let (i, _) = tag("$")(i)?;
        let (i, addr) = hex_u8(i)?;
        let (i, _) = indexed_x(i)?;

        Ok((i, Address::IndexedIndirect(addr)))
    })(i)
}

fn addr_mode_indexed_indirect16(i: Span) -> ParserResult<Address> {
    parens(|i: Span| {
        let (i, _) = tag("$")(i)?;
        let (i, addr) = hex_u16(i)?;
        let (i, _) = indexed_x(i)?;

        Ok((i, Address::IndexedIndirect16(addr)))
    })(i)
}

fn addr_mode_indirect_indexed(i: Span) -> ParserResult<Address> {
    let (i, addr) = parens(|i: Span| {
        let (i, _) = tag("$")(i)?;
        hex_u8(i)
    })(i)?;
    let (i, _) = indexed_y(i)?;
    Ok((i, Address::IndirectIndexed(addr)))
}

fn addr_mode_block_transfer(i: Span) -> ParserResult<Address> {
    let (i, _) = tag("$")(i)?;
    let (i, src_addr) = hex_u16(i)?;
    let (i, _) = comma(i)?;
    let (i, _) = tag("$")(i)?;
    let (i, dst_addr) = hex_u16(i)?;
    let (i, _) = comma(i)?;
    let (i, _) = tag("$")(i)?;
    let (i, len) = hex_u16(i)?;

    Ok((i, Address::BlockTransfer(src_addr, dst_addr, len)))
}

fn address(i: Span) -> ParserResult<Address> {
    alt((
        addr_mode_block_transfer,
        addr_mode_indirect_indexed,
        addr_mode_indexed_indirect,
        addr_mode_indexed_indirect16,
        addr_mode_indirect,
        addr_mode_absolute_y,
        addr_mode_absolute_x,
        addr_mode_absolute,
        addr_mode_zero_page_relative,
        addr_mode_zero_page_y,
        addr_mode_zero_page_x,
        addr_mode_zero_page,
        addr_mode_immediate_absolute_x,
        addr_mode_immediate_absolute,
        addr_mode_immediate_zero_page_x,
        addr_mode_immediate_zero_page,
        addr_mode_immediate,
        addr_mode_accumulator,
        addr_mode_implied,
    ))(i)
}

fn is_mnemonic_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

fn comment(i: Span) -> ParserResult<String> {
    let (i, _) = space0(i)?;
    let (i, _) = tag(";")(i)?;
    let (i, content) = take_till(|c| c == '\n' || c == '\r')(i)?;

    Ok((i, content.fragment().to_string()))
}

fn mnemonic<'a>(inst_table: &InstructionTable, i: Span<'a>) -> ParserResult<'a, Mnemonic> {
    let (i, mnemonic_str) = take_while(is_mnemonic_char)(i)?;
    let mnemonic_str = mnemonic_str.fragment().to_lowercase();

    match inst_table.mnemonic_map.get(&mnemonic_str) {
        Some(mnemonic) => Ok((i, *mnemonic)),
        None => Err(Error::unknown_mnemonic(i, mnemonic_str)),
    }
}

fn instruction<'a>(
    inst_table: &'a InstructionTable,
) -> impl Fn(Span<'a>) -> ParserResult<'a, Instruction> {
    move |i: Span<'a>| {
        let (i, mnemonic) = mnemonic(inst_table, i)?;

        let (i, addr) = opt(|i: Span<'a>| -> ParserResult<Address> {
            let (i, _) = space1(i)?;
            address(i)
        })(i)?;

        let mut addr = addr.unwrap_or(Address::Implied);
        let mut mode = addr.mode();

        // ZeroPage and Relative have the same text representation.  ZeroPage
        // takes precedence in the parsing so we need to fix it up here
        // for instructions with Relative addresses.
        if let Address::ZeroPage(val) = addr {
            if inst_table.instructions[&mnemonic]
                .address_modes
                .contains_key(&AddressMode::Relative)
            {
                mode = AddressMode::Relative;
                addr = Address::Relative(val);
            }
        }

        let opcode = match inst_table.instructions[&mnemonic].address_modes.get(&mode) {
            Some(opcode) => *opcode,
            None => return Err(Error::unsupported_address_mode(i, mnemonic, mode)),
        };

        Ok((
            i,
            Instruction {
                mnemonic,
                opcode,
                addr,
            },
        ))
    }
}

fn line<'a>(inst_table: &'a InstructionTable) -> impl Fn(Span<'a>) -> ParserResult<'a, Line> {
    move |i: Span<'a>| {
        // Pull out all text until a comment
        let (i, pre_comment) = take_till(|c| c == ';')(i)?;

        // Parse the instruction and any whitespace after.
        let (pre_comment, inst) = instruction(inst_table)(pre_comment)?;
        let (pre_comment, _) = space0(pre_comment)?;

        // Error on any text left between the instructions and the
        // comment/newline.
        if !pre_comment.fragment().is_empty() {
            return Err(Error::unexpected_input(
                pre_comment,
                pre_comment.fragment().to_string(),
            ));
        }

        // Parse the comment
        let (i, comment_text) = opt(comment)(i)?;
        Ok((
            i,
            Line {
                inst: Some(inst),
                comment: comment_text,
            },
        ))
    }
}

pub fn parse(src: &str) -> Result<Vec<Line>, failure::Error> {
    let table = get_huc6280_instruction_table()?;
    let i = Span::new(src);
    let (i, lines) = separated_list0(line_ending, line(&table))(i)
        .map_err(|e| format_err!("Parse error: {}", e))?;

    if !i.fragment().is_empty() {
        return Err(format_err!("Unexpected input: {}", i.fragment()));
    }

    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use failure::format_err;
    use std::panic;

    #[test]
    fn test_from_external_error() {
        assert_eq!(
            Error::from_external_error("", nom::error::ErrorKind::Tag, format_err!("error")),
            Error {
                kind: ErrorKind::Nom("", nom::error::ErrorKind::Tag),
                errors: Vec::new()
            }
        );
    }

    #[test]
    fn test_relative_address_mode() {
        assert_eq!(Address::Relative(0xa5).mode(), AddressMode::Relative);
    }

    fn test_addr_mode<F: Fn(Span) -> ParserResult<Address>>(
        f: F,
        inputs: &[&'static str],
        expected: Address,
    ) -> Result<(), failure::Error> {
        for input in inputs {
            let res = f(Span::new(input)).map_err(|e| format_err!("parse error: {:?}", e))?;

            if !res.0.fragment().is_empty() {
                return Err(format_err!(
                    "Parsing {} left input {}",
                    input,
                    *res.0.fragment()
                ));
            }

            if res.1 != expected {
                return Err(format_err!(
                    "parsing {}: {:x?} != {:x?}",
                    input,
                    &res,
                    &expected
                ));
            }
        }

        Ok(())
    }

    #[test]
    fn test_addr_mode_parse_error() {
        let res = test_addr_mode(addr_mode_accumulator, &["B"], Address::Accumulator);
        println!("{:?}", res);
        assert!(res.is_err());
    }

    #[test]
    fn test_addr_mode_input_left() {
        assert!(test_addr_mode(addr_mode_accumulator, &["AB"], Address::Accumulator).is_err());
    }

    #[test]
    fn test_addr_mode_wrong_mode() {
        assert!(test_addr_mode(addr_mode_accumulator, &["A"], Address::Implied).is_err());
    }

    #[test]
    fn addr_modes() -> Result<(), failure::Error> {
        test_addr_mode(addr_mode_implied, &[""], Address::Implied)?;

        test_addr_mode(addr_mode_accumulator, &["A", "a"], Address::Accumulator)?;

        test_addr_mode(
            addr_mode_immediate,
            &["#$a5", "#$A5"],
            Address::Immediate(0xa5),
        )?;

        test_addr_mode(
            addr_mode_zero_page,
            &["$a5", "$A5"],
            Address::ZeroPage(0xa5),
        )?;

        test_addr_mode(
            addr_mode_zero_page_x,
            &["$a5,x", "$a5,X", "$a5 ,x", "$a5 , x", "$a5, x"],
            Address::ZeroPageX(0xa5),
        )?;

        test_addr_mode(
            addr_mode_zero_page_y,
            &["$a5,y", "$a5,Y", "$a5 ,y", "$a5 , y", "$a5, y"],
            Address::ZeroPageY(0xa5),
        )?;

        test_addr_mode(
            addr_mode_zero_page_relative,
            &["$a5,$5a", "$a5 ,$5a", "$a5, $5a", "$a5 ,$5a"],
            Address::ZeroPageRelative(0xa5, 0x5a),
        )?;

        test_addr_mode(
            addr_mode_absolute,
            &["$a55a", "$A55a"],
            Address::Absolute(0xa55a),
        )?;

        test_addr_mode(
            addr_mode_absolute_x,
            &["$a55a,x", "$a55a,X", "$a55a ,x", "$a55a, x", "$a55a , x"],
            Address::AbsoluteX(0xa55a),
        )?;

        test_addr_mode(
            addr_mode_absolute_y,
            &["$a55a,y", "$a55a,Y", "$a55a ,y", "$a55a, y", "$a55a , y"],
            Address::AbsoluteY(0xa55a),
        )?;

        test_addr_mode(
            addr_mode_indirect,
            &["($a55a)", "($A55a)", "( $a55a)", "($a55a )", "( $a55a )"],
            Address::Indirect(0xa55a),
        )?;

        test_addr_mode(
            addr_mode_indexed_indirect,
            &[
                "($a5,x)",
                "($A5,X)",
                "( $a5,x)",
                "($a5,x )",
                "( $a5,x )",
                "($a5, x)",
                "($a5,x )",
                "($a5, x )",
            ],
            Address::IndexedIndirect(0xa5),
        )?;

        test_addr_mode(
            addr_mode_indirect_indexed,
            &[
                "($a5),y",
                "($A5),Y",
                "( $a5),y",
                "($a5 ),y",
                "( $a5 ),y",
                "($a5), y",
                "($a5) ,y",
                "($a5) , y",
            ],
            Address::IndirectIndexed(0xa5),
        )?;

        test_addr_mode(
            addr_mode_block_transfer,
            &[
                "$a55a,$5aa5,$a5a5",
                "$a55a ,$5aa5,$a5a5",
                "$a55a, $5aa5,$a5a5",
                "$a55a , $5aa5,$a5a5",
                "$a55a,$5aa5 ,$a5a5",
                "$a55a ,$5aa5 ,$a5a5",
                "$a55a, $5aa5 ,$a5a5",
                "$a55a , $5aa5 ,$a5a5",
                "$a55a,$5aa5, $a5a5",
                "$a55a ,$5aa5, $a5a5",
                "$a55a, $5aa5, $a5a5",
                "$a55a , $5aa5, $a5a5",
                "$a55a,$5aa5 , $a5a5",
                "$a55a, $5aa5 , $a5a5",
                "$a55a ,$5aa5 , $a5a5",
                "$a55a , $5aa5 , $a5a5",
            ],
            Address::BlockTransfer(0xa55a, 0x5aa5, 0xa5a5),
        )?;

        // By now we're pretty sure commas and whitespace work so we'll stop
        // enumerating all the combinations.

        test_addr_mode(
            addr_mode_immediate_zero_page,
            &["#$a5, $a5"],
            Address::ImmediateZeroPage(0xa5, 0xa5),
        )?;
        test_addr_mode(
            addr_mode_immediate_zero_page_x,
            &["#$a5, $a5, x"],
            Address::ImmediateZeroPageX(0xa5, 0xa5),
        )?;
        test_addr_mode(
            addr_mode_immediate_absolute,
            &["#$a5, $a55a"],
            Address::ImmediateAbsolute(0xa5, 0xa55a),
        )?;
        test_addr_mode(
            addr_mode_immediate_absolute_x,
            &["#$a5, $a55a, x"],
            Address::ImmediateAbsoluteX(0xa5, 0xa55a),
        )?;

        Ok(())
    }

    fn test_mnemonic(
        table: &InstructionTable,
        mnemonic_str: &str,
        expected: Mnemonic,
    ) -> Result<(), failure::Error> {
        let res = mnemonic(&table, Span::new(mnemonic_str))
            .map_err(|e| format_err!("Parsing {} returned error {:?}.", mnemonic_str, e))?;

        if !res.0.fragment().is_empty() {
            return Err(format_err!(
                "Parsing {} left input {}",
                mnemonic_str,
                *res.0.fragment()
            ));
        }

        if res.1 != expected {
            return Err(format_err!(
                "parsing {}: {:x?} != {:x?}",
                mnemonic_str,
                &res,
                &expected
            ));
        }

        Ok(())
    }

    #[test]
    fn mnemonic_matching() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_mnemonic(&table, "adc", Mnemonic::Adc)?;
        test_mnemonic(&table, "Adc", Mnemonic::Adc)?;
        test_mnemonic(&table, "ADC", Mnemonic::Adc)?;

        test_mnemonic(&table, "bbr0", Mnemonic::Bbr(0))?;
        test_mnemonic(&table, "bbs1", Mnemonic::Bbs(1))?;
        test_mnemonic(&table, "rmb3", Mnemonic::Rmb(3))?;
        test_mnemonic(&table, "smb4", Mnemonic::Smb(4))?;
        test_mnemonic(&table, "st2", Mnemonic::St(2))?;

        Ok(())
    }

    #[test]
    fn test_unknown_mnemonic() {
        let table = get_huc6280_instruction_table().unwrap();
        let res = mnemonic(&table, Span::new("zzz"));
        assert!(res.is_err());
    }

    #[test]
    fn mnemonic_errors() {
        let table = get_huc6280_instruction_table().unwrap();
        assert!(test_mnemonic(&table, "nop", Mnemonic::Adc).is_err());
        assert!(test_mnemonic(&table, "adc1", Mnemonic::Adc).is_err());
        assert!(test_mnemonic(&table, "adc 1", Mnemonic::Adc).is_err());
    }

    fn test_asm_line(
        table: &InstructionTable,
        asm: &str,
        mnemonic: &Mnemonic,
        opcode: u8,
        addr: Address,
    ) -> Result<(), failure::Error> {
        let res = line(&table)(Span::new(asm))
            .map_err(|e| format_err!("Parsing {} returned error {:?}.", asm, e))?;

        let expected = Line {
            inst: Some(Instruction {
                mnemonic: *mnemonic,
                opcode,
                addr,
            }),
            comment: None,
        };
        if res.1 != expected {
            return Err(format_err!(
                "parsing {}: {:x?} != {:x?}",
                asm,
                &res,
                &expected
            ));
        }

        Ok(())
    }

    struct AluOpcodes {
        immediate: u8,
        zero_page: u8,
        zero_page_x: u8,
        absolute: u8,
        absolute_x: u8,
        absolute_y: u8,
        indirect: u8,
        indexed_indirect: u8,
        indirect_indexed: u8,
    }

    fn test_alu_line(
        table: &InstructionTable,
        inst_str: &str,
        mnemonic: &Mnemonic,
        opcodes: AluOpcodes,
    ) -> Result<(), failure::Error> {
        test_asm_line(
            &table,
            &*format!("{} #$a5", inst_str),
            mnemonic,
            opcodes.immediate,
            Address::Immediate(0xa5),
        )?;

        test_asm_line(
            &table,
            &*format!("{} $a5", inst_str),
            mnemonic,
            opcodes.zero_page,
            Address::ZeroPage(0xa5),
        )?;

        test_asm_line(
            &table,
            &*format!("{} $a5, X", inst_str),
            mnemonic,
            opcodes.zero_page_x,
            Address::ZeroPageX(0xa5),
        )?;

        test_asm_line(
            &table,
            &*format!("{} $a55a", inst_str),
            mnemonic,
            opcodes.absolute,
            Address::Absolute(0xa55a),
        )?;

        test_asm_line(
            &table,
            &*format!("{} $a55a, X", inst_str),
            mnemonic,
            opcodes.absolute_x,
            Address::AbsoluteX(0xa55a),
        )?;

        test_asm_line(
            &table,
            &*format!("{} $a55a, Y", inst_str),
            mnemonic,
            opcodes.absolute_y,
            Address::AbsoluteY(0xa55a),
        )?;

        test_asm_line(
            &table,
            &*format!("{} ($a55a)", inst_str),
            mnemonic,
            opcodes.indirect,
            Address::Indirect(0xa55a),
        )?;

        test_asm_line(
            &table,
            &*format!("{} ($a5, X)", inst_str),
            mnemonic,
            opcodes.indexed_indirect,
            Address::IndexedIndirect(0xa5),
        )?;

        test_asm_line(
            &table,
            &*format!("{} ($a5), Y", inst_str),
            mnemonic,
            opcodes.indirect_indexed,
            Address::IndirectIndexed(0xa5),
        )?;

        Ok(())
    }

    struct LimitedAluOpcodes {
        accumulator: u8,
        zero_page: u8,
        zero_page_x: u8,
        absolute: u8,
        absolute_x: u8,
    }

    fn test_limited_alu_line(
        table: &InstructionTable,
        inst_str: &str,
        mnemonic: &Mnemonic,
        opcodes: LimitedAluOpcodes,
    ) -> Result<(), failure::Error> {
        test_asm_line(
            &table,
            &*format!("{} A", inst_str),
            mnemonic,
            opcodes.accumulator,
            Address::Accumulator,
        )?;

        test_asm_line(
            &table,
            &*format!("{} $a5", inst_str),
            mnemonic,
            opcodes.zero_page,
            Address::ZeroPage(0xa5),
        )?;

        test_asm_line(
            &table,
            &*format!("{} $a5, X", inst_str),
            mnemonic,
            opcodes.zero_page_x,
            Address::ZeroPageX(0xa5),
        )?;

        test_asm_line(
            &table,
            &*format!("{} $a55a", inst_str),
            mnemonic,
            opcodes.absolute,
            Address::Absolute(0xa55a),
        )?;

        test_asm_line(
            &table,
            &*format!("{} $a55a, X", inst_str),
            mnemonic,
            opcodes.absolute_x,
            Address::AbsoluteX(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_asm_line_parse_error() {
        let table = get_huc6280_instruction_table().unwrap();
        assert!(test_asm_line(&table, "zzz", &Mnemonic::Nop, 0xea, Address::Implied).is_err());
    }

    #[test]
    fn test_asm_line_extra_input() {
        let table = get_huc6280_instruction_table().unwrap();
        assert!(test_asm_line(&table, "nop fds", &Mnemonic::Nop, 0xea, Address::Implied).is_err());
    }

    #[test]
    fn test_asm_line_wrong_result() {
        let table = get_huc6280_instruction_table().unwrap();
        assert!(test_asm_line(&table, "brk", &Mnemonic::Nop, 0xea, Address::Implied).is_err());
    }

    #[test]
    fn test_line_wrong_addr() {
        let table = get_huc6280_instruction_table().unwrap();
        let res = line(&table)(Span::new("iny $a55a, x"));
        println!("{:?}", res);
        assert!(res.is_err());
    }

    #[test]
    fn test_adc_line() -> Result<(), failure::Error> {
        test_alu_line(
            &get_huc6280_instruction_table().unwrap(),
            "adc",
            &Mnemonic::Adc,
            AluOpcodes {
                immediate: 0x69,
                zero_page: 0x65,
                zero_page_x: 0x75,
                absolute: 0x6d,
                absolute_x: 0x7d,
                absolute_y: 0x79,
                indirect: 0x72,
                indexed_indirect: 0x61,
                indirect_indexed: 0x71,
            },
        )?;
        Ok(())
    }

    #[test]
    fn test_and_line() -> Result<(), failure::Error> {
        test_alu_line(
            &get_huc6280_instruction_table().unwrap(),
            "and",
            &Mnemonic::And,
            AluOpcodes {
                immediate: 0x29,
                zero_page: 0x25,
                zero_page_x: 0x35,
                absolute: 0x2d,
                absolute_x: 0x3d,
                absolute_y: 0x39,
                indirect: 0x32,
                indexed_indirect: 0x21,
                indirect_indexed: 0x31,
            },
        )?;

        Ok(())
    }

    #[test]
    fn test_asl_line() -> Result<(), failure::Error> {
        test_limited_alu_line(
            &get_huc6280_instruction_table().unwrap(),
            "asl",
            &Mnemonic::Asl,
            LimitedAluOpcodes {
                accumulator: 0x0a,
                zero_page: 0x06,
                zero_page_x: 0x16,
                absolute: 0x0e,
                absolute_x: 0x1e,
            },
        )?;
        Ok(())
    }

    #[test]
    fn test_bbr_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        let opcodes = [0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f];
        for i in 0..8 {
            test_asm_line(
                &table,
                &*format!("bbr{} $a5, $5a", i),
                &Mnemonic::Bbr(i),
                opcodes[i as usize],
                Address::ZeroPageRelative(0xa5, 0x5a),
            )?;
        }
        Ok(())
    }

    #[test]
    fn test_bbs_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        let opcodes = [0x8f, 0x9f, 0xaf, 0xbf, 0xcf, 0xdf, 0xef, 0xff];
        for i in 0..8 {
            test_asm_line(
                &table,
                &*format!("bbs{} $a5, $5a", i),
                &Mnemonic::Bbs(i),
                opcodes[i as usize],
                Address::ZeroPageRelative(0xa5, 0x5a),
            )?;
        }

        Ok(())
    }

    #[test]
    fn test_branch_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();

        test_asm_line(
            &table,
            "bcc $a5",
            &Mnemonic::Bcc,
            0x90,
            Address::Relative(0xa5),
        )?;

        test_asm_line(
            &table,
            "bcs $a5",
            &Mnemonic::Bcs,
            0xb0,
            Address::Relative(0xa5),
        )?;

        test_asm_line(
            &table,
            "beq $a5",
            &Mnemonic::Beq,
            0xf0,
            Address::Relative(0xa5),
        )?;

        test_asm_line(
            &table,
            "bmi $a5",
            &Mnemonic::Bmi,
            0x30,
            Address::Relative(0xa5),
        )?;

        test_asm_line(
            &table,
            "bne $a5",
            &Mnemonic::Bne,
            0xd0,
            Address::Relative(0xa5),
        )?;

        test_asm_line(
            &table,
            "bpl $a5",
            &Mnemonic::Bpl,
            0x10,
            Address::Relative(0xa5),
        )?;

        test_asm_line(
            &table,
            "bra $a5",
            &Mnemonic::Bra,
            0x80,
            Address::Relative(0xa5),
        )?;

        test_asm_line(
            &table,
            "bsr $a5",
            &Mnemonic::Bsr,
            0x44,
            Address::Relative(0xa5),
        )?;

        test_asm_line(
            &table,
            "bvc $a5",
            &Mnemonic::Bvc,
            0x50,
            Address::Relative(0xa5),
        )?;

        test_asm_line(
            &table,
            "bvs $a5",
            &Mnemonic::Bvs,
            0x70,
            Address::Relative(0xa5),
        )?;

        Ok(())
    }

    #[test]
    fn test_bit_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();

        test_asm_line(
            &table,
            "bit #$a5",
            &Mnemonic::Bit,
            0x89,
            Address::Immediate(0xa5),
        )?;

        test_asm_line(
            &table,
            "bit $a5",
            &Mnemonic::Bit,
            0x24,
            Address::ZeroPage(0xa5),
        )?;

        test_asm_line(
            &table,
            "bit $a5, X",
            &Mnemonic::Bit,
            0x34,
            Address::ZeroPageX(0xa5),
        )?;

        test_asm_line(
            &table,
            "bit $a55a",
            &Mnemonic::Bit,
            0x2c,
            Address::Absolute(0xa55a),
        )?;

        test_asm_line(
            &table,
            "bit $a55a, X",
            &Mnemonic::Bit,
            0x3c,
            Address::AbsoluteX(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_implied_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();

        test_asm_line(&table, "brk", &Mnemonic::Brk, 0x00, Address::Implied)?;

        test_asm_line(&table, "cla", &Mnemonic::Cla, 0x62, Address::Implied)?;
        test_asm_line(&table, "clc", &Mnemonic::Clc, 0x18, Address::Implied)?;
        test_asm_line(&table, "cld", &Mnemonic::Cld, 0xd8, Address::Implied)?;
        test_asm_line(&table, "cli", &Mnemonic::Cli, 0x58, Address::Implied)?;
        test_asm_line(&table, "clv", &Mnemonic::Clv, 0xb8, Address::Implied)?;
        test_asm_line(&table, "clx", &Mnemonic::Clx, 0x82, Address::Implied)?;
        test_asm_line(&table, "cly", &Mnemonic::Cly, 0xc2, Address::Implied)?;

        test_asm_line(&table, "csh", &Mnemonic::Csh, 0xd4, Address::Implied)?;
        test_asm_line(&table, "csl", &Mnemonic::Csl, 0x54, Address::Implied)?;

        test_asm_line(&table, "dex", &Mnemonic::Dex, 0xca, Address::Implied)?;
        test_asm_line(&table, "dey", &Mnemonic::Dey, 0x88, Address::Implied)?;
        test_asm_line(&table, "inx", &Mnemonic::Inx, 0xe8, Address::Implied)?;
        test_asm_line(&table, "iny", &Mnemonic::Iny, 0xc8, Address::Implied)?;

        test_asm_line(&table, "nop", &Mnemonic::Nop, 0xea, Address::Implied)?;

        test_asm_line(&table, "pha", &Mnemonic::Pha, 0x48, Address::Implied)?;
        test_asm_line(&table, "php", &Mnemonic::Php, 0x08, Address::Implied)?;
        test_asm_line(&table, "phx", &Mnemonic::Phx, 0xda, Address::Implied)?;
        test_asm_line(&table, "phy", &Mnemonic::Phy, 0x5a, Address::Implied)?;
        test_asm_line(&table, "pla", &Mnemonic::Pla, 0x68, Address::Implied)?;
        test_asm_line(&table, "plp", &Mnemonic::Plp, 0x28, Address::Implied)?;
        test_asm_line(&table, "plx", &Mnemonic::Plx, 0xfa, Address::Implied)?;
        test_asm_line(&table, "ply", &Mnemonic::Ply, 0x7a, Address::Implied)?;

        test_asm_line(&table, "rti", &Mnemonic::Rti, 0x40, Address::Implied)?;
        test_asm_line(&table, "rts", &Mnemonic::Rts, 0x60, Address::Implied)?;
        test_asm_line(&table, "sax", &Mnemonic::Sax, 0x22, Address::Implied)?;
        test_asm_line(&table, "say", &Mnemonic::Say, 0x42, Address::Implied)?;

        test_asm_line(&table, "sec", &Mnemonic::Sec, 0x38, Address::Implied)?;
        test_asm_line(&table, "sed", &Mnemonic::Sed, 0xf8, Address::Implied)?;
        test_asm_line(&table, "sei", &Mnemonic::Sei, 0x78, Address::Implied)?;
        test_asm_line(&table, "set", &Mnemonic::Set, 0xf4, Address::Implied)?;

        test_asm_line(&table, "sxy", &Mnemonic::Sxy, 0x02, Address::Implied)?;

        test_asm_line(&table, "tax", &Mnemonic::Tax, 0xaa, Address::Implied)?;
        test_asm_line(&table, "tay", &Mnemonic::Tay, 0xa8, Address::Implied)?;

        test_asm_line(&table, "tsx", &Mnemonic::Tsx, 0xba, Address::Implied)?;
        test_asm_line(&table, "txa", &Mnemonic::Txa, 0x8a, Address::Implied)?;
        test_asm_line(&table, "txs", &Mnemonic::Txs, 0x9a, Address::Implied)?;
        test_asm_line(&table, "tya", &Mnemonic::Tya, 0x98, Address::Implied)?;

        Ok(())
    }

    #[test]
    fn test_cmp_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();

        test_alu_line(
            &table,
            "cmp",
            &Mnemonic::Cmp,
            AluOpcodes {
                immediate: 0xc9,
                zero_page: 0xc5,
                zero_page_x: 0xd5,
                absolute: 0xcd,
                absolute_x: 0xdd,
                absolute_y: 0xd9,
                indirect: 0xd2,
                indexed_indirect: 0xc1,
                indirect_indexed: 0xd1,
            },
        )?;

        test_asm_line(
            &table,
            "cpx #$a5",
            &Mnemonic::Cpx,
            0xe0,
            Address::Immediate(0xa5),
        )?;
        test_asm_line(
            &table,
            "cpx $a5",
            &Mnemonic::Cpx,
            0xe4,
            Address::ZeroPage(0xa5),
        )?;
        test_asm_line(
            &table,
            "cpx $a55a",
            &Mnemonic::Cpx,
            0xec,
            Address::Absolute(0xa55a),
        )?;

        test_asm_line(
            &table,
            "cpy #$a5",
            &Mnemonic::Cpy,
            0xc0,
            Address::Immediate(0xa5),
        )?;
        test_asm_line(
            &table,
            "cpy $a5",
            &Mnemonic::Cpy,
            0xc4,
            Address::ZeroPage(0xa5),
        )?;
        test_asm_line(
            &table,
            "cpy $a55a",
            &Mnemonic::Cpy,
            0xcc,
            Address::Absolute(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_dec_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "dec $a5",
            &Mnemonic::Dec,
            0xc6,
            Address::ZeroPage(0xa5),
        )?;
        test_asm_line(
            &table,
            "dec $a5, X",
            &Mnemonic::Dec,
            0xd6,
            Address::ZeroPageX(0xa5),
        )?;
        test_asm_line(
            &table,
            "dec $a55a",
            &Mnemonic::Dec,
            0xce,
            Address::Absolute(0xa55a),
        )?;
        test_asm_line(
            &table,
            "dec $a55a, X",
            &Mnemonic::Dec,
            0xde,
            Address::AbsoluteX(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_eor_line() -> Result<(), failure::Error> {
        test_alu_line(
            &get_huc6280_instruction_table().unwrap(),
            "eor",
            &Mnemonic::Eor,
            AluOpcodes {
                immediate: 0x49,
                zero_page: 0x45,
                zero_page_x: 0x55,
                absolute: 0x4d,
                absolute_x: 0x5d,
                absolute_y: 0x59,
                indirect: 0x52,
                indexed_indirect: 0x41,
                indirect_indexed: 0x51,
            },
        )?;

        Ok(())
    }

    #[test]
    fn test_inc_line() -> Result<(), failure::Error> {
        test_limited_alu_line(
            &get_huc6280_instruction_table().unwrap(),
            "inc",
            &Mnemonic::Inc,
            LimitedAluOpcodes {
                accumulator: 0x1a,
                zero_page: 0xe6,
                zero_page_x: 0xf6,
                absolute: 0xee,
                absolute_x: 0xfe,
            },
        )?;
        Ok(())
    }

    #[test]
    fn test_jumps_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "jmp $a55a",
            &Mnemonic::Jmp,
            0x4c,
            Address::Absolute(0xa55a),
        )?;
        test_asm_line(
            &table,
            "jmp ($a55a)",
            &Mnemonic::Jmp,
            0x6c,
            Address::Indirect(0xa55a),
        )?;
        test_asm_line(
            &table,
            "jmp ($a55a, X)",
            &Mnemonic::Jmp,
            0x7c,
            Address::IndexedIndirect16(0xa55a),
        )?;

        test_asm_line(
            &table,
            "jsr $a55a",
            &Mnemonic::Jsr,
            0x20,
            Address::Absolute(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_lda_line() -> Result<(), failure::Error> {
        test_alu_line(
            &get_huc6280_instruction_table().unwrap(),
            "lda",
            &Mnemonic::Lda,
            AluOpcodes {
                immediate: 0xa9,
                zero_page: 0xa5,
                zero_page_x: 0xb5,
                absolute: 0xad,
                absolute_x: 0xbd,
                absolute_y: 0xb9,
                indirect: 0xb2,
                indexed_indirect: 0xa1,
                indirect_indexed: 0xb1,
            },
        )?;

        Ok(())
    }

    #[test]
    fn test_ldx_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "ldx #$a5",
            &Mnemonic::Ldx,
            0xa2,
            Address::Immediate(0xa5),
        )?;

        test_asm_line(
            &table,
            "ldx $a5",
            &Mnemonic::Ldx,
            0xa6,
            Address::ZeroPage(0xa5),
        )?;

        test_asm_line(
            &table,
            "ldx $a5, y",
            &Mnemonic::Ldx,
            0xb6,
            Address::ZeroPageY(0xa5),
        )?;

        test_asm_line(
            &table,
            "ldx $a55a",
            &Mnemonic::Ldx,
            0xae,
            Address::Absolute(0xa55a),
        )?;

        test_asm_line(
            &table,
            "ldx $a55a,y",
            &Mnemonic::Ldx,
            0xbe,
            Address::AbsoluteY(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_ldy_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "ldy #$a5",
            &Mnemonic::Ldy,
            0xa0,
            Address::Immediate(0xa5),
        )?;

        test_asm_line(
            &table,
            "ldy $a5",
            &Mnemonic::Ldy,
            0xa4,
            Address::ZeroPage(0xa5),
        )?;

        test_asm_line(
            &table,
            "ldy $a5, x",
            &Mnemonic::Ldy,
            0xb4,
            Address::ZeroPageX(0xa5),
        )?;

        test_asm_line(
            &table,
            "ldy $a55a",
            &Mnemonic::Ldy,
            0xac,
            Address::Absolute(0xa55a),
        )?;

        test_asm_line(
            &table,
            "ldy $a55a,x",
            &Mnemonic::Ldy,
            0xbc,
            Address::AbsoluteX(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_lsr_line() -> Result<(), failure::Error> {
        test_limited_alu_line(
            &get_huc6280_instruction_table().unwrap(),
            "lsr",
            &Mnemonic::Lsr,
            LimitedAluOpcodes {
                accumulator: 0x4a,
                zero_page: 0x46,
                zero_page_x: 0x56,
                absolute: 0x4e,
                absolute_x: 0x5e,
            },
        )?;

        Ok(())
    }

    #[test]
    fn test_ora_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();

        test_alu_line(
            &table,
            "ora",
            &Mnemonic::Ora,
            AluOpcodes {
                immediate: 0x09,
                zero_page: 0x05,
                zero_page_x: 0x15,
                absolute: 0x0d,
                absolute_x: 0x1d,
                absolute_y: 0x19,
                indirect: 0x12,
                indexed_indirect: 0x01,
                indirect_indexed: 0x11,
            },
        )?;

        Ok(())
    }

    #[test]
    fn test_rmb_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        let opcodes = [0x07, 0x17, 0x27, 0x37, 0x47, 0x57, 0x67, 0x77];
        for i in 0..8 {
            test_asm_line(
                &table,
                &*format!("rmb{} $a5", i),
                &Mnemonic::Rmb(i),
                opcodes[i as usize],
                Address::ZeroPage(0xa5),
            )?;
        }

        Ok(())
    }

    #[test]
    fn test_rol_line() -> Result<(), failure::Error> {
        test_limited_alu_line(
            &get_huc6280_instruction_table().unwrap(),
            "rol",
            &Mnemonic::Rol,
            LimitedAluOpcodes {
                accumulator: 0x2a,
                zero_page: 0x26,
                zero_page_x: 0x36,
                absolute: 0x2e,
                absolute_x: 0x3e,
            },
        )?;
        Ok(())
    }

    #[test]
    fn test_ror_line() -> Result<(), failure::Error> {
        test_limited_alu_line(
            &get_huc6280_instruction_table().unwrap(),
            "ror",
            &Mnemonic::Ror,
            LimitedAluOpcodes {
                accumulator: 0x6a,
                zero_page: 0x66,
                zero_page_x: 0x76,
                absolute: 0x6e,
                absolute_x: 0x7e,
            },
        )?;

        Ok(())
    }

    #[test]
    fn test_sbc_line() -> Result<(), failure::Error> {
        test_alu_line(
            &get_huc6280_instruction_table().unwrap(),
            "sbc",
            &Mnemonic::Sbc,
            AluOpcodes {
                immediate: 0xe9,
                zero_page: 0xe5,
                zero_page_x: 0xf5,
                absolute: 0xed,
                absolute_x: 0xfd,
                absolute_y: 0xf9,
                indirect: 0xf2,
                indexed_indirect: 0xe1,
                indirect_indexed: 0xf1,
            },
        )?;

        Ok(())
    }

    #[test]
    fn test_smb_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        let opcodes = [0x87, 0x97, 0xa7, 0xb7, 0xc7, 0xd7, 0xe7, 0xf7];
        for i in 0..8 {
            test_asm_line(
                &table,
                &*format!("smb{} $a5", i),
                &Mnemonic::Smb(i),
                opcodes[i as usize],
                Address::ZeroPage(0xa5),
            )?;
        }

        Ok(())
    }

    #[test]
    fn test_st_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        let opcodes = [0x03, 0x13, 0x23];
        for i in 0..3 {
            test_asm_line(
                &table,
                &*format!("st{} #$a5", i),
                &Mnemonic::St(i),
                opcodes[i as usize],
                Address::Immediate(0xa5),
            )?;
        }

        Ok(())
    }

    #[test]
    fn test_sta_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "sta $a5",
            &Mnemonic::Sta,
            0x85,
            Address::ZeroPage(0xa5),
        )?;

        test_asm_line(
            &table,
            "sta $a5, X",
            &Mnemonic::Sta,
            0x95,
            Address::ZeroPageX(0xa5),
        )?;

        test_asm_line(
            &table,
            "sta $a55a",
            &Mnemonic::Sta,
            0x8d,
            Address::Absolute(0xa55a),
        )?;

        test_asm_line(
            &table,
            "sta $a55a, X",
            &Mnemonic::Sta,
            0x9d,
            Address::AbsoluteX(0xa55a),
        )?;

        test_asm_line(
            &table,
            "sta $a55a, Y",
            &Mnemonic::Sta,
            0x99,
            Address::AbsoluteY(0xa55a),
        )?;

        test_asm_line(
            &table,
            "sta ($a55a)",
            &Mnemonic::Sta,
            0x92,
            Address::Indirect(0xa55a),
        )?;

        test_asm_line(
            &table,
            "sta ($a5, X)",
            &Mnemonic::Sta,
            0x81,
            Address::IndexedIndirect(0xa5),
        )?;

        test_asm_line(
            &table,
            "sta ($a5), Y",
            &Mnemonic::Sta,
            0x91,
            Address::IndirectIndexed(0xa5),
        )?;

        Ok(())
    }

    #[test]
    fn test_stx_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();

        test_asm_line(
            &table,
            "stx $a5",
            &Mnemonic::Stx,
            0x86,
            Address::ZeroPage(0xa5),
        )?;

        test_asm_line(
            &table,
            "stx $a5, X",
            &Mnemonic::Stx,
            0x96,
            Address::ZeroPageX(0xa5),
        )?;

        test_asm_line(
            &table,
            "stx $a55a",
            &Mnemonic::Stx,
            0x8e,
            Address::Absolute(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_sty_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();

        test_asm_line(
            &table,
            "sty $a5",
            &Mnemonic::Sty,
            0x84,
            Address::ZeroPage(0xa5),
        )?;

        test_asm_line(
            &table,
            "sty $a5, X",
            &Mnemonic::Sty,
            0x94,
            Address::ZeroPageX(0xa5),
        )?;

        test_asm_line(
            &table,
            "sty $a55a",
            &Mnemonic::Sty,
            0x8c,
            Address::Absolute(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_stz_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();

        test_asm_line(
            &table,
            "stz $a5",
            &Mnemonic::Stz,
            0x64,
            Address::ZeroPage(0xa5),
        )?;

        test_asm_line(
            &table,
            "stz $a5, X",
            &Mnemonic::Stz,
            0x74,
            Address::ZeroPageX(0xa5),
        )?;

        test_asm_line(
            &table,
            "stz $a55a",
            &Mnemonic::Stz,
            0x9c,
            Address::Absolute(0xa55a),
        )?;

        test_asm_line(
            &table,
            "stz $a55a, x",
            &Mnemonic::Stz,
            0x9e,
            Address::AbsoluteX(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_transfer_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "tai $a55a, $5a5a, $5aa5",
            &Mnemonic::Tai,
            0xf3,
            Address::BlockTransfer(0xa55a, 0x5a5a, 0x5aa5),
        )?;
        test_asm_line(
            &table,
            "tdd $a55a, $5a5a, $5aa5",
            &Mnemonic::Tdd,
            0xc3,
            Address::BlockTransfer(0xa55a, 0x5a5a, 0x5aa5),
        )?;
        test_asm_line(
            &table,
            "tia $a55a, $5a5a, $5aa5",
            &Mnemonic::Tia,
            0xe3,
            Address::BlockTransfer(0xa55a, 0x5a5a, 0x5aa5),
        )?;
        test_asm_line(
            &table,
            "tii $a55a, $5a5a, $5aa5",
            &Mnemonic::Tii,
            0x73,
            Address::BlockTransfer(0xa55a, 0x5a5a, 0x5aa5),
        )?;
        test_asm_line(
            &table,
            "tin $a55a, $5a5a, $5aa5",
            &Mnemonic::Tin,
            0xd3,
            Address::BlockTransfer(0xa55a, 0x5a5a, 0x5aa5),
        )?;

        Ok(())
    }

    #[test]
    fn test_tam_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "tam #$a5",
            &Mnemonic::Tam,
            0x53,
            Address::Immediate(0xa5),
        )?;

        Ok(())
    }

    #[test]
    fn test_tma_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "tma #$a5",
            &Mnemonic::Tma,
            0x43,
            Address::Immediate(0xa5),
        )?;

        Ok(())
    }

    #[test]
    fn test_trb_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "trb $a5",
            &Mnemonic::Trb,
            0x14,
            Address::ZeroPage(0xa5),
        )?;
        test_asm_line(
            &table,
            "trb $a55a",
            &Mnemonic::Trb,
            0x1c,
            Address::Absolute(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_tsb_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "tsb $a5",
            &Mnemonic::Tsb,
            0x04,
            Address::ZeroPage(0xa5),
        )?;
        test_asm_line(
            &table,
            "tsb $a55a",
            &Mnemonic::Tsb,
            0x0c,
            Address::Absolute(0xa55a),
        )?;

        Ok(())
    }

    #[test]
    fn test_tst_line() -> Result<(), failure::Error> {
        let table = get_huc6280_instruction_table().unwrap();
        test_asm_line(
            &table,
            "tst #$a5, $5a",
            &Mnemonic::Tst,
            0x83,
            Address::ImmediateZeroPage(0xa5, 0x5a),
        )?;
        test_asm_line(
            &table,
            "tst #$a5, $5a, x",
            &Mnemonic::Tst,
            0xa3,
            Address::ImmediateZeroPageX(0xa5, 0x5a),
        )?;
        test_asm_line(
            &table,
            "tst #$a5, $5aa5",
            &Mnemonic::Tst,
            0x93,
            Address::ImmediateAbsolute(0xa5, 0x5aa5),
        )?;
        test_asm_line(
            &table,
            "tst #$a5, $5aa5, x",
            &Mnemonic::Tst,
            0xb3,
            Address::ImmediateAbsoluteX(0xa5, 0x5aa5),
        )?;

        Ok(())
    }

    #[test]
    fn test_parser() {
        let lines = parse("adc $45").unwrap();
        assert_eq!(
            lines,
            vec![Line {
                inst: Some(Instruction {
                    mnemonic: Mnemonic::Adc,
                    opcode: 0x65,
                    addr: Address::ZeroPage(0x45,),
                }),
                comment: None,
            }]
        );
        let lines = parse("adc $45 ; Comment\nadc $45").unwrap();
        assert_eq!(
            lines,
            vec![
                Line {
                    inst: Some(Instruction {
                        mnemonic: Mnemonic::Adc,
                        opcode: 0x65,
                        addr: Address::ZeroPage(0x45,),
                    }),
                    comment: Some(" Comment".to_string()),
                },
                Line {
                    inst: Some(Instruction {
                        mnemonic: Mnemonic::Adc,
                        opcode: 0x65,
                        addr: Address::ZeroPage(0x45,),
                    }),
                    comment: None,
                }
            ]
        );

        assert!(parse("adc $45 1").is_err());
    }
}
