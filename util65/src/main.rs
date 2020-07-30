use failure::Error;
use asm65::parser::parse;

fn main() -> Result<(), Error> {
    let lines = parse("adc $45")?;

    println!("output: {:#x?}", lines);

    Ok(())
}
