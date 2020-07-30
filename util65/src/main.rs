use asm65::parser::parse;
use failure::Error;

fn main() -> Result<(), Error> {
    let lines = parse("adc $45")?;

    println!("output: {:#x?}", lines);

    Ok(())
}
