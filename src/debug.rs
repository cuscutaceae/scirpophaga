fn uc_dump(uc: &Unicorn<'_, ()>, start: u64, len: usize) -> Result<(), unicorn_engine::uc_error> {
    let mut buf = vec![0u8; len];
    uc.mem_read(start, &mut buf)?;
    dump_print(&buf, start.try_into().unwrap(), len);
    Ok(())
}

fn dump_print(mem: &[u8], start: usize, len: usize) {
    println!("                 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F   0123456789ABCDEF");
    let mut cursor = 0usize;
    while cursor < len {
        let base_str = format!("{:016X} ", start + cursor);
        let hexes: Vec<_> = mem.iter().skip(cursor).take(16).map(Option::from).collect();
        let len = hexes.len();
        let hexes: Vec<_> = hexes
            .into_iter()
            .chain(iter::repeat_n(Option::None, 16 - len))
            .collect();
        print!("{base_str}");
        for it in &hexes {
            match it {
                Some(u) => print!("{:02X}", *u),
                None => print!("- "),
            }
            print!(" ");
        }
        print!(" ");
        for it in &hexes {
            if let Some(it) = it {
                print!(
                    "{}",
                    if it.is_ascii() {
                        match it {
                            32..=126 => **it as char,
                            _ => '.',
                        }
                    } else {
                        '.'
                    }
                );
            } else {
                print!(" ",);
            }
        }
        println!();
        cursor += 16;
    }
}
