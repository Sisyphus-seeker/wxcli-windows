pub fn cmd_doctor(fix: bool) -> Result<(), Box<dyn std::error::Error>> {
    let checks = wx_keychain::all_preflight_checks();

    let all_passed = checks.iter().all(|c| c.passed);

    for c in &checks {
        let icon = if c.passed { "\u{2705}" } else { "\u{2717}" };
        println!("{icon}  {:<24} {}", c.name, c.detail);
    }

    if fix && !all_passed {
        println!("\n--- Fix commands ---");
        let mut has_fix = false;
        for c in &checks {
            if !c.passed {
                if let Some(ref cmd) = c.fix_cmd {
                    println!("\n# Fix: {}", c.name);
                    println!("{cmd}");
                    has_fix = true;
                }
            }
        }
        if !has_fix {
            println!("(no automatic fixes available)");
        }
    }

    if all_passed {
        println!("\nAll checks passed.");
    }

    Ok(())
}
