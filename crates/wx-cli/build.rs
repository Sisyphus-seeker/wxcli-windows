use vergen_gitcl::{Build, Emitter, Gitcl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build = Build::builder().build_date(true).use_local(true).build();
    let gitcl = Gitcl::builder().sha(true).build();

    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&gitcl)?
        .emit()?;

    Ok(())
}
