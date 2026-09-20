//! Reading `--flag value` pairs out of a command line — one copy for every
//! subcommand, so a change to how a flag is spelled is made once.

/// The value following the first `name`, if both are there.
pub fn value_of(arguments: &[String], name: &str) -> Option<String> {
    arguments.iter().position(|argument| argument == name).and_then(|at| arguments.get(at + 1)).cloned()
}

#[cfg(test)]
mod tests {
    use super::value_of;

    #[test]
    fn the_value_is_the_word_after_the_flag() {
        let arguments: Vec<String> = ["add", "--person", "Jane Doe"].iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(value_of(&arguments, "--person").as_deref(), Some("Jane Doe"));
        assert_eq!(value_of(&arguments, "--grant"), None);
        assert_eq!(value_of(&arguments[..2], "--person"), None, "a flag with nothing after it");
    }
}
