pub(crate) const NAMED_CHAR_HEX: &[(&str, &str)] = &[
    ("nul", "0"),
    ("null_byte", "0"),
    ("zero_byte", "0"),
    ("newline", "a"),
    ("enter", "a"),
    ("nl", "a"),
    ("line_feed", "a"),
    ("lf", "a"),
    ("carriage_return", "d"),
    ("cr", "d"),
    ("crlf", "d a"),
    ("tab", "9"),
    ("sp", "20"),
    ("space", "20"),
    ("pipe", "7c"),
    ("left_brace", "7b"),
    ("lbrace", "7b"),
    ("right_brace", "7d"),
    ("rbrace", "7d"),
    ("left_paren", "28"),
    ("lp", "28"),
    ("lparen", "28"),
    ("right_paren", "29"),
    ("rparen", "29"),
    ("rp", "29"),
    ("left_bracket", "5b"),
    ("lbracket", "5b"),
    ("right_bracket", "5d"),
    ("rbracket", "5d"),
    ("single_quote", "27"),
    ("squote", "27"),
    ("sq", "27"),
    ("double_quote", "22"),
    ("dquote", "22"),
    ("dq", "22"),
    ("path_sep", "2f"),
    ("psep", "2f"),
    ("separator", "2f"),
    ("eol", "a"),
    ("lsep", "a"),
    ("line_sep", "a"),
    ("esep", "3a"),
    ("env_sep", "3a"),
    ("tilde", "7e"),
    ("twiddle", "7e"),
    ("squiggly", "7e"),
    ("home", "7e"),
    ("hash", "23"),
    ("hashtag", "23"),
    ("pound_sign", "23"),
    ("sharp", "23"),
    ("root", "23"),
    ("nf_branch", "e0a0"),
    ("nf_segment", "e0b0"),
    ("nf_left_segment", "e0b0"),
    ("nf_left_segment_thin", "e0b1"),
    ("nf_right_segment", "e0b2"),
    ("nf_right_segment_thin", "e0b3"),
    ("nf_git", "f1d3"),
    ("nf_git_branch", "e709 e0a0"),
    ("nf_folder1", "f07c"),
    ("nf_folder2", "f115"),
    ("nf_house1", "f015"),
    ("nf_house2", "f7db"),
    ("identical_to", "2261"),
    ("hamburger", "2261"),
    ("not_identical_to", "2262"),
    ("branch_untracked", "2262"),
    ("strictly_equivalent_to", "2263"),
    ("branch_identical", "2263"),
    ("upwards_arrow", "2191"),
    ("branch_ahead", "2191"),
    ("downwards_arrow", "2193"),
    ("branch_behind", "2193"),
    ("up_down_arrow", "2195"),
    ("branch_ahead_behind", "2195"),
    ("black_right_pointing_triangle", "25b6"),
    ("prompt", "25b6"),
    ("vector_or_cross_product", "2a2f"),
    ("failed", "2a2f"),
    ("high_voltage_sign", "26a1"),
    ("elevated", "26a1"),
    ("sun", "2600 fe0f"),
    ("sunny", "2600 fe0f"),
    ("sunrise", "2600 fe0f"),
    ("moon", "1f31b"),
    ("cloudy", "2601 fe0f"),
    ("cloud", "2601 fe0f"),
    ("clouds", "2601 fe0f"),
    ("rainy", "1f326 fe0f"),
    ("rain", "1f326 fe0f"),
    ("foggy", "1f32b fe0f"),
    ("fog", "1f32b fe0f"),
    ("mist", "2591"),
    ("haze", "2591"),
    ("snowy", "2744 fe0f"),
    ("snow", "2744 fe0f"),
    ("thunderstorm", "1f329 fe0f"),
    ("thunder", "1f329 fe0f"),
    ("bel", "7"),
    ("backspace", "8"),
    ("file_separator", "1c"),
    ("file_sep", "1c"),
    ("fs", "1c"),
    ("group_separator", "1d"),
    ("group_sep", "1d"),
    ("gs", "1d"),
    ("record_separator", "1e"),
    ("record_sep", "1e"),
    ("rs", "1e"),
    ("unit_separator", "1f"),
    ("unit_sep", "1f"),
    ("us", "1f"),
];

pub(crate) fn known_named_char_hex(name: &str) -> Option<&'static str> {
    NAMED_CHAR_HEX
        .iter()
        .find_map(|(candidate, hex)| (*candidate == name).then_some(*hex))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_named_char_table_has_unique_names() {
        let mut seen = HashSet::new();
        for (name, _) in NAMED_CHAR_HEX {
            assert!(
                seen.insert(*name),
                "duplicate named character entry: {name}"
            );
        }
    }

    #[test]
    fn test_named_char_lookup_returns_prompt_glyph_hex() {
        assert_eq!(known_named_char_hex("prompt"), Some("25b6"));
    }
}
