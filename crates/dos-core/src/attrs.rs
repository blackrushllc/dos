/// DOS-style attributes. We keep it as a string set like "RHA".
/// For MVP we just store/return, and server can ignore enforcement until later.

pub fn normalize_attrs(s: &str) -> String {
    let mut chars: Vec<char> = s
        .chars()
        .filter(|c| matches!(c, 'R' | 'H' | 'A' | 'S'))
        .collect();
    chars.sort_unstable();
    chars.dedup();
    chars.into_iter().collect()
}
