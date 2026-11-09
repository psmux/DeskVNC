//! What a person types into the Boundary pad.
//!
//! Three shapes are accepted: the code as the computer shows it in groups
//! (`1234 5678 9012`), the twelve digits run together, or the whole
//! `boundary1:` invitation pasted from a message. The first two go to the
//! code service; the third needs no network at all.

/// What [`parse`] made of the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entered {
    /// Twelve digits, nothing else, ready for `boundary_codes::Client::resolve`.
    Code(String),
    /// A full invitation, already checked to decode.
    Invitation(String),
}

/// The prefix every invitation starts with.
pub const INVITATION_PREFIX: &str = "boundary1:";

/// Read what was typed. Whitespace of any kind and the `-` some people type
/// between groups are ignored in a code; an invitation is taken as is, once
/// trimmed, and has to decode.
pub fn parse(input: &str) -> Result<Entered, String> {
    let input = input.trim();
    if input.len() > 8192 {
        return Err("That is too long to be a support code or an invitation".into());
    }
    if input
        .get(..INVITATION_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(INVITATION_PREFIX))
    {
        boundary_session::Invitation::decode(input).map_err(|_| {
            "That invitation is not complete. Copy the whole text again".to_string()
        })?;
        return Ok(Entered::Invitation(input.to_string()));
    }
    let digits: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if digits.len() != 12 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Enter the 12 digit code shown on the other computer".into());
    }
    // The same check the code service client makes, so the two cannot drift.
    boundary_codes::normalize_code(&digits).map_err(|e| e.to_string())?;
    Ok(Entered::Code(digits))
}

/// The code in the four digit groups the pad shows, for messages.
pub fn grouped(code: &str) -> String {
    let mut out = String::with_capacity(code.len() + 2);
    for (i, c) in code.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_and_plain_codes_parse_the_same() {
        let want = Entered::Code("123456789012".into());
        assert_eq!(parse("1234 5678 9012").unwrap(), want);
        assert_eq!(parse("123456789012").unwrap(), want);
        assert_eq!(parse("  1234-5678-9012 \n").unwrap(), want);
        assert_eq!(parse("1234\u{a0}5678\t9012").unwrap(), want);
    }

    #[test]
    fn wrong_codes_are_refused() {
        for bad in [
            "",
            "1234 5678 901",
            "1234 5678 90123",
            "1234 5678 901a",
            "١٢٣٤٥٦٧٨٩٠١٢",
            "boundary2:abc",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn a_broken_invitation_is_refused_not_sent_to_the_service() {
        assert!(parse("boundary1:not-a-real-invitation").is_err());
        assert!(parse("BOUNDARY1:").is_err());
    }

    #[test]
    fn groups_for_display() {
        assert_eq!(grouped("123456789012"), "1234 5678 9012");
        assert_eq!(grouped(""), "");
    }
}
