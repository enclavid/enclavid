//! The keys a component declares for its texts — the cases of the `key` enum
//! of its slot's `i18n` interface — and the check of a catalog against them.
//!
//! The same check runs where the catalog is embedded, against the keys the
//! component's WIT declares, and in the TEE, against the keys the slot is
//! imported with.

use crate::{Catalog, DEFAULT_LANGUAGE};

/// Something wrong with a catalog against its keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The language whose text it is about, if it is about one.
    pub language: Option<String>,
    /// The key it is about.
    pub key: String,
    pub message: String,
    /// Worth saying, but not a reason to refuse the catalog.
    pub warning: bool,
}

/// Whether `catalog` is what `keys` declare: every text a key's, and every key
/// a text in some language — in English too, or a warning, since a language
/// without its own falls back to English.
pub fn check(keys: &[String], catalog: &Catalog) -> Vec<Problem> {
    let mut problems = Vec::new();
    for (language, texts) in catalog {
        for key in texts.keys().filter(|key| !keys.contains(key)) {
            problems.push(Problem {
                language: Some(language.clone()),
                key: key.clone(),
                message: "is not one of the keys".into(),
                warning: false,
            });
        }
    }
    let in_language = |key: &str, language: &str| {
        catalog
            .get(language)
            .is_some_and(|texts| texts.contains_key(key))
    };
    for key in keys {
        if !catalog.keys().any(|language| in_language(key, language)) {
            problems.push(Problem {
                language: None,
                key: key.clone(),
                message: "has no text in any language".into(),
                warning: false,
            });
        } else if !in_language(key, DEFAULT_LANGUAGE) {
            problems.push(Problem {
                language: None,
                key: key.clone(),
                message: format!(
                    "has no `{DEFAULT_LANGUAGE}` text, which is where a language without its own falls back"
                ),
                warning: true,
            });
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    fn catalog(entries: &[(&str, &str)]) -> Catalog {
        let mut catalog = Catalog::new();
        for (language, key) in entries {
            catalog
                .entry(language.to_string())
                .or_default()
                .insert(key.to_string(), "text".into());
        }
        catalog
    }

    fn errors(problems: &[Problem]) -> Vec<&str> {
        problems
            .iter()
            .filter(|p| !p.warning)
            .map(|p| p.message.as_str())
            .collect()
    }

    #[test]
    fn a_catalog_that_is_its_keys_passes() {
        let problems = check(
            &keys(&["title", "hint"]),
            &catalog(&[("en", "title"), ("en", "hint"), ("ru", "title")]),
        );
        assert_eq!(problems, vec![]);
    }

    #[test]
    fn a_text_no_key_declares_or_a_key_with_no_text_is_refused() {
        let problems = check(&keys(&["title"]), &catalog(&[("en", "subtitle")]));
        assert_eq!(
            errors(&problems),
            ["is not one of the keys", "has no text in any language"]
        );
        assert_eq!(problems[0].language.as_deref(), Some("en"));
    }

    #[test]
    fn a_key_without_an_english_text_is_only_a_warning() {
        let problems = check(&keys(&["title"]), &catalog(&[("ru", "title")]));
        assert!(problems.iter().all(|p| p.warning), "{problems:?}");
        assert_eq!(problems.len(), 1);
    }
}
