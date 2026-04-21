wit_bindgen::generate!({
    path: [
        "../../../../../wit/disclosure",
        "../../../../../wit/form",
        "../../../../../wit/policy",
        "wit",
    ],
    world: "enclavid:test-policy/policy",
    generate_all,
});

use enclavid::disclosure::disclosure::{prompt_disclosure, DisplayField};
use enclavid::form::documents::prompt_passport;
use exports::enclavid::policy::policy::{Decision, EvalArgs, Guest};

struct TestPolicy;

impl Guest for TestPolicy {
    fn evaluate(_args: Vec<(String, EvalArgs)>) -> Decision {
        let _passport = prompt_passport();
        let consented = prompt_disclosure(&[DisplayField {
            label: "id_number".into(),
            value: "123456".into(),
        }]);
        if consented {
            Decision::Approved
        } else {
            Decision::Rejected
        }
    }
}

export!(TestPolicy);
