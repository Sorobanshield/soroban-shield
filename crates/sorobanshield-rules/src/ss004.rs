use crate::common::contract_entrypoints;
use proc_macro2::Span;
use sorobanshield_core::{Confidence, Finding, Rule, RuleMeta, RuleStatus, Severity, SourceUnit};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::ExprMethodCall;

pub const ID: &str = "SS-004";

pub struct ErrorPathReview;

const PANIC_MACROS: &[&str] = &["panic", "todo", "unimplemented"];

struct Sites(Vec<(Span, String)>);

impl<'ast> Visit<'ast> for Sites {
    fn visit_expr_method_call(&mut self, m: &'ast ExprMethodCall) {
        let name = m.method.to_string();
        if (name == "unwrap" && m.args.is_empty()) || (name == "expect" && m.args.len() == 1) {
            self.0.push((m.method.span(), format!("`.{name}()`")));
        }
        syn::visit::visit_expr_method_call(self, m);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if let Some(seg) = m.path.segments.last() {
            let name = seg.ident.to_string();
            if PANIC_MACROS.contains(&name.as_str()) {
                self.0.push((m.path.span(), format!("`{name}!`")));
            }
        }
        syn::visit::visit_macro(self, m);
    }
}

impl Rule for ErrorPathReview {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: ID.into(),
            name: "Error-path review".into(),
            status: RuleStatus::Implemented,
            severity: Some(Severity::Info),
            confidence: Some(Confidence::Low),
            concern: "Public contract functions that fail through .unwrap(), .expect(..), panic!, todo! or unimplemented! abort with an opaque trap instead of a typed contract error. Callers and tests cannot distinguish failure causes, and some panics may be reachable by attacker-chosen input.".into(),
            detection: "Parses each file with syn. In public functions of #[contractimpl] impl blocks it counts calls to .unwrap() with no arguments, .expect(..) with one argument, and the panic!, todo! and unimplemented! macros. Arguments inside other macros are not parsed and are not inspected. unreachable!, assert! and panic_with_error! are not reported. #[cfg(test)] items are skipped.".into(),
            severity_rationale: "Informational: in Soroban a failed invocation reverts its state changes, so a panic does not leave partial state behind; the concern is diagnosability, deliberate error design and unintended reachable traps. Low confidence because an unwrap on an invariant that cannot fail is fine.".into(),
            remediation: "Return `Result<_, Error>` with a #[contracterror] enum, or use panic_with_error!(&env, Error::X), so each failure has a stable code. Keep unwrap only for invariants that genuinely cannot fail, and test the failure paths.".into(),
            false_positives: vec![
                "unwrap/expect on values that are guaranteed to be present by construction or earlier validation.".into(),
                "Contracts that deliberately trap on invalid state.".into(),
            ],
            false_negatives: vec![
                "Panics inside private helpers, other files or macro arguments.".into(),
                "Other trapping operations such as indexing, division by zero, or unwrap_or_else with a panicking closure.".into(),
                "Whether error handling is consistent across the contract is not assessed.".into(),
            ],
            references: vec![
                "https://developers.stellar.org/docs/build/smart-contracts/example-contracts/errors".into(),
                "https://doc.rust-lang.org/book/ch09-00-error-handling.html".into(),
            ],
            fixtures: vec![
                "tests/fixtures/positive/panicking_entrypoints".into(),
                "tests/fixtures/negative/typed_errors".into(),
                "tests/fixtures/positive/trait_impl_unwrap".into(),
            ],
        }
    }

    fn check(&self, unit: &SourceUnit<'_>) -> Vec<Finding> {
        let meta = self.meta();
        let mut out = Vec::new();
        for f in contract_entrypoints(&unit.ast.items) {
            let mut sites = Sites(Vec::new());
            sites.visit_block(&f.block);
            if sites.0.is_empty() {
                continue;
            }
            let first = sites
                .0
                .iter()
                .map(|(s, _)| s.start().line)
                .min()
                .unwrap_or(0);
            let last = sites
                .0
                .iter()
                .map(|(s, _)| s.end().line)
                .max()
                .unwrap_or(first);
            let mut kinds: Vec<&str> = sites.0.iter().map(|(_, k)| k.as_str()).collect();
            kinds.sort_unstable();
            kinds.dedup();
            out.push(Finding {
                rule_id: ID.into(),
                title: meta.name.clone(),
                severity: Severity::Info,
                confidence: Confidence::Low,
                message: format!(
                    "Public contract function `{}` can trap through {} ({} site(s)) instead of returning a typed contract error.",
                    f.sig.ident,
                    kinds.join(", "),
                    sites.0.len()
                ),
                file: unit.path.to_string(),
                start_line: Some(first),
                end_line: Some(last),
                remediation: meta.remediation.clone(),
                references: meta.references.clone(),
                limitations: vec![
                    "unwrap/expect on guaranteed-present values is fine; this rule cannot tell.".into(),
                    "A failed invocation reverts state, so this is about error design, not partial state.".into(),
                ],
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(body: &str) -> Vec<Finding> {
        let src = format!("use soroban_sdk::*; pub struct C; #[contractimpl] impl C {{ {body} }}");
        let ast = syn::parse_file(&src).unwrap();
        ErrorPathReview.check(&SourceUnit {
            path: "lib.rs",
            ast: &ast,
        })
    }

    #[test]
    fn flags_unwrap_expect_and_panic_macros() {
        assert_eq!(
            run("pub fn f(env: Env) -> u32 { env.storage().instance().get(&K).unwrap() }").len(),
            1
        );
        assert_eq!(run("pub fn f(env: Env) -> u32 { env.storage().instance().get(&K).expect(\"missing\") }").len(), 1);
        assert_eq!(run("pub fn f() { panic!(\"no\"); }").len(), 1);
        assert_eq!(run("pub fn f() { todo!(); }").len(), 1);
        assert_eq!(run("pub fn f() { unimplemented!(); }").len(), 1);
    }

    #[test]
    fn typed_errors_and_other_unwrap_variants_are_not_flagged() {
        assert!(run("pub fn f(env: Env) -> Result<u32, Error> { env.storage().instance().get(&K).ok_or(Error::Missing) }").is_empty());
        assert!(
            run("pub fn f(env: Env) -> u32 { env.storage().instance().get(&K).unwrap_or(0) }")
                .is_empty()
        );
        assert!(run("pub fn f(env: Env) { panic_with_error!(&env, Error::Bad); }").is_empty());
        assert!(run("pub fn f(x: u32) { assert!(x > 0); unreachable!(); }").is_empty());
    }

    #[test]
    fn one_finding_per_function_with_counts() {
        let f = run("pub fn f(env: Env) -> u32 { let a: u32 = env.storage().instance().get(&A).unwrap(); let b: u32 = env.storage().instance().get(&B).unwrap(); a + b }");
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("2 site(s)"));
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn skips_private_and_cfg_test_code() {
        assert!(run("fn f() { panic!(\"x\"); }").is_empty());
        let ast = syn::parse_file("#[cfg(test)] mod t { pub struct C; #[contractimpl] impl C { pub fn f() { panic!(); } } }").unwrap();
        assert!(ErrorPathReview
            .check(&SourceUnit {
                path: "x.rs",
                ast: &ast
            })
            .is_empty());
    }
}
