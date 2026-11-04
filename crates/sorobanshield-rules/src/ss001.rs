use crate::common::{
    has_attr, is_cfg_test, is_public_entrypoint, receiver_chain_has_storage, WRITE_CALLS,
};
use proc_macro2::Span;
use sorobanshield_core::{Confidence, Finding, ProjectUnit, Rule, RuleMeta, RuleStatus, Severity};
use std::collections::{HashMap, HashSet};
use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprMethodCall, ImplItem, Item, ItemFn, ItemImpl, ItemMod};

pub const ID: &str = "SS-001";

pub struct AuthorizationPathReview;

const AUTH_CALLS: &[&str] = &["require_auth", "require_auth_for_args"];

/// OpenZeppelin stellar-contracts attribute macros that expand to a
/// `require_auth` call. `has_role` and `has_any_role` are deliberately absent:
/// they check role membership without requiring authorization. Matched by
/// name only, so a different macro with the same name is also accepted.
const AUTH_ATTRS: &[&str] = &["only_owner", "only_admin", "only_role", "only_any_role"];

#[derive(Default)]
struct BodyFacts {
    has_auth: bool,
    /// Names of everything called, by method or by path.
    callees: HashSet<String>,
    /// Calls of the form `f(..)` or `a::b::f(..)`, by last path segment, in source order.
    path_calls: Vec<(String, Span)>,
    writes: Vec<Span>,
}

impl<'ast> Visit<'ast> for BodyFacts {
    fn visit_expr_method_call(&mut self, m: &'ast ExprMethodCall) {
        let name = m.method.to_string();
        if AUTH_CALLS.contains(&name.as_str()) {
            self.has_auth = true;
        } else if WRITE_CALLS.contains(&name.as_str()) && receiver_chain_has_storage(&m.receiver) {
            self.writes.push(m.method.span());
        }
        self.callees.insert(name);
        syn::visit::visit_expr_method_call(self, m);
    }

    fn visit_expr_call(&mut self, c: &'ast ExprCall) {
        if let Expr::Path(p) = &*c.func {
            if let Some(seg) = p.path.segments.last() {
                let name = seg.ident.to_string();
                if AUTH_CALLS.contains(&name.as_str()) {
                    self.has_auth = true;
                }
                self.path_calls.push((name.clone(), seg.ident.span()));
                self.callees.insert(name);
            }
        }
        syn::visit::visit_expr_call(self, c);
    }
}

fn facts(block: &syn::Block) -> BodyFacts {
    let mut f = BodyFacts::default();
    f.visit_block(block);
    f
}

/// One function body found anywhere in the project's non-test code.
struct FnInfo<'a> {
    file: &'a str,
    name: String,
    /// True for a public function of a `#[contractimpl]` block.
    entrypoint: bool,
    line: usize,
    facts: BodyFacts,
}

fn collect<'a>(file: &'a str, items: &'a [Item], out: &mut Vec<FnInfo<'a>>) {
    let mut push =
        |attrs: &[syn::Attribute], sig: &syn::Signature, block: &syn::Block, entrypoint: bool| {
            let mut facts = facts(block);
            facts.has_auth |= AUTH_ATTRS.iter().any(|a| has_attr(attrs, a));
            out.push(FnInfo {
                file,
                name: sig.ident.to_string(),
                entrypoint,
                line: sig.ident.span().start().line,
                facts,
            });
        };
    let mut nested: Vec<&'a [Item]> = Vec::new();
    for item in items {
        match item {
            Item::Fn(ItemFn {
                attrs, sig, block, ..
            }) if !is_cfg_test(attrs) => push(attrs, sig, block, false),
            Item::Impl(ItemImpl {
                attrs,
                items,
                trait_,
                ..
            }) if !is_cfg_test(attrs) => {
                let contract = has_attr(attrs, "contractimpl");
                for it in items {
                    if let ImplItem::Fn(f) = it {
                        let entry = contract && is_public_entrypoint(f, trait_.is_some());
                        push(&f.attrs, &f.sig, &f.block, entry);
                    }
                }
            }
            Item::Mod(ItemMod {
                attrs,
                content: Some((_, inner)),
                ..
            }) if !is_cfg_test(attrs) => nested.push(inner),
            _ => {}
        }
    }
    for inner in nested {
        collect(file, inner, out);
    }
}

/// Which functions reach a storage write or an authorization call through
/// calls to functions whose name is unique in the project.
struct Reach {
    /// For each function, whether it (transitively) writes storage.
    writes: Vec<bool>,
    /// For each function, whether it (transitively) calls require_auth.
    auth: Vec<bool>,
    /// name -> index, only for names defined exactly once in the project.
    unique: HashMap<String, usize>,
}

impl Reach {
    fn new(fns: &[FnInfo<'_>]) -> Self {
        let mut count: HashMap<&str, usize> = HashMap::new();
        for f in fns {
            *count.entry(f.name.as_str()).or_default() += 1;
        }
        let unique: HashMap<String, usize> = fns
            .iter()
            .enumerate()
            .filter(|(_, f)| count[f.name.as_str()] == 1)
            .map(|(i, f)| (f.name.clone(), i))
            .collect();
        let mut writes: Vec<bool> = fns.iter().map(|f| !f.facts.writes.is_empty()).collect();
        let mut auth: Vec<bool> = fns.iter().map(|f| f.facts.has_auth).collect();
        loop {
            let mut changed = false;
            for (i, f) in fns.iter().enumerate() {
                if !writes[i]
                    && f.facts
                        .path_calls
                        .iter()
                        .any(|(n, _)| unique.get(n).is_some_and(|&j| j != i && writes[j]))
                {
                    writes[i] = true;
                    changed = true;
                }
                if !auth[i]
                    && f.facts
                        .callees
                        .iter()
                        .any(|n| unique.get(n).is_some_and(|&j| j != i && auth[j]))
                {
                    auth[i] = true;
                    changed = true;
                }
            }
            if !changed {
                return Reach {
                    writes,
                    auth,
                    unique,
                };
            }
        }
    }
}

impl Rule for AuthorizationPathReview {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: ID.into(),
            name: "Authorization path review".into(),
            status: RuleStatus::Implemented,
            severity: Some(Severity::Medium),
            confidence: Some(Confidence::Low),
            concern: "A public contract function writes to contract storage, directly or through helper functions it calls, but no require_auth call is visible in the function or in the helpers it calls. Authorization may be missing, or it may be enforced somewhere this rule cannot see.".into(),
            detection: "Parses each Rust file with syn. In impl blocks annotated #[contractimpl], for each public function it looks for storage writes (a .set(..) or .remove(..) call whose receiver chain contains .storage()) and for require_auth / require_auth_for_args calls. The scan is project-wide. A call to a function is followed by its last path segment, and only when exactly one function with that name exists in the project's non-test code, so a write or an auth call in a helper in another file is seen. Writes are followed through path calls such as storage::set_x(..) or Self::f(..), not through method calls on a receiver. A function is reported when it writes storage (directly or through such helpers), contains no auth call, and calls no same-file function, and no uniquely named function elsewhere, that reaches one. For an indirect write the finding points at the call. The attribute macros #[only_owner], #[only_admin], #[only_role] and #[only_any_role] (OpenZeppelin stellar-contracts) count as authorization; #[has_role] and #[has_any_role] do not, because they check membership without require_auth. Items under #[cfg(test)] are skipped, and so is the __constructor function, which runs only at deployment.".into(),
            severity_rationale: "Medium: missing authorization on a storage write can be serious, but this rule only establishes that no auth call is visible, not that authorization is absent. Confidence is low for the same reason, so the finding is a prompt for manual review, not a vulnerability claim.".into(),
            remediation: "Trace every caller of the function. If the write must be restricted, call require_auth() on the relevant Address before it, and add tests for authorized and unauthorized callers. If authorization is enforced elsewhere (for example the function is only reachable through an authorized entrypoint), document that and treat the finding as reviewed.".into(),
            false_positives: vec![
                "Public initialization functions that are intentionally callable once by anyone.".into(),
                "Authorization performed in another crate, in a caller, via a trait method, or in a helper reached by a call this rule does not follow (a method call, or a name defined more than once).".into(),
                "Writes to temporary storage that carry no security meaning.".into(),
            ],
            false_negatives: vec![
                "A require_auth call exists but is on the wrong Address, or is conditional and skipped on some paths.".into(),
                "Storage writes hidden behind macros, behind method calls (receiver.save(..)), behind helper names defined more than once in the project, in other crates, or through non-set/remove APIs (for example extend_ttl or bump).".into(),
                "A write reached through a same-named function that is not the one actually called: calls are matched by name, not resolved by type or path.".into(),
                "Functions not marked pub or not inside #[contractimpl], and contract code that is generated rather than written.".into(),
                "Any call named require_auth on an unrelated type is counted as authorization, and so is any attribute macro named only_owner, only_admin, only_role or only_any_role, whatever it actually expands to.".into(),
            ],
            references: vec![
                "https://developers.stellar.org/docs/build/smart-contracts/example-contracts/auth".into(),
                "https://docs.rs/soroban-sdk/latest/soroban_sdk/struct.Address.html#method.require_auth".into(),
            ],
            fixtures: vec![
                "tests/fixtures/positive/unprotected_write".into(),
                "tests/fixtures/negative/protected_write".into(),
                "tests/fixtures/negative/helper_auth".into(),
                "tests/fixtures/positive/cross_file_write".into(),
                "tests/fixtures/negative/cross_file_auth".into(),
                "tests/fixtures/edge/test_module_ignored".into(),
                "tests/fixtures/positive/trait_impl_write".into(),
                "tests/fixtures/negative/trait_impl_auth".into(),
                "tests/fixtures/edge/trait_impl_not_contractimpl".into(),
            ],
        }
    }

    fn check_project(&self, project: &ProjectUnit<'_>) -> Vec<Finding> {
        let mut fns: Vec<FnInfo<'_>> = Vec::new();
        for unit in project.files {
            if !project.test_only.contains(unit.path) {
                collect(unit.path, &unit.ast.items, &mut fns);
            }
        }
        let reach = Reach::new(&fns);
        let meta = self.meta();

        let mut out = Vec::new();
        for (i, f) in fns.iter().enumerate().filter(|(_, f)| f.entrypoint) {
            // `__constructor` runs once at deployment and cannot be invoked afterwards.
            if f.name == "__constructor" {
                continue;
            }
            // Where the write is: directly in the body, or at the first call
            // into a uniquely named function that reaches one.
            let indirect = f.facts.path_calls.iter().find(|(n, _)| {
                reach
                    .unique
                    .get(n)
                    .is_some_and(|&j| j != i && reach.writes[j])
            });
            if f.facts.writes.is_empty() && indirect.is_none() {
                continue;
            }
            if f.facts.has_auth {
                continue;
            }
            // Authorization in a same-file helper (matched by name) or in a
            // uniquely named function elsewhere in the project.
            let authorized = f.facts.callees.iter().any(|n| {
                *n != f.name
                    && (fns
                        .iter()
                        .any(|g| g.file == f.file && g.name == *n && g.facts.has_auth)
                        || reach
                            .unique
                            .get(n)
                            .is_some_and(|&j| j != i && reach.auth[j]))
            });
            if authorized {
                continue;
            }
            let (message, first, last, mut limitations) = if !f.facts.writes.is_empty() {
                let first = f.facts.writes[0].start().line;
                let last = f.facts.writes.last().map(|s| s.end().line).unwrap_or(first);
                (
                    format!(
                        "Public contract function `{}` writes to storage ({} write(s)) but no require_auth call is visible in it or in a function it calls. Review whether every caller is meant to be allowed to do this.",
                        f.name,
                        f.facts.writes.len()
                    ),
                    first,
                    last,
                    Vec::new(),
                )
            } else {
                let (callee, span) = indirect.expect("checked above");
                let j = reach.unique[callee];
                let line = span.start().line;
                (
                    format!(
                        "Public contract function `{}` reaches a storage write through `{}` (defined in {} line {}) but no require_auth call is visible in it or in a function it calls. Review whether every caller is meant to be allowed to do this.",
                        f.name, callee, fns[j].file, fns[j].line
                    ),
                    line,
                    line,
                    vec!["The write was found by following calls by function name, and only to names defined exactly once in the project; it may not be the function actually called.".to_string()],
                )
            };
            limitations.push("Authorization enforced in another crate, a caller, a trait method, or a function reached by a call this rule does not follow is not visible to it.".into());
            limitations
                .push("This is a review prompt, not proof that authorization is missing.".into());
            out.push(Finding {
                rule_id: ID.into(),
                title: meta.name.clone(),
                severity: Severity::Medium,
                confidence: Confidence::Low,
                message,
                file: f.file.to_string(),
                start_line: Some(first),
                end_line: Some(last),
                remediation: meta.remediation.clone(),
                references: meta.references.clone(),
                limitations,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sorobanshield_core::SourceUnit;

    fn run(src: &str) -> Vec<Finding> {
        run_files(&[("lib.rs", src)])
    }

    fn run_files(files: &[(&str, &str)]) -> Vec<Finding> {
        let parsed: Vec<(String, syn::File)> = files
            .iter()
            .map(|(p, s)| (p.to_string(), syn::parse_file(s).unwrap()))
            .collect();
        let units: Vec<SourceUnit<'_>> = parsed
            .iter()
            .map(|(p, a)| SourceUnit { path: p, ast: a })
            .collect();
        AuthorizationPathReview.check_project(&ProjectUnit {
            files: &units,
            test_only: &HashSet::new(),
        })
    }

    const ENTRY: &str = "use soroban_sdk::*; pub struct C; #[contractimpl] impl C {";

    const HEAD: &str = "use soroban_sdk::*; pub struct C; #[contractimpl] impl C {";

    #[test]
    fn flags_unprotected_storage_write() {
        let f = run(&format!(
            "{HEAD} pub fn put(env: Env, v: u32) {{ env.storage().instance().set(&KEY, &v); }} }}"
        ));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "SS-001");
        assert_eq!(f[0].start_line, Some(1));
    }

    #[test]
    fn flags_remove_on_persistent_storage() {
        let f = run(&format!(
            "{HEAD} pub fn rm(env: Env) {{ env.storage().persistent().remove(&KEY); }} }}"
        ));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn accepts_direct_require_auth() {
        let f = run(&format!("{HEAD} pub fn put(env: Env, who: Address) {{ who.require_auth(); env.storage().instance().set(&KEY, &1u32); }} }}"));
        assert!(f.is_empty());
    }

    #[test]
    fn accepts_require_auth_for_args() {
        let f = run(&format!("{HEAD} pub fn put(env: Env, who: Address) {{ who.require_auth_for_args(vec![&env]); env.storage().instance().set(&KEY, &1u32); }} }}"));
        assert!(f.is_empty());
    }

    #[test]
    fn accepts_same_file_auth_helper() {
        let f = run(&format!("fn guard(a: &Address) {{ a.require_auth(); }} {HEAD} pub fn put(env: Env, who: Address) {{ guard(&who); env.storage().instance().set(&KEY, &1u32); }} }}"));
        assert!(f.is_empty());
    }

    #[test]
    fn auth_helper_that_is_a_method_is_recognised() {
        let f = run(&format!("{HEAD} fn guard(who: &Address) {{ who.require_auth(); }} pub fn put(env: Env, who: Address) {{ Self::guard(&who); env.storage().instance().set(&KEY, &1u32); }} }}"));
        assert!(f.is_empty());
    }

    #[test]
    fn ignores_reads_and_unrelated_set_calls() {
        let f = run(&format!("{HEAD} pub fn get(env: Env) -> u32 {{ let mut m = Map::new(&env); m.set(1, 2); env.storage().instance().get(&KEY).unwrap() }} }}"));
        assert!(f.is_empty());
    }

    #[test]
    fn ignores_non_public_and_non_contract_functions() {
        let f = run(&format!("{HEAD} fn private(env: Env) {{ env.storage().instance().set(&KEY, &1u32); }} }} pub struct D; impl D {{ pub fn x(env: Env) {{ env.storage().instance().set(&KEY, &1u32); }} }}"));
        assert!(f.is_empty());
    }

    #[test]
    fn skips_constructor() {
        let f = run(&format!("{HEAD} pub fn __constructor(env: Env) {{ env.storage().instance().set(&KEY, &1u32); }} }}"));
        assert!(f.is_empty());
    }

    #[test]
    fn skips_cfg_test_modules() {
        let f = run("#[cfg(test)] mod tests { use soroban_sdk::*; pub struct C; #[contractimpl] impl C { pub fn put(env: Env) { env.storage().instance().set(&K, &1u32); } } }");
        assert!(f.is_empty());
    }

    #[test]
    fn one_finding_per_function_not_per_write() {
        let f = run(&format!("{HEAD} pub fn put(env: Env) {{ env.storage().instance().set(&A, &1u32); env.storage().instance().set(&B, &2u32); }} }}"));
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("2 write"));
    }

    #[test]
    fn follows_a_storage_write_into_another_file() {
        let f = run_files(&[
            (
                "lib.rs",
                &format!("{ENTRY} pub fn put(env: Env) {{ storage::set_value(&env, 1); }} }}"),
            ),
            (
                "storage.rs",
                "pub fn set_value(env: &Env, v: u32) { env.storage().instance().set(&KEY, &v); }",
            ),
        ]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].file, "lib.rs");
        assert!(
            f[0].message
                .contains("through `set_value` (defined in storage.rs"),
            "{}",
            f[0].message
        );
    }

    #[test]
    fn follows_writes_through_a_chain_of_helpers() {
        let f = run_files(&[
            (
                "lib.rs",
                &format!("{ENTRY} pub fn put(env: Env) {{ a::step(&env); }} }}"),
            ),
            ("a.rs", "pub fn step(env: &Env) { b::store(env); }"),
            (
                "b.rs",
                "pub fn store(env: &Env) { env.storage().instance().set(&K, &1u32); }",
            ),
        ]);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn auth_in_a_helper_in_another_file_counts() {
        let f = run_files(&[
            ("lib.rs", &format!("{ENTRY} pub fn put(env: Env, who: Address) {{ guard::check(&who); storage::set_value(&env, 1); }} }}")),
            ("guard.rs", "pub fn check(who: &Address) { who.require_auth(); }"),
            ("storage.rs", "pub fn set_value(env: &Env, v: u32) { env.storage().instance().set(&KEY, &v); }"),
        ]);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn ambiguous_helper_names_are_not_followed() {
        // `set_value` is defined twice, so the call may resolve to either.
        let f = run_files(&[
            (
                "lib.rs",
                &format!("{ENTRY} pub fn put(env: Env) {{ set_value(&env); }} }}"),
            ),
            (
                "a.rs",
                "pub fn set_value(env: &Env) { env.storage().instance().set(&K, &1u32); }",
            ),
            ("b.rs", "pub fn set_value(env: &Env) { let _ = env; }"),
        ]);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn method_calls_are_not_followed_for_writes() {
        let f = run_files(&[
            ("lib.rs", &format!("{ENTRY} pub fn put(env: Env, s: Store) {{ s.save(&env); }} }}")),
            ("store.rs", "impl Store { pub fn save(&self, env: &Env) { env.storage().instance().set(&K, &1u32); } }"),
        ]);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn helpers_in_test_only_files_are_ignored() {
        let parsed = syn::parse_file(
            "pub fn set_value(env: &Env) { env.storage().instance().set(&K, &1u32); }",
        )
        .unwrap();
        let lib = syn::parse_file(&format!(
            "{ENTRY} pub fn put(env: Env) {{ set_value(&env); }} }}"
        ))
        .unwrap();
        let units = [
            SourceUnit {
                path: "lib.rs",
                ast: &lib,
            },
            SourceUnit {
                path: "tests/h.rs",
                ast: &parsed,
            },
        ];
        let test_only: HashSet<String> = ["tests/h.rs".to_string()].into();
        let f = AuthorizationPathReview.check_project(&ProjectUnit {
            files: &units,
            test_only: &test_only,
        });
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn access_control_attribute_macros_count_as_authorization() {
        for attr in [
            "only_owner",
            "only_admin",
            "only_role(operator, \"manager\")",
            "only_any_role(operator, [\"a\"])",
        ] {
            let f = run(&format!("{ENTRY} #[{attr}] pub fn put(env: Env) {{ env.storage().instance().set(&K, &1u32); }} }}"));
            assert!(f.is_empty(), "{attr}: {f:?}");
        }
    }

    #[test]
    fn membership_only_attribute_macros_do_not_count() {
        for attr in [
            "has_role(operator, \"manager\")",
            "when_not_paused",
            "when_paused",
        ] {
            let f = run(&format!("{ENTRY} #[{attr}] pub fn put(env: Env) {{ env.storage().instance().set(&K, &1u32); }} }}"));
            assert_eq!(f.len(), 1, "{attr}");
        }
    }

    #[test]
    fn trait_impl_methods_are_entrypoints_without_pub() {
        let f = run("use soroban_sdk::*; pub struct C; #[contractimpl] impl Api for C { fn put(env: Env) { env.storage().instance().set(&K, &1u32); } }");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn non_contractimpl_trait_impls_are_ignored() {
        let f = run("pub struct C; impl Api for C { fn put(env: Env) { env.storage().instance().set(&K, &1u32); } }");
        assert!(f.is_empty());
    }

    #[test]
    fn recursion_terminates() {
        let f = run(&format!("{ENTRY} pub fn put(env: Env) {{ a(&env); }} }} fn a(env: &Env) {{ b(env); }} fn b(env: &Env) {{ a(env); }}"));
        assert!(f.is_empty());
    }
}
