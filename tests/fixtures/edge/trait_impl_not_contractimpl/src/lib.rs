#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

/// A plain Rust trait. Its impl below has no #[contractimpl], so its methods are
/// not part of the contract interface and cannot be invoked by callers.
pub trait Store {
    fn save(env: &Env, value: u32);
}

#[contract]
pub struct Counter;

impl Store for Counter {
    fn save(env: &Env, value: u32) {
        env.storage().instance().set(&symbol_short!("VALUE"), &value);
    }
}

#[contractimpl]
impl Counter {
    pub fn get_value(env: Env) -> u32 {
        env.storage().instance().get(&symbol_short!("VALUE")).unwrap_or(0)
    }
}

#[cfg(test)]
mod test;
