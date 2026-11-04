#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

pub trait CounterTrait {
    fn set_value(env: Env, admin: Address, value: u32);
    fn get_value(env: Env) -> u32;
}

#[contract]
pub struct Counter;

#[contractimpl]
impl CounterTrait for Counter {
    fn set_value(env: Env, admin: Address, value: u32) {
        admin.require_auth();
        env.storage().instance().set(&symbol_short!("VALUE"), &value);
    }

    fn get_value(env: Env) -> u32 {
        env.storage().instance().get(&symbol_short!("VALUE")).unwrap_or(0)
    }
}

#[cfg(test)]
mod test;
