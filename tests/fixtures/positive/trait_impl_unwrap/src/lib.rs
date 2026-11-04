#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

pub trait ConfigTrait {
    fn read_config(env: Env) -> u32;
}

#[contract]
pub struct Config;

#[contractimpl]
impl ConfigTrait for Config {
    fn read_config(env: Env) -> u32 {
        env.storage().instance().get(&symbol_short!("CFG")).unwrap()
    }
}
