#![cfg(test)]
use super::*;

#[test]
fn exercises_entrypoints() {
    let client = Client::new();
    client.set_value();
    client.get_value();
}
