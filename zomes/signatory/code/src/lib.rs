#[macro_use]
extern crate hdk;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate holochain_json_derive;

use hdk::{
    error::ZomeApiResult,
};
use hdk::holochain_core_types::{
    signature::Signature,
};

use hdk::holochain_json_api::{
    error::JsonError,
    json::JsonString,
};

use hdk::
    holochain_wasm_utils::api_serialization::{
        keystore::KeyType,
};

pub fn handle_sign_message(sign_by_id:String,message:String) -> ZomeApiResult<Signature> {
    hdk::keystore_sign(sign_by_id.to_string(), message.to_string()).map(Signature::from)
}

pub fn handle_create_key(id:String) -> ZomeApiResult<String> {
// Create Revocation key
    let rev_key = hdk::keystore_derive_key("rev_seed".to_string(), id.to_string(), KeyType::Signing)?;
    hdk::debug(format!("Revocation Key 1 : {:}",rev_key).to_string())?;
    Ok(rev_key)
}

define_zome! {
    entries: []

    genesis: || { Ok(()) }

    functions: [
        sign: {
            inputs: | sign_by_id:String, message:String |,
            outputs: |result: ZomeApiResult<Signature>|,
            handler: handle_sign_message
        }
        derive_key: {
            inputs: | id:String |,
            outputs: |result: ZomeApiResult<String>|,
            handler: handle_create_key
        }
    ]

    traits: {
        hc_public [sign]
    }
}
