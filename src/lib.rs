#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("./bindings.rs");

extern crate libc;

use std::ffi::CStr;
use std::ffi::CString;

#[test]
fn example_bfv_basics_i() {
    // This means to emulate https://github.com/Microsoft/SEAL/blob/master/examples/examples.cpp
    unsafe {
    println!("Example: BFV Basics I");
    let ep = bindings_new_encryption_parameters(1);
    let poly_modulus_degree:usize = 4096;
    bindings_EncryptionParameters_set_poly_modulus_degree(&ep, poly_modulus_degree);
    let bit_sizes = vec![20,20,20]; 
    //EncryptionParameters_set_coeff_modulus_Create(&ep, poly_modulus_degree, &bit_sizes);
    bindings_EncryptionParameters_set_coeff_modulus_BFVDefault(&ep, poly_modulus_degree);
    bindings_EncryptionParameters_set_plain_modulus(&ep, 1024);
    //EncryptionParameters_set_plain_modulus_Batching(&ep, poly_modulus_degree, 1024);
    let ctx = bindings_new_SEALContext(&param);
    bindings_print_parameters(&ctx);
    
    
    let keygen = bindings_new_KeyGenerator(&ctx);
    let sk = bindings_KeyGenerator_secret_key(&keygen);
    let spk = bindings_KeyGenerator_create_public_key(&keygen);
    let srlk = bindings_KeyGenerator_create_relin_keys(&keygen);
    let pk = bindings_Serializable_to_PublicKey(&ctx, &spk);
    let rlk = bindings_Serializable_to_RelinKeys(&ctx, &srlk);
    

    let plaintext = bindings_new_Plaintext(data_to_string(10));//hex
    let decryptor = bindings_new_Decryptor(&ctx, &sk);
    let encryptor = bindings_new_Encryptor_pk(&ctx, &pk);
    let cipher = bindings_encrypt(&encryptor, &plaintext);
    let ciphertext = bindings_Serializable_to_Ciphertext(&ctx, &cipher);
    
    let evaluator = bindings_new_Evaluator(&ctx);
    let res = bindings_negate(&evaluator, &ciphertext);
    
    
    let plain = bindings_decrypt(&decryptor, &res);
    let data = bindings_Plaintext_to_string(&plain);
    println!("data:{}",data);
    }
}


