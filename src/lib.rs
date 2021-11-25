#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod bridge;
use bridge::seal::*;

#[test]
fn test1() {
    let param = new_encryption_parameters();
    
    let poly_modulus_degree:usize = 4096;
    EncryptionParameters_set_poly_modulus_degree(&param, poly_modulus_degree);
    let bit_sizes = vec![20,20,20]; 
    //EncryptionParameters_set_coeff_modulus_Create(&param, poly_modulus_degree, &bit_sizes);
    EncryptionParameters_set_coeff_modulus_BFVDefault(&param, poly_modulus_degree);
    EncryptionParameters_set_plain_modulus(&param, 1024);
    //EncryptionParameters_set_plain_modulus_Batching(&param, poly_modulus_degree, 1024);
    let ctx = new_SEALContext(&param);
    print_parameters(&ctx);
    
    
    let keygen = new_KeyGenerator(&ctx);
    let sk = KeyGenerator_secret_key(&keygen);
    let spk = KeyGenerator_create_public_key(&keygen);
    let srlk = KeyGenerator_create_relin_keys(&keygen);
    let pk = Serializable_to_PublicKey(&ctx, &spk);
    let rlk = Serializable_to_RelinKeys(&ctx, &srlk);
    

    let plaintext = new_Plaintext(data_to_string(10));//hex
    let decryptor = new_Decryptor(&ctx, &sk);
    let encryptor = new_Encryptor_pk(&ctx, &pk);
    let cipher = encrypt(&encryptor, &plaintext);
    let ciphertext = Serializable_to_Ciphertext(&ctx, &cipher);
    
    let evaluator = new_Evaluator(&ctx);
    let res = negate(&evaluator, &ciphertext);
    
    
    let plain = decrypt(&decryptor, &res);
    let data = Plaintext_to_string(&plain);
    println!("data:{}",data);
}

#[test]
fn test2() {
    let param = new_encryption_parameters();
    
    let poly_modulus_degree:usize = 4096;
    EncryptionParameters_set_poly_modulus_degree(&param, poly_modulus_degree);
    let bit_sizes = vec![36 , 36 , 37]; 
    //EncryptionParameters_set_coeff_modulus_Create(&param, poly_modulus_degree, &bit_sizes);
    EncryptionParameters_set_coeff_modulus_BFVDefault(&param, poly_modulus_degree);
    //EncryptionParameters_set_plain_modulus(&param, 1024);
    EncryptionParameters_set_plain_modulus_Batching(&param, poly_modulus_degree, 20);
    let ctx = new_SEALContext(&param);
    print_parameters(&ctx);
    
    let keygen = new_KeyGenerator(&ctx);
    let sk = KeyGenerator_secret_key(&keygen);
    let spk = KeyGenerator_create_public_key(&keygen);
    let srlk = KeyGenerator_create_relin_keys(&keygen);
    let pk = Serializable_to_PublicKey(&ctx, &spk);
    let rlk = Serializable_to_RelinKeys(&ctx, &srlk);
    

    let decryptor = new_Decryptor(&ctx, &sk);
    let encryptor = new_Encryptor_pk(&ctx, &pk);
    let be = new_BatchEncoder(&ctx);
    let slot_count = slot_count(&be);
    let row_size = slot_count/2;
    let mut vec = Vec::new();
    for i in 1..slot_count{
    	vec.push(i as u64);
    }
    let plaintext = encode(&be, &vec);
    
    let cipher = encrypt(&encryptor, &plaintext);
    let ciphertext = Serializable_to_Ciphertext(&ctx, &cipher);
    
    let evaluator = new_Evaluator(&ctx);
    let res = negate(&evaluator, &ciphertext);
    
    let plain = decrypt(&decryptor, &res);
    let v = decode(&be, &plain);
    for i in 1..slot_count {
    	println!("{}",v[i]);
    }
}
