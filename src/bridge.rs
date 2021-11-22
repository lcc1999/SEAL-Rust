#[cxx::bridge(namespace = "seal")]

pub mod seal {

    unsafe extern "C++" {
	include!("seal/include/rust.h");
	type EncryptionParameters;
	type SEALContext;
	type KeyGenerator;
	type SecretKey;
	type PublicKey;
	type RelinKeys;
	type SerializablePublicKey;
	type SerializableRelinKeys;
	type Plaintext;
	type Ciphertext;
	type SerializableCiphertext;
	type BatchEncoder;
	type Encryptor;
	type Decryptor;
	type Evaluator;
	
	
	//setup
	fn new_encryption_parameters() -> UniquePtr<EncryptionParameters>;
	fn print_parameters(ctx:&UniquePtr<SEALContext>);
	fn EncryptionParameters_set_poly_modulus_degree(ep:&UniquePtr<EncryptionParameters>, poly_modulus_degree:usize);
	fn EncryptionParameters_set_coeff_modulus_Create(ep:&UniquePtr<EncryptionParameters>, poly_modulus_degree:usize, bit_sizes:&Vec<i32>);
	fn EncryptionParameters_set_coeff_modulus_BFVDefault(ep:&UniquePtr<EncryptionParameters>, poly_modulus_degree:usize);
	fn EncryptionParameters_set_plain_modulus(ep:&UniquePtr<EncryptionParameters>, plain_modulus:usize);
	fn EncryptionParameters_set_plain_modulus_Batching(ep:&UniquePtr<EncryptionParameters>, poly_modulus_degree:usize, bit_size:i32);
	//fn EncryptionParameters_save() -> ;
	//fn EncryptionParameters_load();
	fn new_SEALContext(ep:&UniquePtr<EncryptionParameters>) -> UniquePtr<SEALContext>;
	
	
	//keygen
	fn new_KeyGenerator(ctx:&UniquePtr<SEALContext>) -> UniquePtr<KeyGenerator>;
	fn KeyGenerator_secret_key(keygen:&UniquePtr<KeyGenerator>) -> UniquePtr<SecretKey>;
	fn KeyGenerator_create_public_key(keygen:&UniquePtr<KeyGenerator>) -> UniquePtr<SerializablePublicKey>;
	fn KeyGenerator_create_relin_keys(keygen:&UniquePtr<KeyGenerator>) -> UniquePtr<SerializableRelinKeys>;
	fn Serializable_to_PublicKey(ctx:&UniquePtr<SEALContext>, spk:&UniquePtr<SerializablePublicKey>) -> UniquePtr<PublicKey>;
	fn Serializable_to_RelinKeys(ctx:&UniquePtr<SEALContext>, srlk:&UniquePtr<SerializableRelinKeys>) -> UniquePtr<RelinKeys>;
	
	
	//encode and decode
	//no simd
	fn data_to_string(data:u64) -> String;
	fn new_Plaintext(data:String) -> UniquePtr<Plaintext>;
	fn Plaintext_to_string(plaintext:&UniquePtr<Plaintext>) -> String;
	//use simd
	fn new_BatchEncoder(ctx:&UniquePtr<SEALContext>) -> UniquePtr<BatchEncoder>;
	fn slot_count(be:&UniquePtr<BatchEncoder>) -> usize;
	fn encode(be:&UniquePtr<BatchEncoder>, vec:&Vec<u64>) -> UniquePtr<Plaintext>;
	fn decode(be:&UniquePtr<BatchEncoder>, plain:&UniquePtr<Plaintext>) -> Vec<u64>;
	
	
	//decryptor
	fn new_Decryptor(ctx:&UniquePtr<SEALContext>, sk:&UniquePtr<SecretKey>) -> UniquePtr<Decryptor>;
	fn Serializable_to_Ciphertext(ctx:&UniquePtr<SEALContext>, cipher:&UniquePtr<SerializableCiphertext>) -> UniquePtr<Ciphertext>;
	fn decrypt(decryptor:&UniquePtr<Decryptor>, ciphertext:&UniquePtr<Ciphertext>) -> UniquePtr<Plaintext>;
	//encrypt
	fn new_Encryptor_pk(ctx:&UniquePtr<SEALContext>, pk:&UniquePtr<PublicKey>) -> UniquePtr<Encryptor>;
	fn encrypt(encryptor:&UniquePtr<Encryptor>, plaintext:&UniquePtr<Plaintext>) -> UniquePtr<SerializableCiphertext>;
	//encrypt_symmetric
	fn new_Encryptor_sk(ctx:&UniquePtr<SEALContext>, sk:&UniquePtr<SecretKey>) -> UniquePtr<Encryptor>;
	fn encrypt_symmetric(encryptor:&UniquePtr<Encryptor>, plaintext:&UniquePtr<Plaintext>) -> UniquePtr<SerializableCiphertext>;
	
	
	//evaluator
	fn new_Evaluator(ctx:&UniquePtr<SEALContext>) -> UniquePtr<Evaluator>;
	fn negate(evaluator:&UniquePtr<Evaluator>, encrypted:&UniquePtr<Ciphertext>) -> UniquePtr<Ciphertext>;
	fn add(evaluator:&UniquePtr<Evaluator>, encrypted1:&UniquePtr<Ciphertext>, encrypted2:&UniquePtr<Ciphertext>) -> UniquePtr<Ciphertext>;
	//fn add_many(evaluator:&UniquePtr<Evaluator>, encrypted:&Vec<Ciphertext>) -> UniquePtr<Ciphertext>;
	fn sub(evaluator:&UniquePtr<Evaluator>, encrypted1:&UniquePtr<Ciphertext>, encrypted2:&UniquePtr<Ciphertext>) -> UniquePtr<Ciphertext>;
	fn multiply(evaluator:&UniquePtr<Evaluator>, encrypted1:&UniquePtr<Ciphertext>, encrypted2:&UniquePtr<Ciphertext>) -> UniquePtr<Ciphertext>;
	fn square(evaluator:&UniquePtr<Evaluator>, encrypted:&UniquePtr<Ciphertext>) -> UniquePtr<Ciphertext>;
	fn relinearize(evaluator:&UniquePtr<Evaluator>, encrypted:&UniquePtr<Ciphertext>, rlk:&UniquePtr<RelinKeys>) -> UniquePtr<Ciphertext>;
	fn rescale_to_next(evaluator:&UniquePtr<Evaluator>, encrypted:&UniquePtr<Ciphertext>) -> UniquePtr<Ciphertext>;
	//fn multiply_many(evaluator:&UniquePtr<Evaluator>, encrypted:&Vec<Ciphertext>) -> UniquePtr<Ciphertext>;
	fn exponentiate(evaluator:&UniquePtr<Evaluator>, encrypted:&UniquePtr<Ciphertext>, exponent:u64, rlk:&UniquePtr<RelinKeys>) -> UniquePtr<Ciphertext>;
	fn add_plain(evaluator:&UniquePtr<Evaluator>, encrypted:&UniquePtr<Ciphertext>, plain:&UniquePtr<Plaintext>) -> UniquePtr<Ciphertext>;
	fn sub_plain(evaluator:&UniquePtr<Evaluator>, encrypted:&UniquePtr<Ciphertext>, plain:&UniquePtr<Plaintext>) -> UniquePtr<Ciphertext>;
	fn multiply_plain(evaluator:&UniquePtr<Evaluator>, encrypted:&UniquePtr<Ciphertext>, plain:&UniquePtr<Plaintext>) -> UniquePtr<Ciphertext>;
    }
}
