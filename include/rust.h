#pragma once
#include "rust/cxx.h"
#include "seal/seal.h"
#include <memory>
#include <vector>
#include <iomanip>
#include <iostream>

namespace seal
{
	typedef Serializable<PublicKey> SerializablePublicKey;
	typedef Serializable<RelinKeys> SerializableRelinKeys;
	typedef Serializable<Ciphertext> SerializableCiphertext;
	void print_parameters(const std::unique_ptr<SEALContext>& ctx);
	//setup
	std::unique_ptr<EncryptionParameters> new_encryption_parameters(uint8_t scheme);
	void EncryptionParameters_set_poly_modulus_degree(const std::unique_ptr<EncryptionParameters>& ep, size_t degree);
	void EncryptionParameters_set_coeff_modulus_Create(const std::unique_ptr<EncryptionParameters>& ep, size_t poly_modulus_degree, const rust::Vec<int> &bit_sizes);
	void EncryptionParameters_set_coeff_modulus_BFVDefault(const std::unique_ptr<EncryptionParameters>& ep, size_t poly_modulus_degree);
	void EncryptionParameters_set_plain_modulus(const std::unique_ptr<EncryptionParameters>& ep, size_t plain_modulus);
	void EncryptionParameters_set_plain_modulus_Batching(const std::unique_ptr<EncryptionParameters>& ep, size_t poly_modulus_degree, int bit_size);
	std::unique_ptr<SEALContext> new_SEALContext(const std::unique_ptr<EncryptionParameters>& ep);
	
	//keygen
	std::unique_ptr<KeyGenerator> new_KeyGenerator(const std::unique_ptr<SEALContext>& ctx);
	std::unique_ptr<SecretKey> KeyGenerator_secret_key(const std::unique_ptr<KeyGenerator>& keygen);
	std::unique_ptr<SerializablePublicKey> KeyGenerator_create_public_key(const std::unique_ptr<KeyGenerator>& keygen);
	std::unique_ptr<SerializableRelinKeys> KeyGenerator_create_relin_keys(const std::unique_ptr<KeyGenerator>& keygen);
	std::unique_ptr<PublicKey> Serializable_to_PublicKey(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<SerializablePublicKey>& spk);
	std::unique_ptr<RelinKeys> Serializable_to_RelinKeys(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<SerializableRelinKeys>& srlk);
	
	//encode and decode
	//no simd
	rust::String data_to_string(uint64_t data);
	std::unique_ptr<Plaintext> new_Plaintext(const rust::String data);
	rust::String Plaintext_to_string(const std::unique_ptr<Plaintext>& plaintext);
	//use simd
	std::unique_ptr<BatchEncoder> new_BatchEncoder(const std::unique_ptr<SEALContext>& ctx);
	size_t BatchEncoder_slot_count(const std::unique_ptr<BatchEncoder>& be);
	std::unique_ptr<Plaintext> BatchEncoder_encode(const std::unique_ptr<BatchEncoder>& be, const rust::Vec<uint64_t> &vec);
	rust::Vec<uint64_t> BatchEncoder_decode(const std::unique_ptr<BatchEncoder>& be, const std::unique_ptr<Plaintext>& plain);
	std::unique_ptr<CKKSEncoder> new_CKKSEncoder(const std::unique_ptr<SEALContext>& ctx);
	size_t CKKSEncoder_slot_count(const std::unique_ptr<CKKSEncoder>& ce);
	std::unique_ptr<Plaintext> CKKSEncoder_encode_vec(const std::unique_ptr<CKKSEncoder>& ce, double scale, const rust::Vec<double> &vec);
	std::unique_ptr<Plaintext> CKKSEncoder_encode(const std::unique_ptr<CKKSEncoder>& ce, double scale, double value);
	rust::Vec<double> CKKSEncoder_decode(const std::unique_ptr<CKKSEncoder>& ce, const std::unique_ptr<Plaintext>& plain);
	
	
	//encryptor and decryptor
	std::unique_ptr<Decryptor> new_Decryptor(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<SecretKey>& sk);
	std::unique_ptr<Ciphertext> Serializable_to_Ciphertext(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<SerializableCiphertext>& cipher);
	std::unique_ptr<Plaintext> decrypt(const std::unique_ptr<Decryptor>& decryptor, const std::unique_ptr<Ciphertext>& ciphertext);
	std::unique_ptr<Encryptor> new_Encryptor_pk(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<PublicKey>& pk);
	std::unique_ptr<SerializableCiphertext> encrypt(const std::unique_ptr<Encryptor>& encryptor, const std::unique_ptr<Plaintext>& plaintext);
	std::unique_ptr<Encryptor> new_Encryptor_sk(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<SecretKey>& sk);
	std::unique_ptr<SerializableCiphertext> encrypt_symmetric(const std::unique_ptr<Encryptor>& encryptor, const std::unique_ptr<Plaintext>& plaintext);

	//evaluator
	std::unique_ptr<Evaluator> new_Evaluator(const std::unique_ptr<SEALContext>& ctx);
	std::unique_ptr<Ciphertext> negate(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted);
	std::unique_ptr<Ciphertext> add(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2);
	//std::unique_ptr<Ciphertext> add_many(const std::unique_ptr<Evaluator>& evaluator, const rust::Vec<Ciphertext>& encrypted);
	std::unique_ptr<Ciphertext> sub(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2);
	std::unique_ptr<Ciphertext> multiply(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2);
	std::unique_ptr<Ciphertext> square(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted);
	std::unique_ptr<Ciphertext> relinearize(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<RelinKeys>& rlk);
	std::unique_ptr<Ciphertext> rescale_to_next(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted);
	//std::unique_ptr<Ciphertext> multiply_many(const std::unique_ptr<Evaluator>& evaluator, const rust::Vec<Ciphertext>& encrypted);
	std::unique_ptr<Ciphertext> exponentiate(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, uint64_t exponent, const std::unique_ptr<RelinKeys>& rlk);
	std::unique_ptr<Ciphertext> add_plain(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain);
	std::unique_ptr<Ciphertext> sub_plain(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain);
	std::unique_ptr<Ciphertext> multiply_plain(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain);
	
	void negate_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted);
	void add_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2);
	void sub_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2);
	void multiply_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2);
	void square_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted);
	void relinearize_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<RelinKeys>& rlk);
	void rescale_to_next_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted);
	void exponentiate_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, uint64_t exponent, const std::unique_ptr<RelinKeys>& rlk);
	void add_plain_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain);
	void sub_plain_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain);
	void multiply_plain_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain);
	
	
	void setscale(const std::unique_ptr<Ciphertext>& encrypted, double scale);
	std::unique_ptr<parms_id_type> parms_id(const std::unique_ptr<Ciphertext>& encrypted);
	std::unique_ptr<Ciphertext> mod_switch_to(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<parms_id_type>& id);
	void mod_switch_to_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<parms_id_type>& id);
}
