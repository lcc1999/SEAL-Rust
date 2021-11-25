#include "seal/include/rust.h"

namespace seal
{
void print_parameters(const std::unique_ptr<SEALContext>& ctx)
{
    auto &context_data = *ctx->key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}
	//setup
	std::unique_ptr<EncryptionParameters> new_encryption_parameters(uint8_t scheme) {
  		return std::make_unique<EncryptionParameters>(scheme);
	}
	void EncryptionParameters_set_poly_modulus_degree(const std::unique_ptr<EncryptionParameters>& ep, size_t degree) {
        	ep->set_poly_modulus_degree(degree);
    	}
    	void EncryptionParameters_set_coeff_modulus_Create(const std::unique_ptr<EncryptionParameters>& ep, size_t poly_modulus_degree, const rust::Vec<int> &bit_sizes) {
        	std::vector<int> sizes;
  		std::copy(bit_sizes.begin(), bit_sizes.end(), std::back_inserter(sizes));
        	ep->set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree,sizes));
    	}
    	void EncryptionParameters_set_coeff_modulus_BFVDefault(const std::unique_ptr<EncryptionParameters>& ep, size_t poly_modulus_degree) {
        	ep->set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    	}
    	void EncryptionParameters_set_plain_modulus(const std::unique_ptr<EncryptionParameters>& ep, size_t plain_modulus) {
        	ep->set_plain_modulus(plain_modulus);
    	}
    	void EncryptionParameters_set_plain_modulus_Batching(const std::unique_ptr<EncryptionParameters>& ep, size_t poly_modulus_degree, int bit_size) {
    		ep->set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, bit_size));
	}
    	
	std::unique_ptr<SEALContext> new_SEALContext(const std::unique_ptr<EncryptionParameters>& ep) {
		return std::make_unique<SEALContext>(*ep);
	}
	

	//keygen
	std::unique_ptr<KeyGenerator> new_KeyGenerator(const std::unique_ptr<SEALContext>& ctx) {
		return std::make_unique<KeyGenerator>(*ctx);
	}
	std::unique_ptr<SecretKey> KeyGenerator_secret_key(const std::unique_ptr<KeyGenerator>& keygen) {
		return std::make_unique<SecretKey>(keygen->secret_key());
	}
	std::unique_ptr<SerializablePublicKey> KeyGenerator_create_public_key(const std::unique_ptr<KeyGenerator>& keygen) {
		return std::make_unique<SerializablePublicKey>(keygen->create_public_key());
	}
	std::unique_ptr<SerializableRelinKeys> KeyGenerator_create_relin_keys(const std::unique_ptr<KeyGenerator>& keygen) {
		return std::make_unique<SerializableRelinKeys>(keygen->create_relin_keys());
	}
	std::unique_ptr<PublicKey> Serializable_to_PublicKey(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<SerializablePublicKey>& spk) {
		std::stringstream data_stream;
		spk->save(data_stream);
		std::unique_ptr<PublicKey> pk = std::make_unique<PublicKey>();
		pk->load(*ctx, data_stream);
		return pk;
	}
	std::unique_ptr<RelinKeys> Serializable_to_RelinKeys(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<SerializableRelinKeys>& srlk) {
		std::stringstream data_stream;
		srlk->save(data_stream);
		std::unique_ptr<RelinKeys> rlk = std::make_unique<RelinKeys>();
		rlk->load(*ctx, data_stream);
		return rlk;
	}
	
	
	//encode and decode
	//no simd
	rust::String data_to_string(uint64_t data) {
		return rust::String(std::to_string(data));
	}
	std::unique_ptr<Plaintext> new_Plaintext(const rust::String data) {
		return std::make_unique<Plaintext>(std::string(data));
	}
	rust::String Plaintext_to_string(const std::unique_ptr<Plaintext>& plaintext) {
		return rust::String(plaintext->to_string());
	}
	//use simd
	std::unique_ptr<BatchEncoder> new_BatchEncoder(const std::unique_ptr<SEALContext>& ctx) {
		return std::make_unique<BatchEncoder>(*ctx);
	}
	size_t BatchEncoder_slot_count(const std::unique_ptr<BatchEncoder>& be) {
		return be->slot_count();
	}
	std::unique_ptr<Plaintext> BatchEncoder_encode(const std::unique_ptr<BatchEncoder>& be, const rust::Vec<uint64_t> &vec) {
		std::unique_ptr<Plaintext> plaintext = std::make_unique<Plaintext>();
		std::vector<uint64_t> v;
  		std::copy(vec.begin(), vec.end(), std::back_inserter(v));
		be->encode(v, *plaintext);
		return plaintext;
	}
	rust::Vec<uint64_t> BatchEncoder_decode(const std::unique_ptr<BatchEncoder>& be, const std::unique_ptr<Plaintext>& plain) {
		rust::Vec<uint64_t> vec;
		std::vector<uint64_t> v;
		be->decode(*plain, v);
		std::copy(v.begin(), v.end(), std::back_inserter(vec));
		return vec;
	}
	std::unique_ptr<CKKSEncoder> new_CKKSEncoder(const std::unique_ptr<SEALContext>& ctx) {
		return std::make_unique<CKKSEncoder>(*ctx);
	}
	size_t CKKSEncoder_slot_count(const std::unique_ptr<CKKSEncoder>& ce) {
		return ce->slot_count();
	}
	std::unique_ptr<Plaintext> CKKSEncoder_encode_vec(const std::unique_ptr<CKKSEncoder>& ce, double scale, const rust::Vec<double> &vec) {
		std::unique_ptr<Plaintext> plaintext = std::make_unique<Plaintext>();
		std::vector<double> v;
  		std::copy(vec.begin(), vec.end(), std::back_inserter(v));
		ce->encode(v, scale, *plaintext);
		return plaintext;
	}
	std::unique_ptr<Plaintext> CKKSEncoder_encode(const std::unique_ptr<CKKSEncoder>& ce, double scale, double value){
		std::unique_ptr<Plaintext> plaintext = std::make_unique<Plaintext>();
		ce->encode(value, scale, *plaintext);
		return plaintext;
	}
	rust::Vec<double> CKKSEncoder_decode(const std::unique_ptr<CKKSEncoder>& ce, const std::unique_ptr<Plaintext>& plain) {
		rust::Vec<double> vec;
		std::vector<double> v;
		ce->decode(*plain, v);
		std::copy(v.begin(), v.end(), std::back_inserter(vec));
		return vec;
	}
	
	
	
	//encryptor and decryptor
	std::unique_ptr<Decryptor> new_Decryptor(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<SecretKey>& sk) {
		return std::make_unique<Decryptor>(*ctx,*sk);
	}
	std::unique_ptr<Ciphertext> Serializable_to_Ciphertext(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<SerializableCiphertext>& cipher) {
		std::stringstream data_stream;
		cipher->save(data_stream);
		std::unique_ptr<Ciphertext> ciphertext = std::make_unique<Ciphertext>();
		ciphertext->load(*ctx, data_stream);
		return ciphertext;
	}
	std::unique_ptr<Plaintext> decrypt(const std::unique_ptr<Decryptor>& decryptor, const std::unique_ptr<Ciphertext>& ciphertext) {
		std::unique_ptr<Plaintext> plaintext = std::make_unique<Plaintext>();
		decryptor->decrypt(*ciphertext, *plaintext);
		return plaintext;
	}
	std::unique_ptr<Encryptor> new_Encryptor_pk(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<PublicKey>& pk) {
		return std::make_unique<Encryptor>(*ctx,*pk);
	}
	std::unique_ptr<SerializableCiphertext> encrypt(const std::unique_ptr<Encryptor>& encryptor, const std::unique_ptr<Plaintext>& plaintext) {
		return std::make_unique<SerializableCiphertext>(encryptor->encrypt(*plaintext));
	}
	std::unique_ptr<Encryptor> new_Encryptor_sk(const std::unique_ptr<SEALContext>& ctx, const std::unique_ptr<SecretKey>& sk) {
		return std::make_unique<Encryptor>(*ctx,*sk);
	}
	std::unique_ptr<SerializableCiphertext> encrypt_symmetric(const std::unique_ptr<Encryptor>& encryptor, const std::unique_ptr<Plaintext>& plaintext) {
		return std::make_unique<SerializableCiphertext>(encryptor->encrypt_symmetric(*plaintext));
	}
	
	//evaluator
	std::unique_ptr<Evaluator> new_Evaluator(const std::unique_ptr<SEALContext>& ctx) {
		return std::make_unique<Evaluator>(*ctx);
	}
	std::unique_ptr<Ciphertext> negate(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->negate(*encrypted,*res);
		return res;
	}
	std::unique_ptr<Ciphertext> add(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->add(*encrypted1, *encrypted2, *res);
		return res;
	}
	/*std::unique_ptr<Ciphertext> add_many(const std::unique_ptr<Evaluator>& evaluator, const rust::Vec<Ciphertext>& encrypted) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		std::vector<Ciphertext> vec;
  		std::copy(encrypted.begin(), encrypted.end(), std::back_inserter(vec));
		evaluator->add_many(vec,*res);
		return res;
	}*/
	std::unique_ptr<Ciphertext> sub(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->sub(*encrypted1, *encrypted2, *res);
		return res;
	}
	std::unique_ptr<Ciphertext> multiply(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->multiply(*encrypted1, *encrypted2, *res);
		return res;
	}
	std::unique_ptr<Ciphertext> square(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->square(*encrypted,*res);
		return res;
	}
	std::unique_ptr<Ciphertext> relinearize(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<RelinKeys>& rlk) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->relinearize(*encrypted, *rlk, *res);
		return res;
	}
	std::unique_ptr<Ciphertext> rescale_to_next(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->rescale_to_next(*encrypted,*res);
		return res;
	}
	/*std::unique_ptr<Ciphertext> multiply_many(const std::unique_ptr<Evaluator>& evaluator, const rust::Vec<Ciphertext>& encrypted) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		std::vector<Ciphertext> vec;
  		std::copy(encrypted.begin(), encrypted.end(), std::back_inserter(vec));
		evaluator->multiply_many(vec,*res);
		return res;
	}*/
	std::unique_ptr<Ciphertext> exponentiate(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, uint64_t exponent, const std::unique_ptr<RelinKeys>& rlk) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->exponentiate(*encrypted, exponent, *rlk, *res);
		return res;
	}
	std::unique_ptr<Ciphertext> add_plain(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->add_plain(*encrypted, *plain, *res);
		return res;
	}
	std::unique_ptr<Ciphertext> sub_plain(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->sub_plain(*encrypted, *plain, *res);
		return res;
	}
	std::unique_ptr<Ciphertext> multiply_plain(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain) {
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->multiply_plain(*encrypted, *plain, *res);
		return res;
	}
	
	
	
	void negate_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted) {
		evaluator->negate_inplace(*encrypted);
	}
	void add_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2) {
		evaluator->add_inplace(*encrypted1, *encrypted2);
	}
	void sub_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2) {
		evaluator->sub_inplace(*encrypted1, *encrypted2);
	}
	void multiply_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted1, const std::unique_ptr<Ciphertext>& encrypted2) {
		evaluator->multiply_inplace(*encrypted1, *encrypted2);
	}
	void square_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted) {
		evaluator->square_inplace(*encrypted);
	}
	void relinearize_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<RelinKeys>& rlk) {
		evaluator->relinearize_inplace(*encrypted, *rlk);
	}
	void rescale_to_next_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted) {
		evaluator->rescale_to_next_inplace(*encrypted);
	}
	void exponentiate_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, uint64_t exponent, const std::unique_ptr<RelinKeys>& rlk) {
		evaluator->exponentiate_inplace(*encrypted, exponent, *rlk);
	}
	void add_plain_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain) {
		evaluator->add_plain_inplace(*encrypted, *plain);
	}
	void sub_plain_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain) {
		evaluator->sub_plain_inplace(*encrypted, *plain);
	}
	void multiply_plain_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<Plaintext>& plain) {
		evaluator->multiply_plain_inplace(*encrypted, *plain);
	}
	
	
	void setscale(const std::unique_ptr<Ciphertext>& encrypted, double scale) {
		encrypted->scale()=scale;
	}
	std::unique_ptr<parms_id_type> parms_id(const std::unique_ptr<Ciphertext>& encrypted){
		return std::make_unique<parms_id_type>((encrypted->parms_id()));
	}
	std::unique_ptr<Ciphertext> mod_switch_to(const std::unique_ptr<Evaluator>& evaluator, const std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<parms_id_type>& id){
		std::unique_ptr<Ciphertext> res = std::make_unique<Ciphertext>();
		evaluator->mod_switch_to(*encrypted, *id, *res);
		return res;
	}
	void mod_switch_to_inplace(const std::unique_ptr<Evaluator>& evaluator, std::unique_ptr<Ciphertext>& encrypted, const std::unique_ptr<parms_id_type>& id){
		evaluator->mod_switch_to_inplace(*encrypted, *id);
	}
}
