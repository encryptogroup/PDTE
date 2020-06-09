/**
 \file 		dgk_party.cpp
 \author 	masoud.naderpour@helsinki.fi
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
		Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
		This program is free software: you can redistribute it and/or modify
            	it under the terms of the GNU Lesser General Public License as published
           	 by the Free Software Foundation, either version 3 of the License, or
            	(at your option) any later version.
            	ABY is distributed in the hope that it will be useful,
            	but WITHOUT ANY WARRANTY; without even the implied warranty of
            	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            	GNU Lesser General Public License for more details.
            	You should have received a copy of the GNU Lesser General Public License
            	along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		DGK crypto
 */



#include "dgk_party.h"

#define CHECKCOMM 0
#define DEBUG 0
#define NETDEBUG 0
#define WINDOWSIZE 50000 //maximum size of a network packet in Byte

/**
 * initializes a DGK_Party with the asymmetric security parameter and the sharelength and exchanges public keys.
 * @param mode - 0 = generate new key; 1 = read key
 */
DGK::DGK(uint32_t DGKbits, uint32_t sharelen, channel* chan, uint32_t readkey) {

	m_nShareLength = sharelen;
	m_nDGKbits = DGKbits;
	m_nBuflen = DGKbits / 8 + 1; //size of one ciphertext to send via network. DGK uses n bits == n/8 bytes

#if DEBUG
	std::cout << "Created party with " << DGKbits << " key bits and" << sharelen << " bit shares" << std::endl;
#endif

	gmp_randinit_default(m_randstate);
	srand(time(0));
	gmp_randseed_ui(m_randstate, rand());

	if (readkey) {
		readKey();
	} else {
		generateKey();
	}

	keyExchange(chan);
}

/**
 * initializes a DGK_Party with the asymmetric security parameter and the sharelength.
 * @param mode - 0 = generate new key; 1 = read key
 * Public keys must be exchanged manually when using this constructor!
 */
DGK::DGK(uint32_t DGKbits, uint32_t sharelen, uint32_t readkey) {

	m_nShareLength = sharelen;
	m_nDGKbits = DGKbits;
	m_nBuflen = DGKbits / 8; //size of one ciphertext to send via network. DGK uses n bits == n/8 bytes

#if DEBUG
	std::cout << "Created party with " << DGKbits << " key bits and" << sharelen << " bit shares" << std::endl;
#endif

	gmp_randinit_default(m_randstate);
	gmp_randseed_ui(m_randstate, rand());

	if (readkey) {
		if (!readKey()){
			std::cout << "No DGK key file found! Generating a new DGK key." << std::endl;
			generateKey();
			storeKey();
		}
	} else {
		generateKey();
	}
}

bool DGK::readKey() {
#if DEBUG
	std::cout << "KeyGen" << std::endl;
#endif
	dgk_readkey(m_nDGKbits, m_nShareLength, &m_localpub, &m_prv);
#if DEBUG
	std::cout << "key read." << std::endl;
#endif
	return true;
}

void DGK::storeKey(){

	dgk_storekey(m_nDGKbits, m_nShareLength, m_localpub, m_prv);
}

void DGK::generateKey() {
#if DEBUG
	std::cout << "KeyGen" << std::endl;
#endif
	dgk_keygen(m_nDGKbits, m_nShareLength, &m_localpub, &m_prv);

#if DEBUG
	std::cout << "key generated." << std::endl;
#endif
}

/**
 * deletes party and frees keys and randstate
 */
DGK::~DGK() {
#if DEBUG
	std::cout << "Deleting DGK..." << std::endl;
#endif
	gmp_randclear(m_randstate);
	dgk_freeprvkey(m_prv);
	dgk_freepubkey(m_localpub);
	dgk_freepubkey(m_remotepub);

}

/**
 * encrypts PTs in the given Vec
 */
bool DGK::encrypt(vector<uint64_t> &plaintexts, BYTE* &ciphertexts){

	mpz_t tmp, tmp2, res;
	mpz_inits(tmp, tmp2, res, NULL);

	for(int i = 0;i < plaintexts.size();i++){

		//mpz_set_ui(tmp, plaintexts[i]);
		mpz_set_ui(tmp, 123456); //Testing with a fixed val for debugging

		dgk_encrypt_crt(res, m_localpub, m_prv, tmp);
		//dgk_encrypt_plain(res, m_localpub, tmp);
		//mpz_mod(res,res, m_localpub->n); //res % modulus n (TODO: remove this)

		mpz_set_ui(res, plaintexts[i]);
		mpz_export(ciphertexts + i * m_nBuflen, NULL, -1, 1, 1, 0, res);

		dgk_decrypt(tmp2, m_localpub, m_prv, res);
		gmp_printf ("feature%d (%Zd) decryption is (%Zd)\n", i, tmp, tmp2); //TODO: solve the problem with decryption :(

		if (mpz_cmp(tmp, tmp2)) {
			printf("ERROR!\n");
			break; //exit(0);
		}
	}

	return 1;
}

/**
 * encrypts & sends a Vec of plaintexts
 */
void DGK::encSndRcvVec(e_role role, vector<uint64_t> &plaintexts, mpz_t* &ciphertexts, channel* &chan){


	struct timespec start, end;
	uint32_t shareBytes = m_nShareLength / 8;
	uint32_t offset = 0;

	clock_gettime(CLOCK_MONOTONIC, &start);
	
	BYTE *m_encSndBuf, *m_encRcvBuf;
	m_encSndBuf = (BYTE*) calloc(plaintexts.size() * m_nBuflen, 1);
	m_encRcvBuf = (BYTE*) calloc(plaintexts.size() * m_nBuflen, 1);

	encrypt(plaintexts, m_encSndBuf);
	
	clock_gettime(CLOCK_MONOTONIC, &end);

	// send & receive encrypted values
	int window = WINDOWSIZE;
	int tosend = m_nBuflen * plaintexts.size();
	offset = 0;

	while (tosend > 0) {

		window = min(window, tosend);

		chan->send(m_encSndBuf + offset, window);
		chan->blocking_receive(m_encRcvBuf + offset, window);

		tosend -= window;
		offset += window;
	}

#if CHECKCOMM
	for(int i = 0;i < m_nBuflen * plaintexts.size();i++) {
		if(m_encRcvBuf[i] != m_encSndBuf[i]){
			std::cout << "Error: buff is not received correctly!" << std::endl;
			break;
		} else if(i+1 == m_nBuflen * plaintexts.size()) {
			std::cout << "checking successful." << std::endl;
		}
	}

#endif

	//reconstructs the CTs from the received raw data buffer

	ciphertexts = (mpz_t*) calloc(plaintexts.size(), sizeof(mpz_t));

	for(int i = 0; i < plaintexts.size();i++){

		mpz_init(ciphertexts[i]);
		mpz_import(ciphertexts[i], m_nBuflen, -1, 1, 1, 0, m_encRcvBuf + i * m_nBuflen);
		//gmp_printf ("feature %d is %Zx\n", i, ciphertexts[i]);
	}

	//TODO: free unnecessary bufs
}

void DGK::mskSndRcvVec(e_role role, mpz_t* &CTs, mpz_t* &rndMsks, vector<uint64_t> &mapping, mpz_t* &inputsVec, channel* &chan){

	mpz_t tmp, rnd, res;
	mpz_inits(tmp, rnd, res, NULL);

	uint32_t statisParam = 40;

	BYTE *m_encSndBuf, *m_encRcvBuf;
	int bufSize = mapping.size() * m_nBuflen;
	m_encSndBuf = (BYTE*) calloc(bufSize, 1);
	m_encRcvBuf = (BYTE*) calloc(bufSize, 1);
	
	for(int i=0;i < mapping.size();i++){

		//mpz_set_ui(rnd, rndMsks[i]); // mask > 100 bits
		mpz_set (rnd, rndMsks[i]);
		//mpz_urandomb(rnd, m_randstate, m_nShareLength - 1);

		dgk_encrypt_plain(res, m_remotepub, rnd); // server encrypts the mask
		
		mpz_mul(res, res, CTs[mapping[i]]); // masks the feature homomorphically
		mpz_mod(res,res, m_remotepub->n); //res % modulus n

		mpz_export(m_encSndBuf + i * m_nBuflen, NULL, -1, 1, 1, 0, res); // embeds the masked inputs in Snd buffer

	}

	// send & receive encrypted values
	int window = WINDOWSIZE;
	int tosend = m_nBuflen * mapping.size();
	int offset = 0;

	while (tosend > 0) {

		window = min(window, tosend);

		chan->send(m_encSndBuf + offset, window);
		chan->blocking_receive(m_encRcvBuf + offset, window);

		tosend -= window;
		offset += window;
	}

#if CHECKCOMM

	for(int i = 0;i < bufSize;i++) {
		if(m_encRcvBuf[i] != m_encSndBuf[i]){
			std::cout << "Error: buff is not received correctly!" << std::endl;
			break;
		} else if(i+1 == bufSize) {
			std::cout << "checking successful." << std::endl;
		}
	}

#endif

	//reconstructs the CTs from the received raw data buffer

	mpz_t* m_pCTVec = (mpz_t*) calloc(mapping.size(), sizeof(mpz_t)); //TODO: get rid of this
	inputsVec = (mpz_t*) calloc(mapping.size(), sizeof(mpz_t)); //inputs to the substraction circuit in plaintext

	for(int i = 0; i < mapping.size();i++){

		mpz_inits(m_pCTVec[i], inputsVec[i], NULL);
		//mpz_import(m_pCTVec[i], m_nBuflen, -1, 1, 1, 0, m_encRcvBuf + i * m_nBuflen);
		//dgk_decrypt(inputsVec[i],m_localpub, m_prv, m_pCTVec[i]); // decryps the inputs here before returning the vec
	}

	//TODO: free unnecessary bufs;
}

/**
 * exchanges private keys with other party via sock, pre-calculates fixed-base representation of remote pub-key
 */
void DGK::keyExchange(channel* &chan) {

//send public key
	sendmpz_t(m_localpub->n, chan);
	sendmpz_t(m_localpub->g, chan);
	sendmpz_t(m_localpub->h, chan);

//receive and complete public key
	mpz_t n, g, h;
	mpz_inits(n, g, h, NULL);
	receivempz_t(n, chan); //n
	receivempz_t(g, chan); //g
	receivempz_t(h, chan); //h

	dgk_complete_pubkey(m_nDGKbits, m_nShareLength, &m_remotepub, n, g, h);

	// pre calculate table for fixed-base exponentiation for client
	fbpowmod_init_g(m_remotepub->g, m_remotepub->n, 2 * m_nShareLength + 2);
	fbpowmod_init_h(m_remotepub->h, m_remotepub->n, 400); // 2.5 * t = 2.5 * 160 = 400 bit

	//free a and b
	mpz_clears(n, g, h, NULL);

#if DEBUG
	std::cout << "KX done. This pubkey: " << m_localpub->n << " remotekey: " << m_remotepub->n << std::endl;
#endif
}

/**
 * send one mpz_t to sock
 */
void DGK::sendmpz_t(mpz_t t, channel* chan, BYTE * buf) {

//clear upper bytes of the buffer, so tailing bytes are zero
	for (int i = mpz_sizeinbase(t, 256); i < m_nBuflen; i++) {
		*(buf + i) = 0;
	}

#if NETDEBUG
	std::cout << mpz_sizeinbase(t, 256) << " vs. " << m_nBuflen << std::endl;
#endif

	mpz_export(buf, NULL, -1, 1, 1, 0, t);

//send bytes of t
	chan->send(buf, (uint64_t) m_nBuflen);

#if NETDEBUG
	std::cout << std::endl << "SEND" << std::endl;
	for (int i = 0; i < m_nBuflen; i++) {
		printf("%02x.", *(buf + i));
	}

	std::cout << std::endl << "sent: " << t << " with len: " << m_nBuflen << " should have been " << mpz_sizeinbase(t, 256) << std::endl;
#endif
}

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void DGK::receivempz_t(mpz_t t, channel* chan, BYTE * buf) {
	chan->blocking_receive(buf, (uint64_t) m_nBuflen);
	mpz_import(t, m_nBuflen, -1, 1, 1, 0, buf);

#if NETDEBUG
	std::cout << std::endl << "RECEIVE" << std::endl;
	for (int i = 0; i < m_nBuflen; i++) {
		printf("%02x.", *(buf + i));
	}

	std::cout << "received: " << t << " with len: " << m_nBuflen << std::endl;
#endif
}

/**
 * send one mpz_t to sock, allocates buffer
 */
void DGK::sendmpz_t(mpz_t t, channel* chan) {
	unsigned int bytelen = mpz_sizeinbase(t, 256);
	BYTE* arr = (BYTE*) malloc(bytelen);
	mpz_export(arr, NULL, 1, 1, 1, 0, t);

//send byte length
	chan->send((BYTE*) &bytelen, sizeof(bytelen));

//send bytes of t
	chan->send(arr, (uint64_t) bytelen);

	free(arr);
#if NETDEBUG
	std::cout << "sent: " << t << " with len: " << bytelen << std::endl;
#endif
}

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void DGK::receivempz_t(mpz_t t, channel* chan) {
	unsigned int bytelen;

//reiceive byte length
	chan->blocking_receive((BYTE*) &bytelen, sizeof(bytelen));
	BYTE* arr = (BYTE*) malloc(bytelen);

//receive bytes of t
	chan->blocking_receive(arr, (uint64_t) bytelen);
	mpz_import(t, bytelen, 1, 1, 1, 0, arr);

	free(arr);
#if NETDEBUG
	std::cout << "received: " << t << " with len: " << bytelen << std::endl;
#endif
}

void DGK::printBuf(BYTE* b, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) {
		printf("%02x.", *(b + i));
	}
	std::cout << std::endl;
}

