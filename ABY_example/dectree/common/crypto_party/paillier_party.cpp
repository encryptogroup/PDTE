/**
 \file 		paillier_party.h
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
 \brief		Paillier crypto
 */

#include "paillier_party.h"

#define CHECKCOMM 0
#define DEBUG 0
#define NETDEBUG 0
#define WINDOWSIZE 50000 //maximum size of a network packet in Byte

PaillierParty::PaillierParty(uint32_t PaillierBits, uint32_t readkey) {

    m_nShareLength = 104;
    m_nPaillierBits = PaillierBits;
	m_nBuflen = 2 * (PaillierBits / 8 ); //size of one ciphertext to send via network. Paillier uses 2n bits == 2n/8 bytes

#if DEBUG
	std::cout << "Created party with " << PaillierBits << " key bits " << std::endl;
#endif

	gmp_randinit_default(m_randstate);
	gmp_randseed_ui(m_randstate, rand());

	if (readkey) {
		if (!readKey()){
			std::cout << "No key file. Generating a new Paillier key." << std::endl;
			generateKey();
			storeKey();
		}
	} else {
		generateKey();
	}
}

bool PaillierParty::readKey() {

	char smod[5];
	char slbit[4];
	char name[40] = "paillier_key_";
	const char* div = "_";
	const char* ext = ".bin";

	sprintf(smod, "%d", m_nPaillierBits);

	strcat(name, smod);
	// strcat(name, div);
	strcat(name, ext);

	//printf("reading Paillier key from %s\n", name);

	/* allocate the new key structures */
	m_localpub = (paillier_pubkey_t*) malloc(sizeof(paillier_pubkey_t));
	m_prv = (paillier_prvkey_t*) malloc(sizeof(paillier_prvkey_t));

	FILE *fp;
	fp = fopen(name, "r");

	if(!fp) {
		//printf("Cannot find Paillier key's file!\n");
		return 0;
	}

	/* initialize our integers */
	mpz_init(m_localpub->n);
	mpz_init(m_localpub->n_squared);
	mpz_init(m_localpub->n_plusone);
	mpz_init(m_prv->lambda);
	mpz_init(m_prv->x);

	mpz_inp_raw(m_prv->lambda, fp);
	mpz_inp_raw(m_prv->x, fp);
	mpz_inp_raw(m_localpub->n, fp);
	mpz_inp_raw(m_localpub->n_squared, fp);
	mpz_inp_raw(m_localpub->n_plusone, fp);

	fclose(fp);

	m_localpub->bits = m_nPaillierBits;

    return 1;
}

void PaillierParty::storeKey(){

	FILE *fp;

	char smod[5];
	char slbit[4];
	char name[40] = "paillier_key_";
	const char* div = "_";
	const char* ext = ".bin";
	
	sprintf(smod, "%d", m_nPaillierBits);

	strcat(name, smod);
	// strcat(name, div);
	strcat(name, ext);

	//printf("writing Paillier key to %s\n", name);

	fp = fopen(name, "w");

	mpz_out_raw(fp, m_prv->lambda);
	mpz_out_raw(fp, m_prv->x);
	mpz_out_raw(fp, m_localpub->n);
	mpz_out_raw(fp, m_localpub->n_squared);
	mpz_out_raw(fp, m_localpub->n_plusone);

	fclose(fp);
}

void PaillierParty::generateKey() {

    paillier_keygen( m_nPaillierBits, &m_localpub, &m_prv, paillier_get_rand_devrandom );

}

/**
 * deletes party and frees keys and randstate
 */
PaillierParty::~PaillierParty() {

	gmp_randclear(m_randstate);
	paillier_freeprvkey(m_prv);
	paillier_freepubkey(m_localpub);
	paillier_freepubkey(m_remotepub);

}

/**
 * exchanges private keys with other party via sock, pre-calculates fixed-base representation of remote pub-key
 */
void PaillierParty::keyExchange(channel* &chan) {

//send public key
	sendmpz_t(m_localpub->n, chan);

//receive and complete public key
	m_remotepub = (paillier_pubkey_t*) malloc(sizeof(paillier_pubkey_t));
	mpz_inits(m_remotepub->n, m_remotepub->n_squared, m_remotepub->n_plusone, NULL);
	
    receivempz_t(m_remotepub->n, chan); //n
    complete_pubkey(m_remotepub);
    m_remotepub->bits = m_localpub->bits;

#if NETDEBUG
	std::cout << "KX done. This pubkey: " << m_localpub->n << " remotekey: " << m_remotepub->n << std::endl;
#endif
}


/**
 * encrypt values in the plaintext vector
 */
bool PaillierParty::encrypt(vector<uint64_t> &plaintexts, BYTE* &ciphertexts){

	paillier_plaintext_t tmp, tmp2;
	paillier_ciphertext_t res;
	mpz_inits(tmp.m, tmp2.m, res.c, NULL);

	for(int i = 0;i < plaintexts.size();i++){

		mpz_set_ui(tmp.m, plaintexts[i]);

		paillier_enc(&res, m_localpub, &tmp, paillier_get_rand_devrandom);

		mpz_export(ciphertexts + i * m_nBuflen, NULL, 1, 1, 1, 0, res.c);

		// paillier_dec(&tmp2, m_localpub, m_prv, &res);

		//gmp_printf ("feature%d (%Zd) decryption is (%ZX)\n", i, tmp.m, tmp2.m);
	}

	paillier_freeplaintext( &tmp );
	paillier_freeplaintext( &tmp2 );
	paillier_freeciphertext( &res );
	return 0;
}

/**
 * encrypts & sends a Vec of plaintexts
 */
void PaillierParty::encSndRcvVec(e_role role, vector<uint64_t> &plaintexts, mpz_t* &ciphertexts, channel* &chan){


	struct timespec start, end;
	//uint32_t shareBytes =  8;
	uint32_t offset = 0;

	
	BYTE *m_encSndBuf, *m_encRcvBuf;
	m_encSndBuf = (BYTE*) calloc(plaintexts.size() * m_nBuflen, 1);
	m_encRcvBuf = (BYTE*) calloc(plaintexts.size() * m_nBuflen, 1);

	// send & receive encrypted values
	int window = WINDOWSIZE;
	int tosend = m_nBuflen * plaintexts.size();
	offset = 0;

	if (role == CLIENT) {

		clock_gettime(CLOCK_MONOTONIC, &start);
		encrypt(plaintexts, m_encSndBuf);
		clock_gettime(CLOCK_MONOTONIC, &end);
		//printf("CLIENT: Encrypted feature vector in %.0lf ms \n\n", getMillies(start, end));

		while (tosend > 0) {

			window = min(window, tosend);

			chan->send(m_encSndBuf + offset, window);
			//chan->blocking_receive(m_encRcvBuf + offset, window);

			tosend -= window;
			offset += window;
		}

	} else {

		clock_gettime(CLOCK_MONOTONIC, &start);
		while (tosend > 0) {

			window = min(window, tosend);

			//chan->send(m_encSndBuf + offset, window);
			chan->blocking_receive(m_encRcvBuf + offset, window);

			tosend -= window;
			offset += window;
		}
		clock_gettime(CLOCK_MONOTONIC, &end);
		printf("SERVER: Received encrypted feature vector in %.0lf ms \n", getMillies(start, end)); 

		ciphertexts = (mpz_t*) calloc(plaintexts.size(), sizeof(mpz_t));

		for(int i = 0; i < plaintexts.size();i++){

			mpz_init(ciphertexts[i]);
			mpz_import(ciphertexts[i], m_nBuflen, 1, 1, 1, 0, m_encRcvBuf + i * m_nBuflen);
			//gmp_printf ("ciphertext %d is %Zx\n", i, ciphertexts[i]);
		}
	}

	free(m_encSndBuf);
	free(m_encRcvBuf);
}

void PaillierParty::mskSndRcvVec(e_role role, mpz_t* &CTs, mpz_t* &rndMsks, vector<uint64_t> &selectionVec, mpz_t* &blindedInputsVec, channel* &chan){

	struct timespec start, end, startRndEnc, endRndEnc;
	double serverRndEncTime = 0; //time takes to blind the client's input
	
	mpz_t g_pow_m, rnd, tmp, packed_ct;
	mpz_inits(g_pow_m, rnd, tmp, packed_ct, NULL);
	
	uint32_t statisticalParam = 40;

	uint64_t n_batch, batch_size = m_localpub->bits / (sizeof(uint64_t)*8 + statisticalParam); // batch_size = bits / 104

	uint64_t numDecisionNodes = selectionVec.size();

	if (batch_size > numDecisionNodes)
		n_batch = 1;
	else if (numDecisionNodes % batch_size == 0)
		n_batch = numDecisionNodes / batch_size;
	else
		n_batch= numDecisionNodes / batch_size + 1;

	//std::cout << "Paillier key size: " << m_localpub->bits << "\tPacking " << batch_size << " ciphertexts in one." << std::endl;

	BYTE *m_encSndBuf, *m_encRcvBuf;
	int bufSize = n_batch * m_nBuflen;
	m_encSndBuf = (BYTE*) calloc(bufSize, 1);
	m_encRcvBuf = (BYTE*) calloc(bufSize, 1);

	int window = WINDOWSIZE;
	int tosend = m_nBuflen * n_batch;
	int offset = 0;
	uint64_t counter = 0;

	if (role == SERVER) {

		clock_gettime(CLOCK_MONOTONIC, &start);
		mpz_t* sel_enc_attr = (mpz_t*) malloc(selectionVec.size() * sizeof(mpz_t));
		
		//-------select and blind features------------
		for (int i = 0; i < selectionVec.size(); i ++)
		{
			mpz_init(sel_enc_attr[i]);
			
			clock_gettime(CLOCK_MONOTONIC, &startRndEnc);
			mpz_powm(g_pow_m, m_remotepub->n_plusone, rndMsks[i], m_remotepub->n_squared);
			clock_gettime(CLOCK_MONOTONIC, &endRndEnc);
			serverRndEncTime += getMillies(startRndEnc, endRndEnc);

			mpz_mul(sel_enc_attr[i], CTs[selectionVec[i]], g_pow_m); // blind the feature homomorphically
			mpz_mod(sel_enc_attr[i], sel_enc_attr[i] , m_remotepub->n_squared);
		}

		//-------Pack the ciphertexts------------
		counter = 0;
		for (int i = 0; i < n_batch; i++)
		{
			for (int j = 0; j < batch_size; j++)
			{
				if (j == 0) {
					mpz_set(packed_ct, sel_enc_attr[counter++]);
					continue;
				}
				mpz_ui_pow_ui(tmp, 2, 104*j);
				mpz_powm(tmp, sel_enc_attr[counter++], tmp, m_remotepub->n_squared); //shifting
				mpz_mul(packed_ct, packed_ct, tmp); // adding to the packed CT
				mpz_mod(packed_ct, packed_ct, m_remotepub->n_squared);
				if (counter == selectionVec.size())
					break;
			}
			mpz_export(m_encSndBuf + i * m_nBuflen, NULL, 1, 1, 1, 0, packed_ct); // embeds the packed ct in Snd buffer
		}
		
		clock_gettime(CLOCK_MONOTONIC, &end);
		std::cout << "SERVER: Encrypted random numbers in " << serverRndEncTime << " ms" << std::endl;
		//printf("SERVER: selected features in %.0lf ms \n\n", getMillies(start, end) - serverRndEncTime);
		
		//----- send & receive encrypted values---------
		
		while (tosend > 0) {

			window = min(window, tosend);

			chan->send(m_encSndBuf + offset, window);
			//chan->blocking_receive(m_encRcvBuf + offset, window);

			tosend -= window;
			offset += window;
		}
		
	} else { //CLIENT

		clock_gettime(CLOCK_MONOTONIC, &start);
		while (tosend > 0) {

			window = min(window, tosend);

			//chan->send(m_encSndBuf + offset, window);
			chan->blocking_receive(m_encRcvBuf + offset, window);

			tosend -= window;
			offset += window;
		}
		clock_gettime(CLOCK_MONOTONIC, &end);
		printf("CLIENT: Received blinded features in %.0lf ms \n", getMillies(start, end));

		//reconstructs the encrypted blinded values from the received raw data buffer

		clock_gettime(CLOCK_MONOTONIC, &start);

		blindedInputsVec = (mpz_t*) calloc(selectionVec.size(), sizeof(mpz_t)); //inputs to the substraction circuit in plaintext

		mpz_t mod;
		mpz_init(mod);
		mpz_ui_pow_ui(mod, 2, 104);
		
		paillier_plaintext_t rcv_packed_ct; mpz_init(rcv_packed_ct.m);
		paillier_ciphertext_t tmpCT; mpz_init(tmpCT.c);

		counter = 0;
		for (int i = 0; i < n_batch; i++)
		{
			mpz_import(tmpCT.c, m_nBuflen, 1, 1, 1, 0, m_encRcvBuf + i * m_nBuflen);
			paillier_dec(&rcv_packed_ct, m_localpub, m_prv, &tmpCT); // decryps the inputs here before returning the vec
			
			for (int j = 0; j < batch_size; j++)
			{
				mpz_init(blindedInputsVec[counter]);
				
				mpz_mod(blindedInputsVec[counter], rcv_packed_ct.m, mod);
				
				mpz_fdiv_q(rcv_packed_ct.m, rcv_packed_ct.m, mod);

				counter++;

				if (counter == selectionVec.size())
					break;
			}
		}

		clock_gettime(CLOCK_MONOTONIC, &end);
		printf("CLIENT: Depacked & decrypted blinded features in %.0lf ms 	\n", getMillies(start, end));

	#if DEBUG
		for(int i = 0;i < mapping.size();i++) {
			std::cout << "random mask: " << rndMsks[i] << " \tfeature " << mapping[i] << "\tmasked value: "; gmp_printf("%Zd", blindedInputsVec[i]); std::cout << std::endl;
		}
	#endif

	}

	//paillier_freeplaintext(&tmp);
	//paillier_freeplaintext(&rnd);
	//TODO: free unnecessary bufs;
}

void PaillierParty::printBuf(BYTE* b, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) {
		printf("%02x.", *(b + i));
	}
	std::cout << std::endl;
}

/**
 * send one mpz_t to sock
 */
void PaillierParty::sendmpz_t(mpz_t t, channel* chan, BYTE * buf) {

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
void PaillierParty::receivempz_t(mpz_t t, channel* chan, BYTE * buf) {
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
void PaillierParty::sendmpz_t(mpz_t t, channel* chan) {
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
void PaillierParty::receivempz_t(mpz_t t, channel* chan) {
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
