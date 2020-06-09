/**
 \file 		dgk_party.h
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


#ifndef __DGK_PAR_H__
#define __DGK_PAR_H__

#include <gmp.h>
#include <vector>
#include <iostream>
#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/socket.h>
#include <ENCRYPTO_utils/crypto/dgk.h>
#include <ENCRYPTO_utils/powmod.h>
#include <ENCRYPTO_utils/channel.h>
#include "crypto_party.h"

using namespace std;

class DGK: public cryptoParty {
public:
	DGK(uint32_t DGKbits, uint32_t sharelen, uint32_t readkey);
	DGK(uint32_t DGKbits, uint32_t sharelen, channel* chan, uint32_t readkey);
	~DGK();

	void generateKey();

	void keyExchange(channel* &chan);

	bool readKey();

	void storeKey();

	bool encrypt(vector<uint64_t> &plaintexts, BYTE* &ciphertextsBuf);

	void encSndRcvVec(e_role role, vector<uint64_t> &plaintexts, mpz_t* &ciphertexts, channel* &chan);

	void mskSndRcvVec(e_role role, mpz_t* &CTs, mpz_t* &RndMsks, vector<uint64_t> &Mapping, mpz_t* &inputs, channel* &chan);

private:
	uint16_t m_nNumMTThreads;
	uint16_t m_nShareLength;
	uint32_t m_nDGKbits;
	uint32_t m_nBuflen;

	dgk_pubkey_t *m_localpub, *m_remotepub;
	dgk_prvkey_t *m_prv;

	void sendmpz_t(mpz_t t, channel* chan, BYTE * buf);
	void receivempz_t(mpz_t t, channel* chan, BYTE * buf);

	void sendmpz_t(mpz_t t, channel* chan);
	void receivempz_t(mpz_t t, channel* chan);

	void printBuf(BYTE* b, uint32_t l);

};

#endif //__DGK_PAR_H__
