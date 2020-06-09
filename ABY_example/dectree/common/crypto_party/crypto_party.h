/**
 \file 		crypto_party.h
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
 \brief		Crypto functions
 */

#ifndef __CRYPTO_PARTY_H__
#define __CRYPTO_PARTY_H__

#include <ENCRYPTO_utils/channel.h>
#include "../../../..//abycore/ABY_utils/ABYconstants.h"
#include <vector>

using namespace std;

// Super class
class cryptoParty {
public:
    
    virtual void generateKey() = 0;

	virtual void keyExchange(channel* &chan) = 0;

	virtual bool readKey() = 0;

	virtual void storeKey() = 0;

	virtual bool encrypt(vector<uint64_t> &plaintexts, BYTE* &ciphertextsBuf) = 0;

	virtual void encSndRcvVec(e_role role, vector<uint64_t> &plaintexts, mpz_t* &ciphertexts, channel* &chan) = 0;

	virtual void mskSndRcvVec(e_role role, mpz_t* &CTs, mpz_t* &RndMsks, vector<uint64_t> &Mapping, mpz_t* &inputs, channel* &chan) = 0;

protected:

	//GMP PRNG
	gmp_randstate_t m_randstate;
};


#endif //__CRYPTO_PARTY_H__
