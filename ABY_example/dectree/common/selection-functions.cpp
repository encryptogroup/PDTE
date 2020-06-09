/**
 \file 		selection-functions.cpp
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
 \brief		Selection with HE or GC
 */

#include "decision-tree-circuit.h"
#include "selection_blocks/e_SelectionBlock.h"
#include "selection_blocks/t_SelectionBlock.h"

#define HE_SCHEME 1 //enum e_HE_crypto_party { e_DGK = 0, e_PAILLIER = 1};

/**
 * Selection function (homomorphic encryption)
 */
void selction_HE(e_role role, channel* channel, vector<uint64_t> &featureVec, seclvl seclvl, uint64_t numDecisionNodes, uint16_t* permutation, BooleanCircuit* &Circ, share** &CircOut){

	struct timespec start, end, clientOnline;
	uint32_t dimension = featureVec.size();
	uint32_t m_nStatisticalParamBits = 40; // statistical param
	uint32_t m_nFeatureSize = 64; // param t
	uint32_t m_nPlaintextSize = m_nFeatureSize + m_nStatisticalParamBits;

	/* Initilization */
	cryptoParty* cryptoPraty;

	switch(HE_SCHEME) {
		case e_DGK: {
			cryptoPraty = new DGK(seclvl.ifcbits, (uint32_t) m_nPlaintextSize, 1); // ifcbits = 3072 bits for LT security
		}
		break;
		
		case e_PAILLIER:
		default: {
			cryptoPraty = new PaillierParty(2048, 1); // ifcbits = 3072 bits for LT security
		}
		break;
	}
	cryptoPraty->keyExchange(channel);
	
	gmp_randstate_t m_randstate;
	gmp_randinit_default(m_randstate);
	gmp_randseed_ui(m_randstate, rand());

	mpz_t *m_pRandomdMasks = (mpz_t*) calloc(numDecisionNodes, sizeof(mpz_t)); // random masks vector 
	vector<uint64_t> m_nRandomMasksVec;
	vector<uint64_t> m_vSelection; // feature selection function (mapping)

	uint64_t lo, hi;
	mpz_t tmp;
	mpz_init( tmp );

	for(int i=0; i < numDecisionNodes; i++){
		mpz_init(m_pRandomdMasks[i]);
		mpz_urandomb (m_pRandomdMasks[i], m_randstate, MaskBitLen); // MaskBitLen 104
		m_vSelection.push_back(rand() % dimension); // dummy selection function 

		//truncating random masks to sizeof uint64_t
		mpz_mod_2exp( tmp, m_pRandomdMasks[i], 64 );   /* tmp = (lower 64 bits of m_pRandomdMasks[i]) */
		lo = mpz_get_ui( tmp );       /* lo = tmp & 0xffffffff */ 
		mpz_div_2exp( tmp, tmp, 32 ); /* tmp >>= 32 */
		hi = mpz_get_ui( tmp );       /* hi = tmp & 0xffffffff */
		m_nRandomMasksVec.push_back((hi << 32) + lo);
	}
	
	mpz_t *m_pEncFeatureVec, *m_pBlindedFeatureVec;

	//--------client encrypts the feature vec and sends it to server---------- 
	clock_gettime(CLOCK_MONOTONIC, &start);
	cryptoPraty->encSndRcvVec(role, featureVec, m_pEncFeatureVec, channel);

	//--------server selects & sends the inputs to subtraction circuit----------
	cryptoPraty->mskSndRcvVec(role, m_pEncFeatureVec, m_pRandomdMasks, m_vSelection, m_pBlindedFeatureVec, channel); // decrypts the inputs internally
	clock_gettime(CLOCK_MONOTONIC, &end);
	printf("client online runtime: %.0lf ms \n", getMillies(start, end));

	vector<uint64_t> m_vTruncBlindedFeatureVec(numDecisionNodes, 0);
	// Truncating client inputs to garbled circuit
	if(role == CLIENT){
		for(int i= 0; i < numDecisionNodes; i++){
			mpz_mod_2exp( tmp, m_pBlindedFeatureVec[i], 64 );   /* tmp = (lower 64 bits of m_pBlindedFeatureVec[i]) */
			lo = mpz_get_ui( tmp );    
			mpz_div_2exp( tmp, tmp, 32 );
			hi = mpz_get_ui( tmp );
			m_vTruncBlindedFeatureVec[i] = (hi << 32) + lo;
		}
		cout << "CLIENT: Input truncation done." << endl;	
	} else {
		//SleepMiliSec(10);
	}
	mpz_clear( tmp );
	
	
	uint64_t maxbitlen = 64;
	vector<uint64_t> tresholdVec;
	share **tresholdShr, **featureVecShr, **rndMasksVecShr;

	//----------------Settign server input ----------------
	tresholdShr = (share**) malloc(sizeof(share*) * numDecisionNodes);
	for(int i = 0; i < numDecisionNodes; i++) {
		tresholdVec.push_back(rand());
		tresholdShr[permutation[i]] = Circ->PutSIMDINGate(1, tresholdVec[i], maxbitlen, SERVER);
	}
	rndMasksVecShr = (share**) malloc(sizeof(share*) * numDecisionNodes);
	for(int i = 0; i < numDecisionNodes; i++) {
		rndMasksVecShr[i] = Circ->PutSIMDINGate(1, m_nRandomMasksVec[i], maxbitlen, SERVER);
	}
	//----------------Setting client input-------------
	featureVecShr = (share**) malloc(sizeof(share*) * numDecisionNodes);
	for(int i = 0; i < numDecisionNodes; i++) {
		featureVecShr[i] = Circ->PutSIMDINGate(1, m_vTruncBlindedFeatureVec[i], maxbitlen, CLIENT);
	}
	//----------------Subtraction & comparison ciruit--------------
	CircOut = (share**) malloc(sizeof(share*) * numDecisionNodes);
	assert(Circ->GetCircuitType() == C_BOOLEAN);

	for(int i = 0; i < numDecisionNodes; i++) {
		CircOut[i] = Circ->PutSUBGate(featureVecShr[i], rndMasksVecShr[i]);
		CircOut[i] = Circ->PutGTGate(CircOut[i], tresholdShr[i]);
	}
}

/**
 * Selection function (garbled circuit)
 */
void selction_GC(vector<uint64_t> &featureVec, uint64_t numDecisionNodes, uint16_t* permutation, BooleanCircuit* &Circ, share** &CircOut) {

	uint16_t dim = featureVec.size();
	uint16_t m_numNodes = numDecisionNodes;
	uint64_t maxbitlen = 64;
	
	//---- init selectionBlcok ---------------
	SelectionBlock *selBlock;
	if (m_numNodes >= dim){
		selBlock = new e_SelectionBlock(dim, m_numNodes, Circ); // extended SelectionBlock
	} else {
		selBlock = new t_SelectionBlock(dim, m_numNodes, Circ); // truncated SelectionBlock
	}

	//-----------Output Program (Mapping) of Selection Block --------------
	uint32_t *m_nMapping = (uint32_t*) malloc(sizeof(uint32_t) * m_numNodes);
	for(int i = 0; i < m_numNodes; i++){
		m_nMapping[permutation[i]] = rand() % dim;
	}
	selBlock->SelectionBlockProgram(m_nMapping);
	selBlock->SetControlBits();

	vector<uint64_t> tresholdVec;
	share **tresholdShr, **featureVecShr;

	//----------------Settign server input ----------------
	tresholdShr = (share**) malloc(sizeof(share*) * m_numNodes);
	for(int i = 0; i < m_numNodes; i++) {
		tresholdVec.push_back(rand());
		tresholdShr[permutation[i]] = Circ->PutSIMDINGate(1, tresholdVec[i], maxbitlen, SERVER);
	}

	//----------------Setting client input-------------
	featureVecShr = (share**) malloc(sizeof(share*) * dim);
	for(int j = 0; j < dim; j++) {
		featureVecShr[j] = Circ->PutSIMDINGate(1, featureVec[j], maxbitlen, CLIENT);
	}

	//---------------Building selection circuit--------------
	share **out, *cmp, *tmp;
	
	CircOut = (share**) malloc(sizeof(share*) * m_numNodes);
	assert(Circ->GetCircuitType() == C_BOOLEAN);

	vector<vector<uint32_t> > Inputs(dim);
	for(int i = 0; i < dim; i++){
		Inputs[i].resize(1);
		Inputs[i][0] = Circ->PutCombinerGate(featureVecShr[i]->get_wires());
	}

	vector<vector<uint32_t> > tempvec(m_numNodes);
	tempvec = selBlock->buildSelectionBlockCircuit(Inputs);

	share **SelectionBlockOutput = (share**) malloc(sizeof(share*) * m_numNodes);
	for (int i = 0; i < tempvec.size(); i++){
		SelectionBlockOutput[i] = new boolshare(Circ->PutSplitterGate(tempvec[i][0]), Circ);
	}
	
	for (int i=0; i < m_numNodes; i++) {
		CircOut[i] = Circ->PutGTGate(SelectionBlockOutput[i], tresholdShr[i]);
	}
}
