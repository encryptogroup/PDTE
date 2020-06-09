/**
 \file 		decision-tree-circuit.h
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
 \brief		Private decision tree evaluation
 */

#ifndef __DECISION_TREE_H_
#define __DECISION_TREE_H_

#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/sharing/yaoserversharing.h"
#include "selection_blocks/selection_block.h"
#include "crypto_party/crypto_party.h"
#include "crypto_party/dgk_party.h"
#include "crypto_party/paillier_party.h"
#include "dectree.h"

#include <vector>
#include <cassert>

#define RANDOM_TESTCASE
#define MaskBitLen 104
//#define BP_DEBUG

enum e_sel_alg{ SEL_HE = 0, SEL_GC = 1};
enum e_eval_alg{ EVAL_HE = 0, EVAL_GC = 1};
enum e_HE_crypto_party { e_DGK = 0, e_PAILLIER = 1};

void selction_HE(e_role role, channel* channel, vector<uint64_t> &featureVec, seclvl seclvl, uint64_t NumDecisionNodes, uint16_t* permutation, BooleanCircuit* &Circ, share** &CircOut);

void selction_GC(vector<uint64_t> &featureVec, uint64_t numDecisionNodes, uint16_t* permutation, BooleanCircuit* &Circ, share** &CircOut);

int pri_eval_decision_tree(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing comparesharing, e_sel_alg sel_alg, uint64_t numNodes, uint64_t dimension, DecTree &tree);

uint8_t* create_garbled_tree(DecTree &dectree, seclvl seclvl, uint8_t** pointerKey, uint8_t* binPermute, uint16_t* permute);

int Eval_garbled_tree(uint8_t *glbp, uint8_t **keys, uint16_t d, uint32_t keysize, uint32_t msgsize, seclvl seclvl);

//void verify(vector<uint64_t> const &featureVec, BranchingProgram* BP);

#endif /* __DECISION_TREE_H_ */
