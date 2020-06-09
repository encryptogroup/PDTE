/**
 \file 		decision-tree-circuit.cpp
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
 \brief	    Private decision tree evaluation
 */

#include "decision-tree-circuit.h"
#include "garbledBP.h"
#include "sndrcv.h"
#include <algorithm>
#include <sys/time.h>
#include "auxiliary-functions.h"
#include "../../../abycore/sharing/sharing.h"

//#define AES_NOT_HASH

int pri_eval_decision_tree(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing comparesharing, e_sel_alg sel_alg, uint64_t numNodes, uint64_t dimension, DecTree &tree) {

	//=============== Initialization ================

	uint32_t bitlen = 8, i, j, maxbitlen=64, keybitlen = seclvl.symbits, keysize = keybitlen/8;
	uint16_t m_numNodes = numNodes;
	uint16_t dim = dimension;
	uint32_t nodeSize = keysize + sizeof(uint16_t) + sizeof(uint8_t);
	uint8_t *m_cGarbledTree;
	
	timeval tbegin, tend;
	srand(time(NULL));

	// ----- generate a random permutation of [0 1...d-1] ----------
	uint16_t *permutation;
	permutation = new uint16_t[m_numNodes];
	for (uint16_t i = 0;i < m_numNodes;i++) permutation[i] = i;
	random_shuffle(permutation + 1, permutation + m_numNodes ); //permutation[0] = 0 */

	//----------- generate a random feature vector ----------------
	vector<uint64_t> m_vFeatureVec;

	for(int i=0; i < dim; i++){
		m_vFeatureVec.push_back(rand());
		//cout << "Feature " << i << ":" << m_vFeatureVec[i] << endl;
	}

	// ---- ABY init --------
	ABYParty* party = new ABYParty(role, address, port, seclvl, keybitlen, nthreads, mt_alg);

	vector<Sharing*>& sharings = party->GetSharings();
	BooleanCircuit *permuteCirc, *cmpCirc;
	//permuteCirc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine(); // for B+Y testing
	cmpCirc = (BooleanCircuit*) sharings[S_YAO]->GetCircuitBuildRoutine();
	permuteCirc = cmpCirc;

	share **m_shrCircOutput, **output;

	//----- Communication channel establishment ----------
	NetConnection* netConnection = new NetConnection(address, port+1);
	if (!netConnection->EstConnection(role)) {
		std::exit(EXIT_FAILURE);
	}
	
	//===============Feature selection ===================
	switch(sel_alg) {
		case SEL_HE:
		{
			cout << "**Runing oblivious selection subprotocol (homomorphic encryption)..." << endl;
			selction_HE(role, netConnection->commChannel, m_vFeatureVec, seclvl, numNodes, permutation, cmpCirc, m_shrCircOutput);
		}
		break;
		case SEL_GC:
		{
		    cout << "**Runing oblivious selection subprotocol (garbled circuit)..." << endl;
			selction_GC(m_vFeatureVec, m_numNodes, permutation, cmpCirc, m_shrCircOutput);
		}
		break;
	}
	cout << "\n**Running oblivious comparison subprotocol (Yao's garbled circuit protocol)..." << endl;
	party->ExecCircuit();

	//------garbled key/colour bit per node--------
	uint8_t **circuitOutputKeys = (uint8_t**) malloc(sizeof(uint8_t*) * m_numNodes);
	
	for (i = 0;i < m_numNodes;i++) {
		circuitOutputKeys[i] = (uint8_t*) malloc(sizeof(uint8_t) * keysize);
		memcpy(circuitOutputKeys[i], cmpCirc->GetEvaluatedKey(m_shrCircOutput[i]->get_wire_id(0)), keysize);
		//cout << "circuitOutputKeys" << i << ": "; print(circuitOutputKeys[i], keysize);
	}

	ofstream serverOutputFile ("server_colour_bits.txt");
	ofstream clientOutputFile ("client_colour_bits.txt");
	BYTE *pi, colorBit;
	CSocket socket;
	uint16_t port = 7750;

	if (role == SERVER) {
		if (serverOutputFile.is_open()) {
			cout << "Writing server colour bits to file..." << endl; 
			for (i = 0; i < numNodes; i++) {
				pi = permuteCirc->GetPi(m_shrCircOutput[i]->get_wire_id(0));
				serverOutputFile << int(*pi) << endl;
			}
			serverOutputFile.close();
		}
		
		BYTE *tmp, *R, *pi, colorBit;
		tmp = new uint8_t[keysize];
		R = new uint8_t[keysize];
		uint8_t **pointerKey, *binPermute;
		pointerKey = new uint8_t*[2*m_numNodes];
		binPermute = new uint8_t[m_numNodes];

		memcpy(R, ((YaoServerSharing*)sharings[S_YAO])->get_R().GetArr(), keysize); //R: global difference of garbled pairs

		for (i = 0; i < m_numNodes; i++){
			pointerKey[2*i] = new uint8_t[keysize];
			pointerKey[2*i+1] = new uint8_t[keysize];
			memcpy(tmp, permuteCirc->GetServerRandomKey(m_shrCircOutput[i]->get_wire_id(0)), keysize);
			pi = permuteCirc->GetPi(m_shrCircOutput[i]->get_wire_id(0));
			memcpy(binPermute + i, pi, sizeof(uint8_t));
			memcpy(pointerKey[2 * i], tmp, keysize);
			Xor(tmp, R, keysize);
			memcpy(pointerKey[2 * i + 1], tmp, keysize);
		}

		cout << "\n**Running oblivious path evaluation subprotocol (garbled decision tree)..." << endl;
		gettimeofday(&tbegin, NULL);
		m_cGarbledTree = create_garbled_tree(tree, seclvl, pointerKey, binPermute, permutation);
		gettimeofday(&tend, NULL);

		sendGarbledDT( netConnection->commChannel , m_numNodes, nodeSize, m_cGarbledTree );
		cout << "SERVER: Created garbled decision tree in: " << time_diff_microsec(tbegin, tend) << "us" << endl;
	} else { // role = client
		if (clientOutputFile.is_open()) {
			cout << "Writing client colour bits to file..." << endl;
			for (i = 0; i < numNodes; i++) {
				colorBit = circuitOutputKeys[i][keysize-1] & 0x01;
				clientOutputFile << int(colorBit) << endl;
			}
			clientOutputFile.close();
		}
		cout << "\n**Running oblivious path evaluation subprotocol (garbled decision tree)..." << endl;
		m_cGarbledTree = (uint8_t*) malloc(sizeof(uint8_t) *m_numNodes * nodeSize * 2);
		bool success = false;
		success = receiveGarbledDT(netConnection->commChannel, m_numNodes, nodeSize, m_cGarbledTree);
		if (success) {
			Eval_garbled_tree( m_cGarbledTree, circuitOutputKeys, m_numNodes, seclvl.symbits/8, nodeSize, seclvl);
		}
	}
	
	//TODO: free
	delete party;
	return 0;
}

uint8_t* create_garbled_tree(DecTree &dectree, seclvl seclvl, uint8_t** pointerKey, uint8_t* binPermute, uint16_t* permutation){

	crypto *crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	//cout << "seclvl.symbits: " << seclvl.symbits << endl;
	const int type = sizeof(uint8_t), nodeIdxSize = sizeof(uint16_t), keySize = seclvl.symbits/8; // Size * Byte
	const int size = type + nodeIdxSize + keySize; //1+2+16
	//cout << "data size: " << size << endl;

	//	n: number of nodes, d: number of decision nodes
	uint16_t n = dectree.node_vec.size(), d =  dectree.num_dec_nodes;

	//generate random numbers as keys to hash fuction
	uint8_t **nodeKey;
	nodeKey = new uint8_t*[d];

	for(int i = 0; i < d; i++){
		nodeKey[i] = new uint8_t[keySize];
		crypt->gen_rnd(nodeKey[i],keySize);
		//print(nodeKey[i],keySize);
	}
	//nodekey[0] = 0
	memset(nodeKey[0],0,keySize);
	//print(nodeKey[0],keySize);

	//create garbled decision tree
	garbldNode *garbledTree = new garbldNode[d];
	uint8_t *gTree = (uint8_t*) malloc(sizeof(uint8_t) * d * size * 2);


	//copy node data from tree
	uint64_t global_index = 0;
	uint16_t i,j, rindex , lindex;
	uint32_t length = 0;
	DecTree::Node* current_node;

	for(i = 0; i < dectree.num_dec_nodes; i++){

		current_node = dectree.decnode_vec[i];
		j = permutation[i];
		garbledTree[j].rnode = new uint8_t[size];
		garbledTree[j].lnode = new uint8_t[size];
		uint8_t *r = garbledTree[j].rnode, *l = garbledTree[j].lnode;
		
		if (current_node->right != current_node->left) { // non-dummy node

			//left node's data of node i in garbled Tree : [TYPE, PERMUTED INDEX, DELTA]
			lindex = ++global_index;
			if (!(current_node->left->leaf)){
				*l = 0x00; // type : decision
				memcpy(l+type, &(permutation[lindex]), nodeIdxSize); //nodeId
				memcpy(l+type+nodeIdxSize, nodeKey[permutation[lindex]], keySize); //nodeKey
			}
			else{
				*l = 0x01; // type : classification
				memcpy(l+type, &(current_node->left->classification), sizeof(uint64_t)); // Classification label
				memset(l+type+length, 0, size-(type+length));//Padding

			}
			//print(l,size);

			//right node:
			rindex = ++global_index;
			if (!(current_node->right->leaf)){
				*r = 0x00; // type : decision
				memcpy(r+type, &(permutation[rindex]), nodeIdxSize); //nodeId
				memcpy(r+type+nodeIdxSize, nodeKey[permutation[rindex]], keySize); // nodeKey
			}
			else{
				*r = 0x01; // type : classification
				memcpy(l+type, &(current_node->right->classification), sizeof(uint64_t)); // Classification label
				memset(l+type+length, 0, size-(type+length));//Padding
			}
			//print(r,size);
		} else {

			lindex = ++global_index;
			if (!(current_node->left->leaf)){
				*l = 0x00; // type : decision
				memcpy(l+type, &(permutation[lindex]), nodeIdxSize); //nodeId
				memcpy(l+type+nodeIdxSize, nodeKey[permutation[lindex]], keySize); //nodeKey
			}
			else{
				*l = 0x01; // type : classification
				memcpy(l+type, &(current_node->left->classification), sizeof(uint64_t)); // Classification label
				memset(l+type+length, 0, size-(type+length));//Padding

			}
			//print(l,size);

			//right node:
			rindex = lindex; //dummy node
			memcpy(r, l, size);
			//print(r,size);
		}
	}

	uint8_t *key, *ExpKey, colorBit;
	key = new uint8_t[keySize];
	ExpKey = new uint8_t[size];

	//cout << "Encrypted nodes:" << endl;

		for( i = 0;i < d;i++ ){
		colorBit = (pointerKey[2 * i][keySize-1]) & 0x01;

		//Encrypt left node
		memcpy(key, nodeKey[i], keySize);
		timeval tbegin, tend;
		gettimeofday(&tbegin, NULL);
		
		#ifdef AES_NOT_HASH
			uint8_t* one = {};
			crypt->encrypt(ExpKey, one, keySize);
			//crypt->encrypt(Xor(key, pointerKey[2 * i + (colorBit ^ binPermute[i])], keySize), ExpKey, one, keySize);
			//crypt->encrypt(Xor(key, pointerKey[2 * i + (colorBit ^ binPermute[i])], keySize), ExpKey,  zero, keySize);
		#else
			crypt->hash(ExpKey, size, Xor(key, pointerKey[2 * i + (colorBit ^ binPermute[i])], keySize), keySize);
		#endif

		gettimeofday(&tend, NULL);
		//cout << "Hash/AES Time: " << ((tend.tv_sec-tbegin.tv_sec)*1000000 + tend.tv_usec - tbegin.tv_usec) << "us" << endl;
		//cout << "hash keys: ";print(ExpKey,size);
		Xor(garbledTree[i].lnode, ExpKey, size);
		//cout << "l node: ";print(garbledTree[i].lnode,size);

		//Encrypt right node
		memcpy(key, nodeKey[i], keySize);
		
		#ifdef AES_NOT_HASH
				crypt->encrypt(ExpKey, one, keySize);
				//crypt->encrypt(Xor(key, pointerKey[2 * i + !(colorBit ^ binPermute[i])], keySize), ExpKey, one, keySize);
		#else
				crypt->hash(ExpKey, size, Xor(key, pointerKey[2 * i + !(colorBit ^ binPermute[i])], keySize), keySize);
		#endif
		
		//cout << "hash keys: "; print(ExpKey,size);
		Xor(garbledTree[i].rnode, ExpKey, size);
		//cout << "r node: ";print(garbledTree[i].rnode,size);


		//swap nodes randomly
		if (binPermute[i]){
			swap(garbledTree[i].rnode, garbledTree[i].lnode);
		}
		memcpy(gTree+(2*i) * size, garbledTree[i].lnode, size);
		memcpy(gTree+(2*i + 1) * size, garbledTree[i].rnode, size);
	}

	//delete[] permutation;
	//delete[] garbledTree;
	return gTree;

}

int Eval_garbled_tree(uint8_t *garbledTree, uint8_t **keys, uint16_t d, uint32_t keysize, uint32_t msgsize, seclvl seclvl){

	crypto *crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	timeval tbegin, tend;
	uint8_t *nodekey, *data, colorBit;
	uint16_t i, nodeID  = 0 ;
	string classlabel;
	nodekey = new uint8_t[keysize];
	data = new uint8_t[msgsize];

	gettimeofday(&tbegin, NULL);
	memset(nodekey, 0, keysize); //nodekey[0] = 0
	i = 0;
	while(1){

		#ifdef AES_NOT_HASH
				crypt->encrypt(Xor(nodekey, keys[i], keysize), data, one, keysize);
		#else
				crypt->hash(data, msgsize, Xor(nodekey, keys[i], keysize), keysize);
		#endif

		colorBit = keys[i][keysize-1] & 0x01;
		//Decrypting the currentnode
		if (colorBit = 0x00){
			Xor(data, garbledTree + (2*i)*msgsize, msgsize);
		} else {
			Xor(data, garbledTree + (2*i+1)*msgsize, msgsize);
		}
		//evaluating the decrypted node
		if(data[0]){ //classification node
			//cout << " retrieved classification label! "; //TODO: print the classification value
			break;
		} else { //Decision node
			memcpy( &i, data+1, sizeof(uint16_t));
			memcpy( nodekey, data+3, keysize);
		}
	}

	gettimeofday(&tend, NULL);
	printf("CLIENT: Evaluated garbled decision tree in: %.0lf us\n" , time_diff_microsec(tbegin , tend));	

	delete[] nodekey;
	delete[] data;
	return 0;
}
