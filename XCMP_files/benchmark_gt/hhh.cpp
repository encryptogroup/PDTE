/**
 \file 		hhh.cpp
 \author 	kiss@encrypto.cs.tu-darmstadt.de
 \copyright	HHH protocol
			Copyright (C) 2019 Cryptography and Privacy Engineering Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		HHH protocol of Tai et al. implemented using the mcl library and the secure comparison implementation from https://github.com/fionser/XCMP
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cybozu/random_generator.hpp>
#include <cybozu/option.hpp>
#include <cybozu/crypto.hpp>
#include <cybozu/itoa.hpp>
#include <mcl/fp.hpp>
#include <mcl/ec.hpp>
#include <mcl/elgamal.hpp>
#include <mcl/ecparam.hpp>
#include <sys/time.h>
#include <mcl/bn256.hpp>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network.hpp"
#include "dectree.hpp"
#define PROT 0 //0 for HHH, 1 for HH(G), 2 for (GG)/(HG)H where the parts in brackets are executed outside of this code before/after
#define DT 0 //0 for wine", 1 for iris, 2 for breast cancer, 3 for digits, 4 for diabetes, 5 for linnerud, 6 for boston

typedef mcl::FpT<> Fp;
typedef mcl::FpT<mcl::ZnTag> Zn; // use ZnTag because Zn is different class with Fp
typedef mcl::EcT<Fp> Ec;
typedef mcl::ElgamalT<Ec, Zn> Elgamal;

cybozu::RandomGenerator rg;

const uint32_t bitlen = 64;
uint32_t ElGamalBits = 514;
uint32_t Buflen = ElGamalBits / 8 + 1; //size of one ciphertext to send via network. Paillier uses n bits == n/8 bytes

using namespace std;

void SysInit()
{
	const mcl::EcParam& para = mcl::ecparam::secp256k1;
	Zn::init(para.n);
	Fp::init(para.p);
	Ec::init(para.a, para.b);
}

//NETWORK BEGIN

void send_ctxts(std::vector<Elgamal::CipherText> const& ctxts,
		tcp::iostream &conn)
{
	for (const auto &ctx : ctxts)
		conn << ctx << '\n';
}

void receive_ctxts(std::vector<Elgamal::CipherText> &ctxts, int32_t num,
		tcp::iostream &conn)
{
	ctxts.resize(num);
	for (int32_t i = 0; i < num; i++)
		conn >> ctxts[i];
}

//NETWORK END

//COMPARISON PROTOCOL BEGIN

vector<Elgamal::CipherText> encBitbyBitPrecomp(const Elgamal::PublicKey& pub){
	vector<Elgamal::CipherText> xenc(bitlen);
	for(int32_t i = bitlen - 1; i >= 0; --i){
		pub.enc_off(xenc[bitlen - i - 1], rg);
	}
	return xenc;
}

void encBitbyBitOnline(const Elgamal::PublicKey& pub, vector<Elgamal::CipherText>& xenc, uint64_t x){
	int bit;
	for(int32_t i = bitlen - 1; i >= 0; --i){
		bit = (x >> i) & 1;
		pub.enc_on(xenc[bitlen - i - 1], bit);
	}
}

vector<Elgamal::CipherText> encBitbyBit(const Elgamal::PublicKey& pub, uint64_t x){
	vector<Elgamal::CipherText> xenc(bitlen);
	int bit;
	for(int32_t i = bitlen - 1; i >= 0; --i){
		bit = (x >> i) & 1;
		pub.enc(xenc[bitlen - i - 1], bit, rg);
	}
	return xenc;
}

vector<int> getBits(uint64_t number){
	vector<int> bits(bitlen);
	for(uint32_t i = 0; i < bitlen; ++i){
		bits[i] = (number >> (bitlen-i-1)) & 1;   
	}
	return bits;
}

Elgamal::CipherText xorWithConst(const Elgamal::PublicKey& pub, Elgamal::CipherText toXor, int thres){
	Elgamal::CipherText result(toXor);
	if(thres == 1){
		result.neg();
		pub.add(result, 1);
	}
	else{
		pub.rerandomize(result, rg);
	}
	return result;
}

vector<Elgamal::CipherText> PvtCmpS(const Elgamal::PublicKey& pub, Elgamal::CipherText& tmpsum, vector<Elgamal::CipherText> xenc, int64_t threshold, int server_bit){
	vector<Elgamal::CipherText> result(bitlen); 
	vector<int> yBits =  getBits(threshold); 
	int32_t s = 1-2*server_bit; //BINDER
	Elgamal::CipherText currentRes, xorRes;

	for(uint32_t i = 0; i < bitlen; ++i){
		currentRes = xenc[i];
		pub.add(currentRes, s - yBits[i]); // x_i - y_i + s (latter two values known to server)
		xorRes = xorWithConst(pub, xenc[i], yBits[i]); //y_i + x_i
		xorRes.mul(3); //*3
		if(i > 0){
			currentRes.add(tmpsum);
		}
		tmpsum.add(xorRes);
		result[i] = currentRes;
	}
	std::random_shuffle(result.begin(), result.end());
	return result;
}

//decryption
int32_t PvtCmpC(const Elgamal::PrivateKey& prv, vector<Elgamal::CipherText> c){
	for(uint32_t i = 0; i < bitlen; ++i){
		if(prv.isZeroMessage(c[i])){
			return 1;
		}
	}
	return 0;
}

uint32_t testCompClient(const Elgamal::PublicKey& pub, const Elgamal::PrivateKey& prv, uint64_t client_input, tcp::iostream &conn){
	vector<Elgamal::CipherText> enc_bits = encBitbyBitPrecomp(pub);
	encBitbyBitOnline(pub, enc_bits, client_input);
	send_ctxts(enc_bits, conn);

	std::vector<Elgamal::CipherText> gt_result;
	receive_ctxts(gt_result, bitlen, conn);

	uint32_t s = PvtCmpC(prv, gt_result);
	cout << client_input << "  " << s << endl;
	return s;
}

uint32_t testCompServer(const Elgamal::PublicKey& pub, uint64_t server_input, tcp::iostream &conn){
	uint32_t server_bit = std::rand() & 1;
	cout << server_input << "  " << server_bit << endl;

	std::vector<Elgamal::CipherText> ctxts;
	receive_ctxts(ctxts, bitlen, conn);
	assert(ctxts.size() == bitlen);

	Elgamal::CipherText tmpsum;
	pub.enc(tmpsum, 0, rg); //ciphertext for m = 0

	vector<Elgamal::CipherText> gt_result =  PvtCmpS(pub, tmpsum, ctxts, server_input, server_bit);

	send_ctxts(gt_result, conn);
	return server_bit;
}

//COMPARISON PROTOCOL END

//EVALUATION PROTOCOL BEGIN

void calculatePathCosts(const Elgamal::PublicKey& pub, DecTree& tree, vector<Elgamal::CipherText>& pathCost,
		vector<Elgamal::CipherText>& classif, vector<Elgamal::CipherText>& edgeCost0,
		vector<Elgamal::CipherText>& edgeCost1, vector<uint64_t>& rand1, vector<uint64_t>& rand2){
	Elgamal::CipherText tmp;
	uint32_t i = 0, k = 0;
	for(uint32_t j = 0; j < tree.node_vec.size(); j++){
		//start calculating path costs
		if(tree.node_vec[j]->parent == NULL){ //if root
			tree.node_vec[j]->right->path_cost = edgeCost1[i];
			//right is 0, left is 1, could also be the other way around
			tree.node_vec[j]->left->path_cost = edgeCost0[i];
			i++;
		}
		else if(!(tree.node_vec[j]->leaf)){ //decision nodes
			edgeCost1[i].add(tree.node_vec[j]->path_cost);
			edgeCost0[i].add(tree.node_vec[j]->path_cost);
			
			tree.node_vec[j]->right->path_cost = edgeCost1[i];
			tree.node_vec[j]->left->path_cost = edgeCost0[i];
			i++;
		}
		else if(tree.node_vec[j]->leaf){
			tmp = tree.node_vec[j]->path_cost;
			tree.node_vec[j]->path_cost.mul(rand1[k]);
			pathCost[k] = tree.node_vec[j]->path_cost;

			tmp.mul(rand2[k]);
			pub.add(tmp, tree.node_vec[j]->classification);
			classif[k] = tmp;

			k++;
		}
	}
}

//EVALUATION PROTOCOL END


//CLIENTSERVER BEGIN

void play_server(tcp::iostream &conn)
{
	const char* filename[7] = {
			"../../../UCI_dectrees/wine",
			"../../../UCI_dectrees/iris",
			"../../../UCI_dectrees/breast",
			"../../../UCI_dectrees/digits",
			"../../../UCI_dectrees/diabetes",
			"../../../UCI_dectrees/linnerud",
			"../../../UCI_dectrees/boston"
	};
	uint32_t i = DT, k = 0;
	DecTree tree;
	tree.read_from_file(filename[i]);
	//tree.depthPad(); //for benchmarking inefficient protocol HHG

	conn << tree.num_attributes  << '\n';
	conn << tree.num_dec_nodes  << '\n';

	timeval tbegin, tend;

	Elgamal::PublicKey pub;
	conn >> pub; //reads public key

	//COMPARISON OFFLINE
	gettimeofday(&tbegin, NULL);
	vector<uint64_t> server_bits(tree.num_dec_nodes);
	vector<Elgamal::CipherText> tmpsum(tree.num_dec_nodes);
	if(PROT == 0 || PROT == 1){	
		for (uint32_t i = 0; i < tree.num_dec_nodes; i++) {
			server_bits[i] = std::rand() & 1;
		}
		for(uint32_t i = 0; i < tree.num_dec_nodes; i++){
			pub.enc(tmpsum[i], 0, rg); //ciphertext for m = 0
		}
		gettimeofday(&tend, NULL);
		cout << "Comp Offline: " << ((tend.tv_sec-tbegin.tv_sec)*1000000 + tend.tv_usec - tbegin.tv_usec)/1000 << "ms" << endl;
	}

	//EVAL OFFLINE
	gettimeofday(&tbegin, NULL);
	vector<uint64_t> rand1(tree.num_dec_nodes + 1);
	vector<uint64_t> rand2(tree.num_dec_nodes + 1);
	vector<int> indeces(tree.num_dec_nodes + 1);
	if(PROT == 0 || PROT == 2){
		for(uint32_t i = 0; i < tree.num_dec_nodes + 1; ++i){
			rand1[i] = rg.get64();
			rand2[i] = rg.get64();
		}
		for(uint32_t i = 0; i < tree.num_dec_nodes + 1; ++i){
			indeces.push_back(i);
		}
		std::random_shuffle(indeces.begin(), indeces.end());

		gettimeofday(&tend, NULL);
		cout << "Eval Offline: " << ((tend.tv_sec-tbegin.tv_sec)*1000000 + tend.tv_usec - tbegin.tv_usec)/1000 << "ms" << endl;
	}

	//COMPARISON ONLINE
	gettimeofday(&tbegin, NULL);
	vector< vector<Elgamal::CipherText> > gt_results(tree.num_dec_nodes);
	if(PROT == 0 || PROT == 1){
		std::vector< std::vector<Elgamal::CipherText> > ctxts(tree.num_attributes);
		for (uint32_t i = 0; i < tree.num_attributes; i++) {
			receive_ctxts(ctxts[i], bitlen, conn);
		}

		for(uint32_t i = 0; i < tree.num_dec_nodes; i++){
			gt_results[i] = PvtCmpS(pub, tmpsum[i], ctxts[tree.decnode_vec[i]->attribute_index],
				tree.decnode_vec[i]->threshold, server_bits[i]);
			//cout << tree.decnode_vec[i]->threshold << " " << server_bits[i] << " " << tree.decnode_vec[i]->attribute_index << endl; CHECKED CORRECT
			send_ctxts(gt_results[i], conn);
		}
		gettimeofday(&tend, NULL);
		cout << "Comp Online: " << ((tend.tv_sec-tbegin.tv_sec)*1000000 + tend.tv_usec - tbegin.tv_usec)/1000 << "ms" << endl;
	}
	if(PROT == 1){
		ofstream output_shares;
		output_shares.open("../../../output/compH_shares_server.txt");
		for(uint32_t i = 0; i < tree.num_dec_nodes; i++){
			output_shares << server_bits[i] << endl;
		}
		output_shares.close();
	}
	if(PROT == 2){
		ifstream output_shares;
		char c;
		output_shares.open("../../../output/compG_shares_server.txt");
		uint32_t j = 0;
		while(output_shares >> server_bits[j]){
			j++;
		}
		if(j != tree.num_dec_nodes){
			cerr << "PROBLEM " << j << " " << tree.num_dec_nodes << endl;
		}
		output_shares.close();
	}

	//EVAL ONLINE
	gettimeofday(&tbegin, NULL);
	vector< vector<Elgamal::CipherText> > reenc(tree.num_dec_nodes);
	vector<Elgamal::CipherText> edgeCost1(tree.num_dec_nodes);
	vector<Elgamal::CipherText> edgeCost0(tree.num_dec_nodes);
	if(PROT == 0 || PROT == 2){
		for(uint32_t i = 0; i < tree.num_dec_nodes; i++){
			receive_ctxts(reenc[i], 1, conn);
			edgeCost1[i] = xorWithConst(pub, reenc[i][0], server_bits[i]);
			edgeCost0[i] = edgeCost1[i];
			edgeCost1[i].mul(-1);
			pub.add(edgeCost1[i], 1);
		}

		vector<Elgamal::CipherText> pathCost(tree.num_dec_nodes + 1); //path costs on the leaves only!
		vector<Elgamal::CipherText> classif(tree.num_dec_nodes + 1); //classification on the leaves only!

		calculatePathCosts(pub, tree, pathCost, classif, edgeCost0, edgeCost1, rand1, rand2);

		vector<Elgamal::CipherText> pathCost_shuffled(tree.num_dec_nodes + 1);
		vector<Elgamal::CipherText> classif_shuffled(tree.num_dec_nodes + 1);
		for(uint32_t i = 0; i < tree.num_dec_nodes + 1; ++i){
			pathCost_shuffled[i] = pathCost[indeces[i]];
			classif_shuffled[i] = classif[indeces[i]];
		}
		send_ctxts(pathCost, conn);
		send_ctxts(classif, conn);

		gettimeofday(&tend, NULL);
		cout << "Eval Online: " << ((tend.tv_sec-tbegin.tv_sec)*1000000 + tend.tv_usec - tbegin.tv_usec)/1000 << "ms" << endl;
	}
}

void play_client(tcp::iostream &conn)
{

	uint32_t num_attributes;
	uint32_t num_dec_nodes;
	conn >> num_attributes;
	conn >> num_dec_nodes;

	vector<uint64_t> client_inputs(num_attributes); //all values initialized, we need more than num_attributees because not all of them are used, which we do not consider
	for(uint32_t j = 0; j < num_attributes; ++j){
		client_inputs[j] = rg.get64() % 10000;
		//cout << j << " " << client_inputs[j] << endl;
	}
	//tree.evaluate(client_inputs);

	timeval tbegin, tend;

	const mcl::EcParam& para = mcl::ecparam::secp256k1;
	const Fp x0(para.gx);
	const Fp y0(para.gy);
	const Ec P(x0, y0);

	Elgamal::PrivateKey prv;
	prv.init(P, para.bitSize, rg);
	const Elgamal::PublicKey& pub = prv.getPublicKey();

	conn << pub << '\n'; //sends public key

	//COMPARISON OFFLINE
	gettimeofday(&tbegin, NULL);
	vector< vector<Elgamal::CipherText> > enc_bits(num_attributes);
	if(PROT == 0 || PROT == 1){
		for(uint32_t j = 0; j < num_attributes; ++j){
			enc_bits[j] = encBitbyBitPrecomp(pub);
		}

		gettimeofday(&tend, NULL);
		cout << "Comp Offline: " << ((tend.tv_sec-tbegin.tv_sec)*1000000 + tend.tv_usec - tbegin.tv_usec)/1000 << "ms" << endl;
	}

	//EVAL OFFLINE
	gettimeofday(&tbegin, NULL);
	vector< std::vector<Elgamal::CipherText> > gt_results_off(num_dec_nodes);
	if(PROT == 0 || PROT == 2){
		for(uint32_t j = 0; j < num_dec_nodes; ++j){
			gt_results_off[j].resize(1);
			pub.enc_off(gt_results_off[j][0], rg);
		}
		gettimeofday(&tend, NULL);
		cout << "Eval Offline: " << ((tend.tv_sec-tbegin.tv_sec)*1000000 + tend.tv_usec - tbegin.tv_usec)/1000 << "ms" << endl;
	}

	//COMPARISON ONLINE
	gettimeofday(&tbegin, NULL);
	vector< std::vector<Elgamal::CipherText> > gt_results(num_dec_nodes);
	vector<uint32_t> client_out(num_dec_nodes);
	if(PROT == 0 || PROT == 1){
		for(uint32_t j = 0; j < num_attributes; ++j){
			encBitbyBitOnline(pub, enc_bits[j], client_inputs[j]);
			send_ctxts(enc_bits[j], conn);
		}

		for(uint32_t j = 0; j < num_dec_nodes; ++j){
			receive_ctxts(gt_results[j], bitlen, conn);
			client_out[j] = PvtCmpC(prv, gt_results[j]);
			//cout << client_out[j] << endl; CHECKED CORRECT
		}

		gettimeofday(&tend, NULL);
		cout << "Comp Online: " << ((tend.tv_sec-tbegin.tv_sec)*1000000 + tend.tv_usec - tbegin.tv_usec)/1000 << "ms" << endl;
	}
	if(PROT == 1){
		ofstream output_shares;
		output_shares.open("../../../output/compH_shares_client.txt");
		for(uint32_t j = 0; j < num_dec_nodes; j++){
			output_shares << client_out[j] << endl;
		}
		output_shares.close();
	}
	if(PROT == 2){
		ifstream output_shares;
		char c;
		output_shares.open("../../../output/compG_shares_client.txt");
		uint32_t j = 0;
		while(output_shares >> client_out[j]){
			j++;
		}
		if(j != num_dec_nodes){
			cerr << "PROBLEM " << j << " " << num_dec_nodes << endl;
		}
		output_shares.close();
	}

	//EVAL ONLINE
	gettimeofday(&tbegin, NULL);
	vector<Elgamal::CipherText> pathCost(num_dec_nodes + 1); //path costs on the leaves only!
	vector<Elgamal::CipherText> classif(num_dec_nodes + 1); //classification on the leaves only!
	Zn result;
	if(PROT == 0 || PROT == 2){
		for(uint32_t j = 0; j < num_dec_nodes; ++j){
			pub.enc_on(gt_results_off[j][0], client_out[j]);
			//pub.enc(gt_results[j][0], client_out[j], rg);
			send_ctxts(gt_results_off[j], conn);
		}
		receive_ctxts(pathCost, num_dec_nodes + 1, conn);
		receive_ctxts(classif, num_dec_nodes + 1, conn);

		for(uint32_t j = 0; j < pathCost.size(); ++j){
			if(prv.isZeroMessage(pathCost[j])){
				prv.dec(result, classif[j], 1000);
			}
		}

		gettimeofday(&tend, NULL);
		cout << "Eval Online: " << ((tend.tv_sec-tbegin.tv_sec)*1000000 + tend.tv_usec - tbegin.tv_usec)/1000 << "ms" << endl << endl;
		cout << "Evaluation result: " << result << endl;
	}
}

//CLIENTSERVER END

int main(int argc, char *argv[]) {
	long r = 0; //0 for server, 1 for client
	if (argc > 1)
		r = std::stol(argv[1]);
	SysInit();
	std::srand(std::time(0));

	switch(r) {
	case 0:
		std::cout << "waiting for client..." << std::endl;
		run_server(play_server);
		break;
	case 1:
		std::cout << "connect to server..." << std::endl;
		run_client(play_client);
		break;
	}
	return 0;
}

