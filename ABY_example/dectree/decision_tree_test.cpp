/**
 \file 		decision_tree_test.cpp
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

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include "../../abycore/aby/abyparty.h"
#include "common/decision-tree-circuit.h"
#include "common/dectree.h"
#include <cstdlib>

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, string* filename, uint32_t* depth, uint32_t* dim, uint64_t* numNodes, uint32_t* secparam, string* address, uint16_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
			{ (void*) filename, T_STR, "f", "Input file, e.g. wine, boston, ... (provide either an input file or depth & dimension)", false, false },
			{ (void*) depth, T_NUM, "d", "Depth of tree, default: 4", false, false },
			{ (void*) dim, T_NUM, "n", "Dimension of feature vector, default: 8", false, false },
			{ (void*) numNodes, T_NUM, "m", "Number of Decision Nodes, default: 15", false, false },
			{ (void*) bitlen, T_NUM, "b", "Bit-length, default 32", false, false },
			{ (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			{ (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			{ (void*) test_op, T_NUM, "t", "Single test (leave out for all operations), default: off", false, false } };

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	cout << endl;

	//delete options;

	return 1;
}

int main(int argc, char** argv) {
	
	e_role role;
	uint32_t bitlen, secparam = 128, nthreads = 1;
	seclvl seclvl = get_sec_lvl(secparam);
	uint16_t nodeSize, port = 7760;
	string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	e_sel_alg sel_alg = SEL_GC;
	timeval tbegin, tend;

	//----Tree Params------
	uint32_t featureVecDimension = 8, depth = 4; //defaults
	uint64_t numNodes = (1 << depth) - 1; // number of decision nodes
	string dectree_rootdir = "../../src/examples/dectree/UCI_dectrees/";
	string dectree_filename = "wine";
	
	read_test_options(&argc, &argv, &role, &bitlen, &dectree_filename, &depth, &featureVecDimension, &numNodes, &secparam, &address, &port, &test_op);

	DecTree tree;
	tree.read_from_file(dectree_rootdir + dectree_filename);
	tree.depthPad();
	//tree.fullTree(featureVecDimension, depth);
	featureVecDimension = tree.num_attributes; numNodes = tree.num_dec_nodes; //Setting new values if reading from file

	cout << "Testing GGG & HGG protocols..." << endl;
	cout << "Number of decision nodes: " << numNodes << "\tFeature vector dimension: " << featureVecDimension << endl;
	cout << "\n----------------GGG Protocol----------------" << endl;
	
	/* ===GGG=== */
	pri_eval_decision_tree(role, (char*) address.c_str(), port, seclvl, nthreads, mt_alg, S_YAO,sel_alg, numNodes, featureVecDimension, tree);
	
	cout << "\n----------------HGG Protocol----------------" << endl;
	
	/* ===HGG=== */
	sel_alg = SEL_HE;
	pri_eval_decision_tree(role, (char*) address.c_str(), port, seclvl, nthreads, mt_alg, S_YAO, sel_alg, numNodes, featureVecDimension, tree);

	return 0;
}
