/**
 \file 		e_SelectionBlock.cpp
 \author 	masoud.naderpour@helsinki.fi
 \author 	michael.zohner@ec-spride.de
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
 \brief		Implementation of extended SelectionBlock
 */
#include "e_SelectionBlock.h"
#include "permutation_network.h"

void e_SelectionBlock::SelectionBlockProgram(uint32_t *p){
	uint32_t *prog1, *programm;

	if(m_nNumInputs==1) return;

	// count number of occurrences
	vector<uint32_t> c;
	c.resize(m_nNumInputs);

	for(uint32_t i=0; i<m_nNumOutputs; i++) {
		assert(p[i]>=0 && p[i]<m_nNumInputs);
		c[p[i]]++;
	}

	uint32_t sum=0, ndummys=0;
	prog1 = (uint32_t*) malloc(sizeof(uint32_t) * m_nNumInputs);

	vector<uint32_t> upos, dummy;
	upos.resize(m_nNumInputs);
	dummy.resize(m_nNumOutputs); // list of dummy outputs

	for(uint32_t i=0; i<m_nNumInputs; i++) {
		if(c[i]>0) {
			prog1[i]=sum;
			upos[i]=sum;
			if(sum>0) {
				setYProgram(sum-1, true);
				//m_vYgatesProgram[sum-1] = true;
			}
			for(uint32_t j = sum+1; j < sum+c[i]; j++) {
				setYProgram(j-1, false);
				//m_vYgatesProgram[j-1] = false;
				dummy[ndummys++]=j;
			}
			sum+=c[i];
		}
	}

	// program dummys
	uint32_t nextdummy=0;
	for(uint32_t i=0; i<m_nNumInputs; i++) {
		if(c[i]==0) {
			prog1[i]=dummy[nextdummy++];
		}
	}
	m_Pblock1->ProgramPermutationNetwork(prog1);

	// program b2

	vector<uint32_t> prog2;
	prog2.resize(m_nNumOutputs);
	for(uint32_t i=0; i<m_nNumOutputs; i++) {
		prog2[i]=upos[p[i]]++;
	}
    //change prog2 for a P_EP block
    programm = (uint32_t*) malloc(sizeof(uint32_t) * m_nNumOutputs);
    for(uint32_t i=0; i<m_nNumOutputs; i++) {
        uint32_t x = prog2[i];
        programm[x] = i;
    }
	m_Pblock2->ProgramPermutationNetwork(programm);
}

vector<vector<uint32_t> > e_SelectionBlock::buildSelectionBlockCircuit(vector<vector<uint32_t> >& inputs){
	uint32_t rep = inputs[0].size();
	vector<vector<uint32_t> > out_p1,out_g, outputs;

	if(m_nNumInputs==1) {
		for(uint32_t i=0; i<m_nNumOutputs; i++){
			outputs[i].resize(rep);
			for(uint32_t j =0; j < rep; j++)
				outputs[i][j] = inputs[0][j];
		}
		return outputs;
	}
	else {
		out_p1 = m_Pblock1->buildPermutationCircuit(inputs);

		out_g.resize(m_nNumOutputs);
		out_g[0]=out_p1[0];
		for(uint32_t i=1; i<m_nNumOutputs; i++) {
			//out_g[i]=g[i-1].extractCircuit(out_g[i-1],out_p1[i]);
			out_g[i] = PutCondYGate(out_g[i-1], out_p1[i], m_vYGates[i-1]);
		}

		return m_Pblock2->buildPermutationCircuit(out_g);
	}
}
