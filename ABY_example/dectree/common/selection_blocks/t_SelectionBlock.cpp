/**
 \file 		t_SelectionBlock.cpp
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
 \brief		Implementation of truncated SelectionBlock
 */
#include "t_SelectionBlock.h"
#include "permutation_network.h"

Truncated_PN::WaksmanPermutation::~WaksmanPermutation() {
	// TODO Auto-generated destructor stub
}

void Truncated_PN::WaksmanPermutation::program_rec(uint32_t out, uint32_t block, uint32_t* p1, uint32_t* p2, uint32_t* rows, uint32_t* cols) {
	uint32_t in = cols[out];

	if ((out^1) < m_nNumOutputs && cols[out^1] != -1 && out/2 < s2.size()) {
		m_PM->setSwitchProgram(s2[out/2],(block==0)!=(out%2==0));
		Todo->remove(out/2);
	}

	if (block == 1) {
		p2[out/2] = in / 2;
		if(in / 2 < s1.size()) {
			m_PM->setSwitchProgram(s1[in/2], in % 2 == 0);
		}
	} else { // block==0
		p1[out / 2] = in / 2;
		if (in / 2 < s1.size()) {
			m_PM->setSwitchProgram(s1[in/2], in % 2 == 1);
		}
	}
	cols[out] = -1;
	rows[in] = -1;

	uint32_t newin = in^1;
	if (newin < m_nNumInputs && rows[newin]!=-1) {
		uint32_t newout = rows[newin];
		rows[newin] = -1;
		program_rec(newout,block^1,p1,p2,rows,cols);
	}

	if ((out^1) < m_nNumOutputs && cols[out^1] != -1 && out/2 < s2.size()) {
		program_rec(out^1,block^1,p1,p2,rows,cols);
	}
}

void Truncated_PN::WaksmanPermutation::program(uint32_t* perm) {
	if (m_nNumOutputs == 1){
		if(m_nNumInputs == 1) {return;}
		m_vYgatesProgram.resize(m_nNumInputs - 1);
		for(int i=0; i < m_nNumInputs-1; i++) {
				if(i + 1 == perm[0]) m_vYgatesProgram[i] = true;
				else m_vYgatesProgram[i] = false;
		}
		return;
	}

	uint32_t* cols = perm;

	uint32_t* rows = (uint32_t*) malloc(sizeof(uint32_t) * m_nNumInputs); //new uint32_t[u];
	for (uint32_t i = 0; i < m_nNumInputs; i++) rows[i] = -1;
	for (uint32_t i = 0; i < m_nNumOutputs; i++) {
		uint32_t x = perm[i];
		assert(x>=0 && x<m_nNumInputs && rows[x]==-1);
		rows[x] = i;
	}

	// programs for sub-blocks
	uint32_t* p1 = (uint32_t*) malloc(sizeof(uint32_t) * (m_nNumOutputs / 2)); //new uint32_t[v / 2];
	uint32_t* p2 = (uint32_t*) malloc(sizeof(uint32_t) * (m_nNumOutputs - (m_nNumOutputs / 2))); //new uint32_t[v - (v / 2)];

	Todo = new TodoList(s2.size());
	if (m_nNumInputs % 2 == 1) { // case c+d
			if(rows[m_nNumInputs-1]!=-1) program_rec(rows[m_nNumInputs-1], 1, p1, p2, rows, cols);
	}
	if (m_nNumOutputs % 2 == 1) { // case b+d
			if(cols[m_nNumOutputs-1]!=-1) program_rec(m_nNumOutputs-1, 1, p1, p2, rows, cols);
	}
	if (m_nNumInputs % 2 ==0 && m_nNumOutputs % 2 == 0) { // case a
			program_rec(m_nNumOutputs-1, 1, p1, p2, rows, cols);
			if(cols[m_nNumOutputs-2]!=-1) program_rec(m_nNumOutputs-2, 0, p1, p2, rows, cols);
	}

	for (uint32_t n = Todo->next(); n != -1; n = Todo->next()) {
		program_rec(2 * n, 0, p1, p2, rows, cols);
	}

	// program sub-blocks
	b1->program(p1);
	b2->program(p2);
}

Truncated_PN::WaksmanPermutation::WaksmanPermutation(uint32_t numinputs, uint32_t numoutputs, Truncated_PN* pm) {
	assert(numoutputs <= numinputs);
	m_nNumInputs = numinputs;
	m_nNumOutputs = numoutputs;
	m_PM = pm;

	if (numoutputs != 1) {
		// first row X
		s1.resize(m_nNumInputs / 2);

		for (uint32_t i = 0; i < m_nNumInputs / 2; i++)
			s1[i] = pm->nextGate();

		//assign wires to X gates and permute them

		// B1PermutationNetwork
		b1 = new WaksmanPermutation(numinputs / 2, numoutputs / 2, pm);

		// B2
		b2 = new WaksmanPermutation(numinputs - (numinputs / 2), numoutputs - (numoutputs / 2), pm);

		// last row X
		m_nSizeB2 = (numinputs % 2 == 0 && numoutputs % 2 ==0) ? numoutputs / 2 - 1 : numoutputs / 2;
		s2.resize(m_nSizeB2);
		for (uint32_t i = 0; i < m_nSizeB2; i++)
			s2[i] = pm->nextGate();

	}

}

vector<vector<uint32_t> > Truncated_PN::WaksmanPermutation::generateCircuit(vector<vector<uint32_t> > inputs, vector<vector<uint32_t> > outputs) {
	uint32_t rep = inputs[0].size();
	if (outputs == NON_INIT_DEF_OUTPUT) {
		outputs.resize(m_nNumOutputs);
		for (uint32_t i = 0; i < m_nNumOutputs; i++) {
			outputs[i].resize(rep);
		}
	}
	if (m_nNumOutputs == 1) {
		if(m_nNumInputs == 1) {
			for (uint32_t j = 0; j < rep; j++){
				outputs[0][j] = inputs[0][j];
				return outputs;
			}
		}
		vector<vector<uint32_t> > outtmp(1);
		outtmp[0] = m_PM->PutCondYGate(inputs[0], inputs[1],(m_PM->m_cBoolCirc->PutSIMDINGate(1,(uint32_t) m_vYgatesProgram[0],1,SERVER))->get_wire_id(0));
		for(uint32_t i = 1;i < m_nNumInputs - 1; i++) {
			outtmp[0] = m_PM->PutCondYGate(outtmp[0], inputs[i+1], (m_PM->m_cBoolCirc->PutSIMDINGate(1,(uint32_t) m_vYgatesProgram[i],1,SERVER))->get_wire_id(0));
		}
		outputs[0] = outtmp [0];
		return outputs;
	}

	uint32_t sizeB2 = m_nNumInputs - (m_nNumInputs / 2);
	vector<vector<uint32_t> > in_p1(m_nNumInputs / 2);
	vector<vector<uint32_t> > in_p2(sizeB2);

	// first row X
	vector<vector<uint32_t> > outtmp(2);
	for (uint32_t i = 0; i < s1.size(); i++) {
		in_p1[i].resize(rep);
		in_p2[i].resize(rep);
		//in_p1[i] = inputs[2 * i + m_PM->m_vSwitchGateProgram[s1[i]]];
		//in_p2[i] = inputs[2 * i + !(m_PM->m_vSwitchGateProgram[s1[i]])];
		outtmp = m_PM->PutCondSwapGate(inputs[2 * i], inputs[2 * i + 1], m_PM->m_vSwapGates[s1[i]]);
		for (uint32_t j = 0; j < rep; j++) {
			in_p1[i][j] = outtmp[0][j];
			in_p2[i][j] = outtmp[1][j];
		}

	}

	if (m_nNumInputs % 2 == 1) {
		in_p2[sizeB2 - 1].resize(rep);
		for (uint32_t i = 0; i < rep; i++)
			in_p2[sizeB2 - 1][i] = inputs[m_nNumInputs - 1][i];
	}

	vector<vector<uint32_t> > out_p1 = b1->generateCircuit(in_p1, NON_INIT_DEF_OUTPUT);
	vector<vector<uint32_t> > out_p2 = b2->generateCircuit(in_p2, NON_INIT_DEF_OUTPUT);

	// last row X
	for (uint32_t i = 0; i < s2.size(); i++) {

		outtmp = m_PM->PutCondSwapGate(out_p1[i], out_p2[i], m_PM->m_vSwapGates[s2[i]]);
		for (uint32_t j = 0; j < rep; j++) {
			outputs[2 * i][j] = outtmp[0][j];
			outputs[2 * i + 1][j] = outtmp[1][j];
		}


	}

	if(m_nNumOutputs % 2 == 1) {
		for (uint32_t i = 0; i < rep; i++){
			outputs[m_nNumOutputs - 1][i] = out_p2[out_p2.size()-1][i];
		}
	} else if (m_nNumInputs % 2 == 0){
		for (uint32_t i = 0; i < rep; i++){

			outputs[m_nNumOutputs - 1][i] = out_p2[out_p2.size()-1][i];
			outputs[m_nNumOutputs - 2][i] = out_p1[out_p1.size()-1][i];
		}
	}

	return outputs;
}

void t_SelectionBlock::SelectionBlockProgram(uint32_t *p){
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
	prog1 = (uint32_t*) malloc(sizeof(uint32_t) * m_nNumOutputs);

	vector<uint32_t> upos, dummy;
	upos.resize(m_nNumInputs);
	dummy.resize(m_nNumInputs); // list of dummy outputs

	for(uint32_t i=0; i<m_nNumInputs; i++) {
		if(c[i]>0) {
			prog1[sum] = i;
			upos[i] = sum;
			if(sum>0) {
				setYProgram(sum-1, true);
				//m_vYgatesProgram[sum-1] = true;
			}
			for(uint32_t j = sum + 1; j < sum+c[i]; j++) {
				setYProgram(j-1, false);
				//m_vYgatesProgram[j-1] = false;
				prog1[j] = -1;
			}
			sum+=c[i];
		}
		else{
			dummy[ndummys++] = i;
		}
	}

	// program dummys
	uint32_t nextdummy=0;
	for(uint32_t i=0; i < m_nNumOutputs; i++) {
		if(prog1[i]==-1) {
			prog1[i]=dummy[nextdummy++];
		}
	}
	m_Pblock1->ProgramPermutationNetwork(prog1);

	// program b2
  uint32_t* prog2 = (uint32_t*) malloc(sizeof(uint32_t) * m_nNumOutputs);
  for(uint32_t i=0; i < m_nNumOutputs; i++) {
    prog2[i]=upos[p[i]]++;
  }
	m_Pblock2->ProgramPermutationNetwork(prog2);
}

vector<vector<uint32_t> > t_SelectionBlock::buildSelectionBlockCircuit(vector<vector<uint32_t> >& inputs){
	uint32_t rep = inputs[0].size();
	vector<vector<uint32_t> > out_p1,out_g, outputs;

	out_p1 = m_Pblock1->buildPermutationCircuit(inputs);
	out_g.resize(m_nNumOutputs);
	out_g[0]=out_p1[0];
	for(uint32_t i=1; i<m_nNumOutputs; i++) {
		out_g[i] = PutCondYGate(out_g[i-1], out_p1[i], m_vYGates[i-1]);
	}
	return m_Pblock2->buildPermutationCircuit(out_g);
}
