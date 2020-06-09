/**
 \file 		t_SelectionBlock.h
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
#ifndef __ABY_T_SELECTIONBLOCK_H_
#define __ABY_T_SELECTIONBLOCK_H_

#include <vector>
#include <iostream>
#include "stdio.h"
#include <stdlib.h>
#include "../../../../abycore/circuit/booleancircuits.h"
#include "selection_block.h"
#include "permutation_network.h"

using namespace std;

//TODO: Generate destructor methods

class Truncated_PN{
	//double linked list; node n is head
	class TodoList {
		uint32_t* nextu;
		uint32_t* prevu;
		uint32_t n;

	public:
		void remove(uint32_t x) {
			nextu[prevu[x]] = nextu[x];
			prevu[nextu[x]] = prevu[x];
		}

		uint32_t next() {
			uint32_t ret = nextu[n];
			if (ret == n)
				return -1;
			else
				return ret;
		}

		TodoList(uint32_t num) {
			n = num;
			nextu = (uint32_t*) malloc(sizeof(uint32_t) * (n + 1)); //new uint32_t[n+1];
			prevu = (uint32_t*) malloc(sizeof(uint32_t) * (n + 1)); //new uint32_t[n+1];
			for (uint32_t i = 0; i < n + 1; i++) {
				nextu[i] = (i + 1) % (n + 1);
				prevu[i] = (i + n) % (n + 1);
			}
		}
	};

	class WaksmanPermutation {
	public:
		WaksmanPermutation* b1;
		WaksmanPermutation* b2;

		uint32_t m_nNumInputs;
		uint32_t m_nNumOutputs;
		uint32_t m_nSizeB2;

		WaksmanPermutation(uint32_t numgates, uint32_t numoutputs, Truncated_PN* pm);
		virtual ~WaksmanPermutation();
		//Program the permutation
		void program(uint32_t* perm);
		void program_rec(uint32_t out, uint32_t block, uint32_t* p1, uint32_t* p2, uint32_t* rows, uint32_t* cols);
		vector<vector<uint32_t> > generateCircuit(vector<vector<uint32_t> > inputs, vector<vector<uint32_t> > outputs);

		vector<uint32_t> s1, s2;
		vector<uint32_t> m_vYGates;
		vector<bool> m_vYgatesProgram;
		TodoList* Todo;
		Truncated_PN* m_PM;
	};

public:
	Truncated_PN(uint32_t numInputs, uint32_t numOutputs,  BooleanCircuit* circ) {
		m_nNumIn = numInputs;
		m_nNumOut = numOutputs;
		gatebuildcounter = 0;
		m_cBoolCirc = circ;
		m_vSwitchGateProgram.resize(numInputs-1);
		m_vSwitchGateProgram.resize(estimateGates(numInputs, numOutputs));
		wm = new WaksmanPermutation(numInputs, numOutputs, this);
	}

	uint32_t nextGate() {
		return gatebuildcounter++;
	}
	uint32_t getSwapGateAt(uint32_t idx) {
		return m_vSwapGates[idx];
	}
	void setSwitchProgram(uint32_t idx, bool val) {
		m_vSwitchGateProgram[idx] = val;
	}

	/*void setPermutationGates(vector<uint32_t>& gates) {
		m_vSwapGates = gates;
	}*/
	void setPermutationGates() {
		uint32_t val;
		m_vSwapGates.resize(m_vSwitchGateProgram.size());
		for (uint32_t i = 0; i < m_vSwitchGateProgram.size(); i++) {
			val = (uint32_t) m_vSwitchGateProgram[i];
			m_vSwapGates[i] = (m_cBoolCirc->PutSIMDINGate(1,val,1,SERVER))->get_wire_id(0);
		}
	}
	vector<vector<uint32_t> > buildPermutationCircuit(vector<vector<uint32_t> >& input) {
		return wm->generateCircuit(input, NON_INIT_DEF_OUTPUT);
	}
	vector<vector<uint32_t> > PutCondSwapGate(vector<uint32_t>& a, vector<uint32_t>& b, uint32_t s) {
		return m_cBoolCirc->PutCondSwapGate(a, b, s, true);
	}
	vector<uint32_t> PutCondYGate(vector<uint32_t>& a, vector<uint32_t>& b, uint32_t s) {
		//return m_cBoolCirc->PutCondYGate(a, b, s, true);
		return m_cBoolCirc->PutMUXGate(b, a, s);
	}
	vector<bool> ProgramPermutationNetwork(uint32_t* permutation) {
		wm->program(permutation);
		return m_vSwitchGateProgram;
	}
private:
	uint32_t gatebuildcounter;
	uint32_t m_nNumIn;
	uint32_t m_nNumOut;
	vector<bool> m_vSwitchGateProgram;
	vector<uint32_t> m_vSwapGates; //gate addresses of the swapgates
	WaksmanPermutation* wm;
	BooleanCircuit* m_cBoolCirc;

};

class t_SelectionBlock : public SelectionBlock {
//private:
public:
	Truncated_PN *m_Pblock1;
	PermutationNetwork *m_Pblock2;
	uint32_t m_nNumInputs, m_nNumOutputs;
	vector<bool> m_vYgatesProgram;
	vector<uint32_t> m_vYGates;
	BooleanCircuit* m_cBoolCirc;
//public:
	t_SelectionBlock (uint32_t numInputs, uint32_t numOutputs, BooleanCircuit* circ){
		m_nNumInputs = numInputs;
		m_nNumOutputs = numOutputs;
		m_vYgatesProgram.resize(m_nNumOutputs-1);
		m_vYGates.resize(m_nNumOutputs-1);
		m_Pblock1 = new Truncated_PN(numInputs, numOutputs, circ); // Truncated PermutationNetwork(u,v) [v>u]
		m_Pblock2 = new PermutationNetwork(numOutputs, numOutputs, circ);// PermutationNetwork(v,v)
		m_cBoolCirc = circ;
	}

	void SelectionBlockProgram(uint32_t *p);
	uint32_t getYGateAt(uint32_t idx) {
		return m_vYGates[idx];
	}
	void setYProgram(uint32_t idx, bool val) {
		m_vYgatesProgram[idx] = val;
	}
	void setYGates() {
		uint32_t val;
		for (uint32_t i = 0; i < m_nNumOutputs-1 ; i++){
			val = (uint32_t) m_vYgatesProgram[i];
			m_vYGates[i] = (m_cBoolCirc->PutSIMDINGate(1,val,1,SERVER))->get_wire_id(0);
		}
	}
	void SetControlBits(){
		m_Pblock1->setPermutationGates();
		setYGates();
		m_Pblock2->setPermutationGates();
	}
	vector<vector<uint32_t> > buildSelectionBlockCircuit(vector<vector<uint32_t> >& input);
	vector<uint32_t> PutCondYGate(vector<uint32_t>& a, vector<uint32_t>& b, uint32_t s) {
		//return m_cBoolCirc->PutCondYGate(a, b, s, true);
		return {m_cBoolCirc->PutCombinerGate(m_cBoolCirc->PutMUXGate(m_cBoolCirc->PutSplitterGate(b[0]), m_cBoolCirc->PutSplitterGate(a[0]), s, true))};
	}

};
#endif /* __ABY_T_SELECTIONBLOCK_H_ */
