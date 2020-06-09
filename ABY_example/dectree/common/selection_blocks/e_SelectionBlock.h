/**
 \file 		e_SelectionBlock.h
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
#ifndef __ABY_E_SELECTIONBLOCK_H_
#define __ABY_E_SELECTIONBLOCK_H_

#include <vector>
#include <iostream>
#include "stdio.h"
#include <stdlib.h>
#include "../../../../abycore/circuit/booleancircuits.h"
#include "selection_block.h"
#include "permutation_network.h"

using namespace std;

//TODO: Generate destructor methods

class e_SelectionBlock : public SelectionBlock {
//private:
public: // TODO: Fix this!
	PermutationNetwork *m_Pblock1,*m_Pblock2;
	uint32_t m_nNumInputs, m_nNumOutputs;
	vector<bool> m_vYgatesProgram;
	vector<uint32_t> m_vYGates;
	BooleanCircuit* m_cBoolCirc;
//public:
	e_SelectionBlock (uint32_t numInputs, uint32_t numOutputs, BooleanCircuit* circ){
		m_nNumInputs = numInputs;
		m_nNumOutputs = numOutputs;
		m_vYgatesProgram.resize(m_nNumOutputs-1);
		m_vYGates.resize(m_nNumOutputs-1);
		m_Pblock1 = new PermutationNetwork(numInputs, numOutputs, circ); // Extended PermutationNetwork(u,v) [v>u]
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
		return {m_cBoolCirc->PutCombinerGate(m_cBoolCirc->PutMUXGate(m_cBoolCirc->PutSplitterGate(b[0]), m_cBoolCirc->PutSplitterGate(a[0]), s, true))};
		//return m_cBoolCirc->PutCondYGate(a, b, s, true);
		//return m_cBoolCirc->PutMUXGate(b, a, s, true);
	}

};

#endif /* __ABY_E_SELECTIONBLOCK_H_ */
