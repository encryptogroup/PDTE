/**
 \file 		SelectionBlock.h
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
 \brief		Implementation of WaksmanPermutation and SelectionBlock
 */

#ifndef __ABY_SELECTIONBLOCK_H_
#define __ABY_SELECTIONBLOCK_H_

#include <vector>
#include <iostream>
#include "stdio.h"
#include <stdlib.h>
#include "../../../../abycore/circuit/booleancircuits.h"

class SelectionBlock {
public:
  virtual void SelectionBlockProgram(uint32_t *p) = 0;
  virtual void SetControlBits() = 0;
  virtual std::vector<std::vector<uint32_t> > buildSelectionBlockCircuit(std::vector<std::vector<uint32_t> >& input) = 0;
};

#endif /* __ABY_SELECTIONBLOCK_H_ */
