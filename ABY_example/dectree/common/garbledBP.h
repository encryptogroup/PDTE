/**
 \file 		garbledBP.h
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
 \brief		Garbled node
 */

#ifndef __Garbled_BP_H_
#define __Garbled_BP_H_

struct garbldNode{
	uint8_t *rnode, *lnode;
};

#endif /* __Garbled_BP_H_ */
