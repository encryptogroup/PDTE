/**
 \file 		auxiliary-functions.cpp
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
 \brief		Auxiliary functions
 */

#include <iomanip>
#include<iostream>
#include "auxiliary-functions.h"

void print(uint8_t* s, int size){
	for(int i = 0; i < size; i++)
		std::cout<< std::hex << std::setw(2) << std::setfill('0') << int(s[i]);
	std::cout << std::endl;
}

uint8_t* Xor(uint8_t* a, uint8_t* b, int size){
	for(int i = 0; i < size; i++)
		a[i] ^= b[i];
	return a;
}

double time_diff(struct timeval x , struct timeval y){
    double x_ms , y_ms , diff;

    x_ms = (double)x.tv_sec*1000 + (double)(x.tv_usec / 1000);
    y_ms = (double)y.tv_sec*1000 + (double)(y.tv_usec / 1000);

    diff = (double)y_ms - (double)x_ms;

    return diff;
}

double time_diff_microsec(struct timeval x , struct timeval y){
    double x_ms , y_ms , diff;
     
    x_ms = (double)x.tv_sec*1000000 + (double)(x.tv_usec);
    y_ms = (double)y.tv_sec*1000000 + (double)(y.tv_usec);

    diff = (double)y_ms - (double)x_ms;
     
    return diff;
}
