/**
 \file 		sndrcv.h
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
 \brief		Send and receive garbled DT
 */

#include "sndrcv.h"

BOOL NetConnection::EstConnection(e_role role)
{
	BOOL success = true;
	if (role == SERVER) {
		m_pSocket = Listen(ipaddress, port);
		if (!m_pSocket)
			success = false;
	} else { //CLIENT
		m_pSocket = Connect(ipaddress, port);
		if (!m_pSocket)
			success = false;
	}
	if (!success) {
		std::cout << "connection failed!" << std::endl;
		return false;
	}
	
	commlock = std::make_unique<CLock>();
	snd_thread = std::make_unique<SndThread>(m_pSocket.get(), commlock.get());
	rcv_thread = std::make_unique<RcvThread>(m_pSocket.get(), commlock.get());
	snd_thread->Start();
	rcv_thread->Start();

	commChannel  = new channel(PROGRAM_MAIN_CHANNEL, rcv_thread.get(), snd_thread.get());

	return success;
}

NetConnection::NetConnection(const std::string addr, uint16_t port) {
	NetConnection::port = port;
	NetConnection::ipaddress = addr;
}

BOOL sendGarbledDT(channel* chan, const int16_t &numNodes, const int16_t &nodeSize, uint8_t* serialized_garbledDT ) {
	chan->send(serialized_garbledDT, numNodes * nodeSize * 2);
	return TRUE;
}

BOOL receiveGarbledDT(channel* chan, const int16_t &numNodes, const int16_t &nodeSize, uint8_t* rcvBuff) {

	timeval tbegin, tend;
	
	gettimeofday(&tbegin, NULL);
	chan->blocking_receive(rcvBuff, numNodes * nodeSize * 2);
	gettimeofday(&tend, NULL);
	std::cout << " Garbled tree transfer time: " << time_diff_microsec(tbegin, tend) << "us" << std::endl;
	return TRUE;
}
