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

#ifndef __SNDRCV_H__
#define __SNDRCV_H__

#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/socket.h>
#include <ENCRYPTO_utils/connection.h>
#include <ENCRYPTO_utils/rcvthread.h>
#include <ENCRYPTO_utils/sndthread.h>
#include <ENCRYPTO_utils/channel.h>
#include "auxiliary-functions.h"
#include "../../../abycore/ABY_utils/ABYconstants.h"
#include <iostream>
#include <sys/time.h>
#include <unistd.h>

#define PROGRAM_MAIN_CHANNEL 0x01

class NetConnection {
public:
    BOOL EstConnection(e_role role);
    BOOL PartyConnect();
    BOOL PartyListen();
    NetConnection(const std::string addr, uint16_t port);

    channel* commChannel;

private:
    std::string ipaddress;
    uint16_t port;
    std::unique_ptr<CSocket> m_pSocket;
    std::unique_ptr<SndThread> snd_thread;
    std::unique_ptr<RcvThread> rcv_thread;
    std::unique_ptr<CLock> commlock;
};


BOOL sendGarbledDT(channel* chan, const int16_t &numNodes, const int16_t &nodeSize, uint8_t* serialized_garbledDT );
BOOL receiveGarbledDT(channel* chan, const int16_t &numNodes, const int16_t &nodeSize, uint8_t* rcvBuff);

#endif
