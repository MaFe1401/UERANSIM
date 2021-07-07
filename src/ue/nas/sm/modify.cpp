//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include "sm.hpp"

namespace nr::ue
{
void NasSm::receiveModifyCommand(const nas::PduSessionModificationCommand &msg)
{
    m_logger->debug("PDU Session Modify Command received");

    int psi = msg.pduSessionId;
    int pti = msg.pti;
    auto &pt = m_procedureTransactions[pti];
    auto &ps = m_pduSessions[psi];

    if(!ps->isEmergency) {
        m_timers->t3396.stop();
        m_timers->t3585.stop();
    }
    if(!ps->apn.has_value() && !ps->sNssai.has_value()) {
        m_timers->t3584.stop();
    }
    if(msg.authorizedQoSRules.has_value()) {
        for(auto &qosRule : msg.authorizedQoSRules.value().data) {
            m_logger->debug("process qos");
        }
    }

}
}
