//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include "task.hpp"
#include <iterator>
#include <gnb/gtp/proto.hpp>
#include <gnb/rls/task.hpp>
#include <utils/constants.hpp>
#include <utils/libc_error.hpp>

#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h>
#include <asn/ngap/ASN_NGAP_QosFlowAddOrModifyRequestItem.h>

namespace nr::gnb
{

GtpTask::GtpTask(TaskBase *base)
    : m_base{base}, m_udpServer{}, m_ueContexts{},
      m_rateLimiter(std::make_unique<RateLimiter>()), m_pduSessions{}, m_sessionTree{}
{
    m_logger = m_base->logBase->makeUniqueLogger("gtp");
}

void GtpTask::onStart()
{
    try
    {
        m_udpServer = new udp::UdpServerTask(m_base->config->gtpIp, cons::GtpPort, this);
        m_udpServer->start();
    }
    catch (const LibError &e)
    {
        m_logger->err("GTP/UDP task could not be created. %s", e.what());
    }
}

void GtpTask::onQuit()
{
    m_udpServer->quit();
    delete m_udpServer;

    m_ueContexts.clear();
}

void GtpTask::onLoop()
{
    NtsMessage *msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
    case NtsMessageType::GNB_NGAP_TO_GTP: {
        auto *w = dynamic_cast<NmGnbNgapToGtp *>(msg);
        switch (w->present)
        {
        case NmGnbNgapToGtp::UE_CONTEXT_UPDATE: {
            handleUeContextUpdate(*w->update);
            break;
        }
        case NmGnbNgapToGtp::UE_CONTEXT_RELEASE: {
            handleUeContextDelete(w->ueId);
            break;
        }
        case NmGnbNgapToGtp::SESSION_CREATE: {
            handleSessionCreate(w->resource);
            break;
        }
        case NmGnbNgapToGtp::SESSION_MODIFY: {
            handleSessionModify(w->sessionModify);
            break;
        }
        case NmGnbNgapToGtp::SESSION_RELEASE: {
            handleSessionRelease(w->ueId, w->psi);
            break;
        }
        }
        break;
    }
    case NtsMessageType::GNB_RLS_TO_GTP: {
        auto *w = dynamic_cast<NmGnbRlsToGtp *>(msg);
        switch (w->present)
        {
        case NmGnbRlsToGtp::DATA_PDU_DELIVERY: {
            handleUplinkData(w->ueId, w->psi, std::move(w->pdu));
            break;
        }
        }
        break;
    }
    case NtsMessageType::UDP_SERVER_RECEIVE:
        handleUdpReceive(*dynamic_cast<udp::NwUdpServerReceive *>(msg));
        break;
    default:
        m_logger->unhandledNts(msg);
        break;
    }

    delete msg;
}

void GtpTask::handleUeContextUpdate(const GtpUeContextUpdate &msg)
{
    if (!m_ueContexts.count(msg.ueId))
        m_ueContexts[msg.ueId] = std::make_unique<GtpUeContext>(msg.ueId);

    auto &ue = m_ueContexts[msg.ueId];
    ue->ueAmbr = msg.ueAmbr;

    updateAmbrForUe(ue->ueId);
}

void GtpTask::handleSessionCreate(PduSessionResource *session)
{
    if (!m_ueContexts.count(session->ueId))
    {
        m_logger->err("PDU session resource could not be created, UE context with ID[%d] not found", session->ueId);
        return;
    }

    uint64_t sessionInd = MakeSessionResInd(session->ueId, session->psi);
    m_pduSessions[sessionInd] = std::unique_ptr<PduSessionResource>(session);

    m_sessionTree.insert(sessionInd, session->downTunnel.teid);

    updateAmbrForUe(session->ueId);
    updateAmbrForSession(sessionInd);
}

void GtpTask::handleSessionModify(PduSessionResourceModify *pResource)
{
    if (!m_ueContexts.count(pResource->ueId))
    {
        m_logger->err("PDU session resource could not be created, UE context with ID[%d] not found", pResource->ueId);
        return;
    }
    uint64_t sessionInd = MakeSessionResInd(pResource->ueId, pResource->psi);
    auto &pduSession = m_pduSessions[sessionInd];
    auto toModifyOrAddFlows = pResource->qosFlowsToBeAddedOrModified->list;
    for (int i = 0; i < toModifyOrAddFlows.count; i++) {
        auto toModifyOrAddFlow = toModifyOrAddFlows.array[i];
        auto *flow = asn::New<ASN_NGAP_QosFlowSetupRequestItem>();
        flow->qosFlowIdentifier = toModifyOrAddFlow->qosFlowIdentifier;
        flow->qosFlowLevelQosParameters = *(toModifyOrAddFlow->qosFlowLevelQosParameters);
        flow->e_RAB_ID = toModifyOrAddFlow->e_RAB_ID;
        flow->iE_Extensions = toModifyOrAddFlow->iE_Extensions;
        bool flowModified = false;
        asn::ForeachItem(*pduSession->qosFlows, [flow, &flowModified](ASN_NGAP_QosFlowSetupRequestItem &item){
            if(item.qosFlowIdentifier == flow->qosFlowIdentifier) {
                //TODO: modify flow
                flowModified = true;
            }
        });
        if(!flowModified) {
            asn::SequenceAdd(*pduSession->qosFlows, flow);
        }
    }
}

void GtpTask::handleSessionRelease(int ueId, int psi)
{
    if (!m_ueContexts.count(ueId))
    {
        m_logger->err("PDU session resource could not be released, UE context with ID[%d] not found", ueId);
        return;
    }

    uint64_t sessionInd = MakeSessionResInd(ueId, psi);

    // Remove all session information from rate limiter
    m_rateLimiter->updateSessionUplinkLimit(sessionInd, 0);
    m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

    // And remove from PDU session table
    if (m_pduSessions.count(sessionInd))
    {
        uint32_t teid = m_pduSessions[sessionInd]->downTunnel.teid;
        m_pduSessions.erase(sessionInd);

        // And remove from the tree
        m_sessionTree.remove(sessionInd, teid);
    }
}

void GtpTask::handleUeContextDelete(int ueId)
{
    // Find PDU sessions of the UE
    std::vector<uint64_t> sessions{};
    m_sessionTree.enumerateByUe(ueId, sessions);

    for (auto &session : sessions)
    {
        // Remove all session information from rate limiter
        m_rateLimiter->updateSessionUplinkLimit(session, 0);
        m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

        // And remove from PDU session table
        uint32_t teid = m_pduSessions[session]->downTunnel.teid;
        m_pduSessions.erase(session);

        // And remove from the tree
        m_sessionTree.remove(session, teid);
    }

    // Remove all user information from rate limiter
    m_rateLimiter->updateUeUplinkLimit(ueId, 0);
    m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

    // Remove UE context
    m_ueContexts.erase(ueId);
}

ASN_NGAP_FiveQI_t GtpTask::mapto5QI(int dscp){

    ASN_NGAP_FiveQI_t fiveqi;
    switch (dscp) {
        case 32: return fiveqi=(long)6;//PCP = 1 Background
        case 0: return fiveqi=(long)6;//PCP = 0 Best effort
        case 64: return fiveqi=(long)67;//PCP = 2 Excellent effort
        case 96: return fiveqi=(long)67;//PCP = 3 Critical applications
        case 128: return fiveqi=(long)85;//PCP = 4 Video
        case 160: return fiveqi=(long)85;//PCP = 5 Voice
        case 192: return fiveqi=(long)86;//PCP = 6 Internetwork control
        case 224: return fiveqi=(long)86;//PCP = 7 Network control
        case 252: return fiveqi=(long)86;//PTP
    }
    return 6;
}

/*int GtpTask::searchQoSFlow(int fiveqi, int ueId, int psi){
    
    uint64_t sessionInd = MakeSessionResInd(ueId, psi);
    int i = 0;
    auto &pduSession = m_pduSessions[sessionInd];
   for (i=0;i<4;i++){
    if (pduSession->qosFlows->list.array[i]->qosFlowLevelQosParameters.qosCharacteristics.choice.nonDynamic5QI == fiveqi){
        m_logger->info("QoS flow ID is [%d]", pduSession->qosFlows->list.array[i]->qosFlowIdentifier);
        return pduSession->qosFlows->list.array[i]->qosFlowIdentifier;
    }
   }
    return 0;
}*/
void GtpTask::handleUplinkData(int ueId, int psi, OctetString &&pdu)
{
    const uint8_t *data = pdu.data();

    // ignore non IPv4 packets
    if ((data[0] >> 4 & 0xF) != 4)
        return;

    uint64_t sessionInd = MakeSessionResInd(ueId, psi);

    if (!m_pduSessions.count(sessionInd))
    {
        m_logger->err("Uplink data failure, PDU session not found. UE[%d] PSI[%d]", ueId, psi);
        return;
    }

    auto &pduSession = m_pduSessions[sessionInd];

    if (m_rateLimiter->allowUplinkPacket(sessionInd, static_cast<int64_t>(pdu.length())))
    {
        gtp::GtpMessage gtp{};
        gtp.payload = std::move(pdu);
        gtp.msgType = gtp::GtpMessage::MT_G_PDU;
        gtp.teid = pduSession->upTunnel.teid;
        m_logger->info("DSCP is %d", data[1]  & 0xFF);
        int dscp = data[1]  & 0xFF;

        ASN_NGAP_FiveQI_t fiveqi = mapto5QI(dscp);
        m_logger->info("5QI is %d", fiveqi);
       // int qosFlowid = searchQoSFlow(fiveqi, ueId, psi);
        auto ul = std::make_unique<gtp::UlPduSessionInformation>();
        // PCP --> QoS flow 
        if (fiveqi==6){// PCP = 1 and PCP = 0
             ul->qfi = static_cast<int>(pduSession->qosFlows->list.array[0]->qosFlowIdentifier);
        }
        else if (fiveqi==67){// PCP = 2 and PCP = 3
             ul->qfi = static_cast<int>(pduSession->qosFlows->list.array[1]->qosFlowIdentifier);

        }
        else if (fiveqi==85){// PCP = 4 and PCP = 5 
             ul->qfi = static_cast<int>(pduSession->qosFlows->list.array[2]->qosFlowIdentifier);

        }
        else if (fiveqi==86){// PCP = 6 and PCP = 7
             ul->qfi = static_cast<int>(pduSession->qosFlows->list.array[3]->qosFlowIdentifier);

        }
        auto cont = new gtp::PduSessionContainerExtHeader();
        cont->pduSessionInformation = std::move(ul);
        gtp.extHeaders.push_back(std::unique_ptr<gtp::GtpExtHeader>(cont));

        OctetString gtpPdu;
        if (!gtp::EncodeGtpMessage(gtp, gtpPdu))
            m_logger->err("Uplink data failure, GTP encoding failed");
        else
            m_udpServer->send(InetAddress(pduSession->upTunnel.address, cons::GtpPort), gtpPdu);
    }
}

void GtpTask::handleUdpReceive(const udp::NwUdpServerReceive &msg)
{
    OctetView buffer{msg.packet};
    auto *gtp = gtp::DecodeGtpMessage(buffer);

    auto sessionInd = m_sessionTree.findByDownTeid(gtp->teid);
    if (sessionInd == 0)
    {
        m_logger->err("TEID %d not found on GTP-U Downlink", gtp->teid);
        delete gtp;
        return;
    }

    if (gtp->msgType != gtp::GtpMessage::MT_G_PDU)
    {
        m_logger->err("Unhandled GTP-U message type: %d", gtp->msgType);
        delete gtp;
        return;
    }

    if (m_rateLimiter->allowDownlinkPacket(sessionInd, gtp->payload.length()))
    {
        auto *w = new NmGnbGtpToRls(NmGnbGtpToRls::DATA_PDU_DELIVERY);
        w->ueId = GetUeId(sessionInd);
        w->psi = GetPsi(sessionInd);
        w->pdu = std::move(gtp->payload);
        m_base->rlsTask->push(w);
    }

    delete gtp;
}

void GtpTask::updateAmbrForUe(int ueId)
{
    if (!m_ueContexts.count(ueId))
        return;

    auto &ue = m_ueContexts[ueId];
    m_rateLimiter->updateUeUplinkLimit(ueId, ue->ueAmbr.ulAmbr);
    m_rateLimiter->updateUeDownlinkLimit(ueId, ue->ueAmbr.dlAmbr);
}

void GtpTask::updateAmbrForSession(uint64_t pduSession)
{
    if (!m_pduSessions.count(pduSession))
        return;

    auto &sess = m_pduSessions[pduSession];
    m_rateLimiter->updateSessionUplinkLimit(pduSession, sess->sessionAmbr.ulAmbr);
    m_rateLimiter->updateSessionDownlinkLimit(pduSession, sess->sessionAmbr.dlAmbr);
}

} // namespace nr::gnb
