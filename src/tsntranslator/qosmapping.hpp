#include <cstdint>
#include <memory>
#include <optional>
#include <vector>
#include <asn/ngap/ASN_NGAP_FiveQI.h>
#include <utils/octet_string.hpp>
#include <utils/octet_view.hpp>

class qosmapping 
{
    public:
        int readPCP(const OctetString &stream);
        ASN_NGAP_FiveQI_t mapto5QI(int pcp);
};
