#include "qosmapping.hpp"

ASN_NGAP_FiveQI_t qosmapping::mapto5QI(int pcp){

    ASN_NGAP_FiveQI_t fiveqi;
    switch (pcp) {
        case 2: return fiveqi=(long)70;
        case 0: return fiveqi=(long)9;
        case 4: return fiveqi=(long)4;
        case 6: return fiveqi=(long)82;
        case 8: return fiveqi=(long)84;
        case 10: return fiveqi=(long)86;
        case 12: return fiveqi=(long)83;
        case 14: return fiveqi=(long)85;
    }
    return 2;
}

/*int qosmapping::readPCP(const OctetString &stream){

    
}*/
