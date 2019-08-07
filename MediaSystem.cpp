/*
 * Copyright 2017-2018 Metrological
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cdmi.h"
#include "MediaSession.h"

namespace CDMi {

class PlayReady : public IMediaKeys {
private:
    PlayReady (const PlayReady&) = delete;
    PlayReady& operator= (const PlayReady&) = delete;

public:
    PlayReady() {

        NxClient_JoinSettings joinSettings;
        NEXUS_Error rc;
        NEXUS_ClientConfiguration platformConfig;
        OEM_Settings         oemSettings;
        NEXUS_MemoryAllocationSettings heapSettings;
        DRM_RESULT dr = DRM_SUCCESS;

        NxClient_GetDefaultJoinSettings(&joinSettings);
        snprintf(joinSettings.name, NXCLIENT_MAX_NAME, "playready3x");
        rc = NxClient_Join(&joinSettings);
        if (rc) {
            printf("Couldnt join nxserver\n");
            goto ErrorExit;
        }

        /* Drm_Platform_Initialize */
        NEXUS_Memory_GetDefaultAllocationSettings(&heapSettings);
        NEXUS_Platform_GetClientConfiguration(&platformConfig);
        if (platformConfig.heap[NXCLIENT_FULL_HEAP])
        {
            NEXUS_HeapHandle heap = platformConfig.heap[NXCLIENT_FULL_HEAP];
            NEXUS_MemoryStatus heapStatus;
            NEXUS_Heap_GetStatus(heap, &heapStatus);
            if (heapStatus.memoryType & NEXUS_MemoryType_eFull)
            {
                heapSettings.heap = heap;
            }
        }

        BKNI_Memset(&oemSettings, 0, sizeof(OEM_Settings));
        oemSettings.heap = heapSettings.heap;

        dr = Drm_Platform_Initialize((void *)&oemSettings);
        ChkDR(dr);

        m_drmOemContext = oemSettings.f_pOEMContext;
        ChkMem(m_drmOemContext);

ErrorExit:
        if (DRM_FAILED(dr))
        {
            printf("Playready Initialize failed\n");
        }
    }

    ~PlayReady(void) {

        Drm_Platform_Uninitialize(m_drmOemContext);
    }

    CDMi_RESULT CreateMediaKeySession(
        const std::string& /* keySystem */,
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData, 
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData, 
        IMediaKeySession **f_ppiMediaKeySession) {

        *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData, f_pbCDMData, f_cbCDMData, m_drmOemContext);

        return CDMi_SUCCESS; 
    }

    CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        return CDMi_S_FALSE;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession *f_piMediaKeySession) {

        delete f_piMediaKeySession;

        return CDMi_SUCCESS;
    }

private:
    DRM_VOID *m_drmOemContext;
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
