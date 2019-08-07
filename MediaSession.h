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

#pragma once

#include "cdmi.h"
#include <core/core.h>

#include <refsw/nexus_config.h>
#include <refsw/nxclient.h>
#include <refsw/nexus_platform.h>
#include <refsw/nexus_memory.h>
#include <refsw/bstd.h>           /* brcm includes */
#include <refsw/bkni.h>

#include <refsw/oemcommon.h>
#include <refsw/drmmanager.h>
#include <refsw/drmmathsafe.h>
#include <refsw/drmtypes.h>
#include <refsw/drmerr.h>

namespace CDMi {

class MediaKeySession : public IMediaKeySession {
private:
    enum KeyState {
        // Has been initialized.
        KEY_INIT = 0,
        // Has a key message pending to be processed.
        KEY_PENDING = 1,
        // Has a usable key.
        KEY_READY = 2,
        // Has an error.
        KEY_ERROR = 3,
        // Has been closed.
        KEY_CLOSED = 4
    };
    enum MessageType {
        LicenseRequest = 0,
        LicenseRenewal = 1,
        LicenseRelease = 2,
        IndividualizationRequest = 3
    };
public:
    //static const std::vector<std::string> m_mimeTypes;

    MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData, const uint8_t *f_pbCDMData, uint32_t f_cbCDMData, DRM_VOID *f_pOEMContext);
    ~MediaKeySession();
    bool playreadyGenerateKeyRequest();
    bool ready() const { return m_eKeyState == KEY_READY; }

// MediaKeySession overrides
    virtual void Run(
        const IMediaKeySessionCallback *f_piMediaKeySessionCallback) override;

    virtual CDMi_RESULT Load() override;

    virtual void Update(
        const uint8_t *f_pbKeyMessageResponse,
        uint32_t f_cbKeyMessageResponse) override;

    virtual CDMi_RESULT Remove() override;

    virtual CDMi_RESULT Close(void) override;

    virtual const char *GetSessionId(void) const override;
    virtual const char *GetKeySystem(void) const override;
    virtual CDMi_RESULT Decrypt(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t *f_pdwSubSampleMapping,
        uint32_t f_cdwSubSampleMapping,
        const uint8_t *f_pbIV,
        uint32_t f_cbIV,
        const uint8_t *f_pbData,
        uint32_t f_cbData,
        uint32_t *f_pcbOpaqueClearContent,
        uint8_t **f_ppbOpaqueClearContent,
        const uint8_t keyIdLength,
        const uint8_t* keyId,
        bool initWithLast15) override;

    virtual CDMi_RESULT ReleaseClearContent(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t  f_cbClearContentOpaque,
        uint8_t  *f_pbClearContentOpaque ) override;

private:
    bool LoadRevocationList(const char *revListFile);

    static DRM_RESULT PolicyCallback(
            const DRM_VOID *f_pvOutputLevelsData,
            DRM_POLICY_CALLBACK_TYPE f_dwCallbackType,
            const DRM_KID *f_pKID,
            const DRM_LID *f_pLID,
            const DRM_VOID *f_pv);

    int InitSecureClock(DRM_APP_CONTEXT *pDrmAppCtx);

private:
    DRM_APP_CONTEXT *m_poAppContext;
    DRM_DECRYPT_CONTEXT m_oDecryptContext;
    DRM_BYTE *m_pbOpaqueBuffer;
    DRM_DWORD m_cbOpaqueBuffer;

    DRM_BYTE *m_pbRevocationBuffer;

    std::string m_customData;

    IMediaKeySessionCallback *m_piCallback;
    KeyState m_eKeyState;
    DRM_CHAR m_rgchSessionID[CCH_BASE64_EQUIV(sizeof(DRM_ID)) + 1];
    DRM_BOOL m_fCommit;
    DRM_VOID *m_pOEMContext;

    WPEFramework::Core::CriticalSection _decoderLock;

};

} // namespace CDMi
