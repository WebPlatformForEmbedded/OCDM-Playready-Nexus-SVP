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

#include "MediaSession.h"
#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>
#include <string.h>
#include <vector>
#include <sys/utsname.h>

#include <nexus_random_number.h>

#include <drmbuild_oem.h>
#include <drmnamespace.h>
#include <drmbytemanip.h>
#include <drmmanager.h>
#include <drmbase64.h>
#include <drmsoapxmlutility.h>
#include <oemcommon.h>
#include <drmconstants.h>
#include <drmsecuretime.h>
#include <drmsecuretimeconstants.h>
#include <drmrevocation.h>
#include <drmxmlparser.h>
#include <drmmathsafe.h>
#include <prdy_http.h>
#include <drm_data.h>

using SafeCriticalSection = WPEFramework::Core::SafeSyncType<WPEFramework::Core::CriticalSection>;
extern WPEFramework::Core::CriticalSection drmAppContextMutex_;

#define NYI_KEYSYSTEM "keysystem-placeholder"

// ~100 KB to start * 64 (2^6) ~= 6.4 MB, don't allocate more than ~6.4 MB
#define DRM_MAXIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE ( 64 * MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE )

#include <b_secbuf.h>

struct Rpc_Secbuf_Info {
    uint32_t type;
    size_t   size;
    void    *token;
    void    *token_enc;
    uint32_t subsamples_count;
    uint32_t subsamples[];
};

namespace CDMi {

    static const char *DRM_DEFAULT_REVOCATION_LIST_FILE="/tmp/revpackage.xml";
    const DRM_CONST_STRING  *g_rgpdstrRights[1] = {&g_dstrWMDRM_RIGHT_PLAYBACK};

// Parse out the first PlayReady initialization header found in the concatenated
// block of headers in _initData_.
// If a PlayReady header is found, this function returns true and the header
// contents are stored in _output_.
// Otherwise, returns false and _output_ is not touched.
bool parsePlayreadyInitializationData(const std::string& initData, std::string* output)
{
    BufferReader input(reinterpret_cast<const uint8_t*>(initData.data()), initData.length());

    static const uint8_t playreadySystemId[] = {
      0x9A, 0x04, 0xF0, 0x79, 0x98, 0x40, 0x42, 0x86,
      0xAB, 0x92, 0xE6, 0x5B, 0xE0, 0x88, 0x5F, 0x95,
    };

    // one PSSH box consists of:
    // 4 byte size of the atom, inclusive.  (0 means the rest of the buffer.)
    // 4 byte atom type, "pssh".
    // (optional, if size == 1) 8 byte size of the atom, inclusive.
    // 1 byte version, value 0 or 1.  (skip if larger.)
    // 3 byte flags, value 0.  (ignored.)
    // 16 byte system id.
    // (optional, if version == 1) 4 byte key ID count. (K)
    // (optional, if version == 1) K * 16 byte key ID.
    // 4 byte size of PSSH data, exclusive. (N)
    // N byte PSSH data.
    while (!input.IsEOF()) {
        size_t startPosition = input.pos();

        // The atom size, used for skipping.
        uint64_t atomSize;

        if (!input.Read4Into8(&atomSize)) {
            return false;
        }

        std::vector<uint8_t> atomType;
        if (!input.ReadVec(&atomType, 4)) {
            return false;
        }

        if (atomSize == 1) {
            if (!input.Read8(&atomSize)) {
                return false;
            }
        } else if (atomSize == 0) {
            atomSize = input.size() - startPosition;
        }

        if (memcmp(&atomType[0], "pssh", 4)) {
            if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
                return false;
            }
            continue;
        }

        uint8_t version;
        if (!input.Read1(&version)) {
            return false;
        }

        if (version > 1) {
            // unrecognized version - skip.
            if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
                return false;
            }
            continue;
        }

        // flags
        if (!input.SkipBytes(3)) {
            return false;
        }

        // system id
        std::vector<uint8_t> systemId;
        if (!input.ReadVec(&systemId, sizeof(playreadySystemId))) {
            return false;
        }

        if (memcmp(&systemId[0], playreadySystemId, sizeof(playreadySystemId))) {
            // skip non-Playready PSSH boxes.
            if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
                return false;
            }
            continue;
        }

        if (version == 1) {
            // v1 has additional fields for key IDs.  We can skip them.
            uint32_t numKeyIds;
            if (!input.Read4(&numKeyIds)) {
                return false;
            }

            if (!input.SkipBytes(numKeyIds * 16)) {
                return false;
            }
        }

        // size of PSSH data
        uint32_t dataLength;
        if (!input.Read4(&dataLength)) {
            return false;
        }

        output->clear();
        if (!input.ReadString(output, dataLength)) {
            return false;
        }

        return true;
    }

    // we did not find a matching record
    return false;
}

bool MediaKeySession::LoadRevocationList(const char *revListFile)
{
    DRM_RESULT dr = DRM_SUCCESS;
    FILE    * fRev;
    uint8_t * revBuf = nullptr;
    size_t    fileSize = 0;
    uint32_t  currSize = 0;

    assert(revListFile != nullptr);

    fRev = fopen(revListFile, "rb");
    if( fRev == nullptr)
    {
        return true;
    }

    /* get the size of the file */
    fseek(fRev, 0, SEEK_END);
    fileSize = ftell(fRev);
    fseek(fRev, 0, SEEK_SET);

    revBuf = (uint8_t *)BKNI_Malloc(fileSize);
    if( revBuf == nullptr)
    {
        goto ErrorExit;
    }

    BKNI_Memset(revBuf, 0x00, fileSize);

    for(;;) {
        uint8_t buf[512];
        int rc = fread(buf, 1, sizeof(buf), fRev);
        if(rc<=0) {
            break;
        }
        BKNI_Memcpy(revBuf+currSize, buf, rc);
        currSize += rc;
    }

    ChkDR( Drm_Revocation_StorePackage(
            m_poAppContext,
            ( DRM_CHAR * )revBuf,
            fileSize ) );

    if( revBuf != nullptr)
        BKNI_Free(revBuf);

    return true;

ErrorExit:
    if( revBuf != nullptr)
        BKNI_Free(revBuf);

    return false;
}

// PlayReady license policy callback which should be
// customized for platform/environment that hosts the CDM.
// It is currently implemented as a place holder that
// does nothing.
DRM_RESULT MediaKeySession::PolicyCallback(
            const DRM_VOID *f_pvPolicyCallbackData,
            DRM_POLICY_CALLBACK_TYPE f_dwCallbackType,
            const DRM_KID *f_pKID,
            const DRM_LID *f_pLID,
            const DRM_VOID *f_pv)
{
    /*!+!hla fix this, implement for something. */
    DRM_RESULT dr = DRM_SUCCESS;
    const DRM_PLAY_OPL_EX2 *oplPlay = NULL;

    BSTD_UNUSED(f_pKID);
    BSTD_UNUSED(f_pLID);
    BSTD_UNUSED(f_pv);

    switch( f_dwCallbackType )
    {
        case DRM_PLAY_OPL_CALLBACK:
            printf("  Got DRM_PLAY_OPL_CALLBACK from Bind:\r\n");
            ChkArg( f_pvPolicyCallbackData != NULL );
            oplPlay = (const DRM_PLAY_OPL_EX2*)f_pvPolicyCallbackData;

            printf("    minOPL:\r\n");
            printf("    wCompressedDigitalVideo   = %d\r\n", oplPlay->minOPL.wCompressedDigitalVideo);
            printf("    wUncompressedDigitalVideo = %d\r\n", oplPlay->minOPL.wUncompressedDigitalVideo);
            printf("    wAnalogVideo              = %d\r\n", oplPlay->minOPL.wAnalogVideo);
            printf("    wCompressedDigitalAudio   = %d\r\n", oplPlay->minOPL.wCompressedDigitalAudio);
            printf("    wUncompressedDigitalAudio = %d\r\n", oplPlay->minOPL.wUncompressedDigitalAudio);
            printf("\r\n");

            printf("    oplIdReserved:\r\n");
           // ChkDR( DRMTOOLS_PrintOPLOutputIDs( &oplPlay->oplIdReserved ) );

            printf("    vopi:\r\n");
            //ChkDR( DRMTOOLS_PrintVideoOutputProtectionIDs( &oplPlay->vopi ) );

            printf("    dvopi:\r\n");
            //ChkDR( handleDigitalVideoOutputProtectionIDs( &oplPlay->dvopi ) );

            break;

        case DRM_EXTENDED_RESTRICTION_QUERY_CALLBACK:
        {
            const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT *pExtCallback = (const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT*)f_pvPolicyCallbackData;
            DRM_DWORD i = 0;

            printf("  Got DRM_EXTENDED_RESTRICTION_QUERY_CALLBACK from Bind:\r\n");

            printf("    wRightID = %d\r\n", pExtCallback->wRightID);
            printf("    wType    = %d\r\n", pExtCallback->pRestriction->wType);
            printf("    wFlags   = %x\r\n", pExtCallback->pRestriction->wFlags);

            printf("    Data     = ");

            for( i = pExtCallback->pRestriction->ibData; (i - pExtCallback->pRestriction->ibData) < pExtCallback->pRestriction->cbData; i++ )
            {
                printf("0x%.2X ", pExtCallback->pRestriction->pbBuffer[ i ] );
            }
            printf("\r\n\r\n");

            /* Report that restriction was not understood */
            dr = DRM_E_EXTENDED_RESTRICTION_NOT_UNDERSTOOD;
        }
            break;
        case DRM_EXTENDED_RESTRICTION_CONDITION_CALLBACK:
        {
            const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT *pExtCallback = (const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT*)f_pvPolicyCallbackData;
            DRM_DWORD i = 0;

            printf("  Got DRM_EXTENDED_RESTRICTION_CONDITION_CALLBACK from Bind:\r\n");

            printf("    wRightID = %d\r\n", pExtCallback->wRightID);
            printf("    wType    = %d\r\n", pExtCallback->pRestriction->wType);
            printf("    wFlags   = %x\r\n", pExtCallback->pRestriction->wFlags);

            printf("    Data     = ");
            for( i = pExtCallback->pRestriction->ibData; (i - pExtCallback->pRestriction->ibData) < pExtCallback->pRestriction->cbData; i++ )
            {
                printf("0x%.2X ", pExtCallback->pRestriction->pbBuffer[ i ] );
            }
            printf("\r\n\r\n");
        }
            break;
        case DRM_EXTENDED_RESTRICTION_ACTION_CALLBACK:
        {
            const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT *pExtCallback = (const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT*)f_pvPolicyCallbackData;
            DRM_DWORD i = 0;

            printf("  Got DRM_EXTENDED_RESTRICTION_ACTION_CALLBACK from Bind:\r\n");

            printf("    wRightID = %d\r\n", pExtCallback->wRightID);
            printf("    wType    = %d\r\n", pExtCallback->pRestriction->wType);
            printf("    wFlags   = %x\r\n", pExtCallback->pRestriction->wFlags);

            printf("    Data     = ");
            for( i = pExtCallback->pRestriction->ibData; (i - pExtCallback->pRestriction->ibData) < pExtCallback->pRestriction->cbData; i++ )
            {
                printf("0x%.2X ", pExtCallback->pRestriction->pbBuffer[ i ] );
            }
            printf("\r\n\r\n");
        }
            break;
        default:
            printf("  Callback from Bind with unknown callback type of %d.\r\n", f_dwCallbackType);

            /* Report that this callback type is not implemented */
            ChkDR( DRM_E_NOTIMPL );
    }

    ErrorExit:
    return dr;

}

 MediaKeySession::MediaKeySession(
     const uint8_t *f_pbInitData, uint32_t f_cbInitData, 
     const uint8_t *f_pbCDMData, uint32_t f_cbCDMData, 
     DRM_VOID *f_pOEMContext, DRM_APP_CONTEXT * appContext,
     bool initiateChallengeGeneration)
        : m_poAppContext(appContext)
        , m_oDecryptContext(nullptr)
        , m_pbOpaqueBuffer(nullptr)
        , m_cbOpaqueBuffer(0)
        , m_pbRevocationBuffer(nullptr)
        , m_customData(reinterpret_cast<const char*>(f_pbCDMData), f_cbCDMData)
        , m_piCallback(nullptr)
        , m_eKeyState(KEY_CLOSED)
        , m_fCommit(false)
        , m_pOEMContext(f_pOEMContext)
        , mDrmHeader()
        , m_SessionId()
        , mBatchId()
        , m_decryptInited(false)
        , mInitiateChallengeGeneration(initiateChallengeGeneration){

    LOGGER(LINFO_, "Contruction MediaKeySession, Build: %s", __TIMESTAMP__ );
    m_oDecryptContext = new DRM_DECRYPT_CONTEXT;
    memset(m_oDecryptContext, 0, sizeof(DRM_DECRYPT_CONTEXT));
        
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_ID oSessionID;
    DRM_DWORD cchEncodedSessionID = sizeof(m_rgchSessionID);
    DRM_WCHAR          rgwchHDSPath[ DRM_MAX_PATH ];
    DRM_CONST_STRING   dstrHDSPath = DRM_EMPTY_DRM_STRING;
    std::string playreadyInitData;
    DRM_WCHAR           *hdsDir = bdrm_get_hds_dir();
    DRM_WCHAR           *hdsFname = bdrm_get_pr3x_hds_fname();

    DRMFILETIME               ftSystemTime; /* Initialized by Drm_SecureTime_GetValue */
    DRM_SECURETIME_CLOCK_TYPE eClockType;   /* Initialized by Drm_SecureTime_GetValue */

    DRM_DWORD dwEncryptionMode  = OEM_TEE_DECRYPTION_MODE_NOT_SECURE;

    mLicenseResponse = std::unique_ptr<LicenseResponse>(new LicenseResponse());

    // The current state MUST be KEY_CLOSED otherwise error out.
    ChkBOOL(m_eKeyState == KEY_CLOSED, DRM_E_INVALIDARG);

    ChkArg((f_pbInitData == nullptr) == (f_cbInitData == 0));

    if (initiateChallengeGeneration != false) {
        if (f_pbInitData != nullptr)
        {
            std::string initData(reinterpret_cast<const char *>(f_pbInitData), f_cbInitData);

            if (!parsePlayreadyInitializationData(initData, &playreadyInitData)) {
                playreadyInitData = initData;
            }
        }

        ChkMem(m_pbOpaqueBuffer = (DRM_BYTE *)Oem_MemAlloc(MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE));
        m_cbOpaqueBuffer = MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE;

        ChkMem(m_poAppContext = (DRM_APP_CONTEXT *)Oem_MemAlloc(sizeof(DRM_APP_CONTEXT)));

        dstrHDSPath.pwszString = rgwchHDSPath;
        dstrHDSPath.cchString = DRM_MAX_PATH;

        /* Convert the HDS path to DRM_STRING. */
        if (bdrm_get_hds_dir_lgth() > 0){
            BKNI_Memcpy((DRM_WCHAR*)dstrHDSPath.pwszString, hdsDir, bdrm_get_hds_dir_lgth() * sizeof(DRM_WCHAR));
        }
        BKNI_Memcpy((DRM_WCHAR*)dstrHDSPath.pwszString + bdrm_get_hds_dir_lgth(), hdsFname, (bdrm_get_pr3x_hds_fname_lgth() + 1) * sizeof(DRM_WCHAR));

        if (hdsFname != NULL && bdrm_get_pr3x_hds_fname_lgth() > 0) {
            if (bdrm_get_hds_dir_lgth() > 0)
            {
                BKNI_Memcpy((DRM_WCHAR*)dstrHDSPath.pwszString, hdsDir, bdrm_get_hds_dir_lgth() * sizeof(DRM_WCHAR));
                BKNI_Memcpy((DRM_WCHAR*)dstrHDSPath.pwszString + bdrm_get_hds_dir_lgth(),
                            hdsFname, (bdrm_get_pr3x_hds_fname_lgth() + 1) * sizeof(DRM_WCHAR));
            }
        }

        // Initialize DRM app context.
        ChkDR(Drm_Initialize(m_poAppContext,
                            m_pOEMContext,
                            m_pbOpaqueBuffer,
                            m_cbOpaqueBuffer,
                            &dstrHDSPath));

        dr = Drm_SecureTime_GetValue( m_poAppContext, &ftSystemTime, &eClockType  );
        if( (dr == DRM_E_SECURETIME_CLOCK_NOT_SET) || (dr == DRM_E_TEE_PROVISIONING_REQUIRED) )
        {
            /* setup the Playready secure clock */
            if(InitSecureClock(m_poAppContext) != 0)
            {
                LOGGER(LERROR_, "Failed to initiize Secure Clock, quitting...");
                goto ErrorExit;
            }
        }
        else if (dr == DRM_E_CLK_NOT_SUPPORTED)  /* Secure Clock not supported, try the Anti-Rollback Clock */
        {
            DRMSYSTEMTIME   systemTime;
            struct timeval  tv;
            struct tm      *tm;

            LOGGER(LINFO_, "Secure Clock not supported, trying the Anti-Rollback Clock...");

            gettimeofday(&tv, nullptr);
            tm = gmtime(&tv.tv_sec);

            systemTime.wYear         = tm->tm_year+1900;
            systemTime.wMonth        = tm->tm_mon+1;
            systemTime.wDayOfWeek    = tm->tm_wday;
            systemTime.wDay          = tm->tm_mday;
            systemTime.wHour         = tm->tm_hour;
            systemTime.wMinute       = tm->tm_min;
            systemTime.wSecond       = tm->tm_sec;
            systemTime.wMilliseconds = tv.tv_usec/1000;

            if(Drm_AntiRollBackClock_Init(m_poAppContext, &systemTime) != 0)
            {
                LOGGER(LERROR_, "Failed to initiize Anti-Rollback Clock, quitting....");
                goto ErrorExit;
            }
        }
        else
        {
            if (dr != 0) {
                LOGGER(LERROR_, "Expect platform to support Secure Clock or Anti-Rollback Clock. Possible certificate (error 0x%08X)", static_cast<unsigned int>(dr));
                goto ErrorExit;
            }
        }

        // Specify the initial size of the in-memory license store. The store will
        // grow above this size if required during usage, using a memory-doubling
        // algorithm. So it is more efficient, but not required, to get the size
        // correct from the beginning.
        dr = Drm_ResizeInMemoryLicenseStore(m_poAppContext, MAX_NUM_LICENSES * LICENSE_SIZE_BYTES);
        if (DRM_FAILED(dr)) {
            LOGGER(LERROR_,  "Error in Drm_ResizeInMemoryLicenseStore 0x%08lX", dr);
        }

        if (DRM_REVOCATION_IsRevocationSupported())
        {
            ChkMem(m_pbRevocationBuffer = (DRM_BYTE *)Oem_MemAlloc(REVOCATION_BUFFER_SIZE));

            ChkDR(Drm_Revocation_SetBuffer(m_poAppContext,
                                        m_pbRevocationBuffer,
                                        REVOCATION_BUFFER_SIZE));
            if( !LoadRevocationList(DRM_DEFAULT_REVOCATION_LIST_FILE))
            {
                goto ErrorExit;
            }
        }

        // Generate a random media session ID.
        ChkDR(Oem_Random_GetBytes(m_poAppContext, (DRM_BYTE *)&oSessionID, sizeof(oSessionID)));
        ZEROMEM(m_rgchSessionID, sizeof(m_rgchSessionID));
        // Store the generated media session ID in base64 encoded form.
        ChkDR(DRM_B64_EncodeA((DRM_BYTE *)&oSessionID,
                            sizeof(oSessionID),
                            m_rgchSessionID,
                            &cchEncodedSessionID,
                            0));

        LOGGER(LINFO_, "Session ID generated: %s", m_rgchSessionID);

        ChkDR(Drm_Content_SetProperty(m_poAppContext,
                                    DRM_CSP_AUTODETECT_HEADER,
                                    reinterpret_cast<const uint8_t *>(playreadyInitData.data()),
                                    playreadyInitData.size()));

        /* set encryption/decryption mode */
        dwEncryptionMode = OEM_TEE_DECRYPTION_MODE_HANDLE;
        ChkDR(Drm_Content_SetProperty(
                m_poAppContext,
                DRM_CSP_DECRYPTION_OUTPUT_MODE,
                (const DRM_BYTE*)&dwEncryptionMode,
                sizeof( DRM_DWORD ) ) );
        
        m_eKeyState = KEY_INIT;
    } else {
        // TODO: can we do this nicer?
        mDrmHeader.resize(f_cbInitData);
        memcpy(&mDrmHeader[0], f_pbInitData, f_cbInitData);
    }

    LOGGER(LINFO_, "Session Initialized");
ErrorExit:
    if (DRM_FAILED(dr))
    {
        m_eKeyState = KEY_ERROR;
        LOGGER(LERROR_, "Drm_Content_SetProperty() failed, exiting");
    }
}

MediaKeySession::~MediaKeySession(void)
{
    Close();
    LOGGER(LINFO_, "PlayReady Session Destructed");
}


const char *MediaKeySession::GetSessionId(void) const
{

    return m_rgchSessionID;
}

const char *MediaKeySession::GetKeySystem(void) const
{

    return NYI_KEYSYSTEM; // FIXME : replace with keysystem and test.
}

void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback)
{
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_BYTE *pbChallenge = nullptr;
    DRM_DWORD cbChallenge = 0;
    DRM_CHAR *pchSilentURL = nullptr;
    DRM_DWORD cchSilentURL = 0;

    // The current state MUST be KEY_INIT otherwise error out.
    if(m_eKeyState == KEY_INIT){

        ChkArg(f_piMediaKeySessionCallback != nullptr);

        m_piCallback = const_cast<IMediaKeySessionCallback *>(f_piMediaKeySessionCallback);

        // Try to figure out the size of the license acquisition
        // challenge to be returned.
        dr = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                            g_rgpdstrRights,
                                            DRM_NO_OF(g_rgpdstrRights),
                                            nullptr,
                                            !m_customData.empty() ? m_customData.c_str() : nullptr,
                                            m_customData.size(),
                                            nullptr,
                                            &cchSilentURL,
                                            nullptr,
                                            nullptr,
                                            nullptr,
                                            &cbChallenge,
                                            nullptr);
        if (dr == DRM_E_BUFFERTOOSMALL)
        {
            if (cchSilentURL > 0)
            {
                ChkMem(pchSilentURL = (DRM_CHAR *)Oem_MemAlloc(cchSilentURL + 1));
                ZEROMEM(pchSilentURL, cchSilentURL + 1);
            }

            // Allocate buffer that is sufficient to store the license acquisition
            // challenge.
            if (cbChallenge > 0)
            {
                ChkMem(pbChallenge = (DRM_BYTE *)Oem_MemAlloc(cbChallenge + 1));
                ZEROMEM(pbChallenge, cbChallenge + 1);
            }
            dr = DRM_SUCCESS;
        }
        else
        {
            ChkDR(dr);
        }

        // Supply a buffer to receive the license acquisition challenge.
        ChkDR(Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                            g_rgpdstrRights,
                                            DRM_NO_OF(g_rgpdstrRights),
                                            nullptr,
                                            !m_customData.empty() ? m_customData.c_str() : nullptr,
                                            m_customData.size(),
                                            pchSilentURL,
                                            &cchSilentURL,
                                            nullptr,
                                            nullptr,
                                            pbChallenge,
                                            &cbChallenge,
                                            nullptr));

        pbChallenge[cbChallenge] = 0;
        m_eKeyState = KEY_PENDING;

        LOGGER(LINFO_, "Generated license acquisition challenge.");

        // Everything is OK and trigger a callback to let the caller
        // handle the key message.
        m_piCallback->OnKeyMessage((const uint8_t *) pbChallenge, cbChallenge, (char *) pchSilentURL);
    }

ErrorExit:
    if (DRM_FAILED(dr))
    {
        if (m_piCallback != nullptr)
        {
            m_piCallback->OnError(0, CDMi_S_FALSE, "KeyError");
        }
        m_eKeyState = KEY_ERROR;
        LOGGER(LERROR_, "Failure during license acquisition challenge. (error: 0x%08X)",(unsigned int)dr);
    }

    SAFE_OEM_FREE(pbChallenge);
    SAFE_OEM_FREE(pchSilentURL);
}

CDMi_RESULT MediaKeySession::Load(void)
{

  return CDMi_S_FALSE;
}

void MediaKeySession::Update(const uint8_t *f_pbKeyMessageResponse, uint32_t  f_cbKeyMessageResponse)
{

    DRM_RESULT dr = DRM_SUCCESS;    

    if(m_eKeyState == KEY_PENDING){
        DRM_LICENSE_RESPONSE oLicenseResponse;

        ChkArg(f_pbKeyMessageResponse != nullptr && f_cbKeyMessageResponse > 0);

        BKNI_Memset(&oLicenseResponse, 0, sizeof(oLicenseResponse));

        LOGGER(LINFO_, "Processing license acquisition response...");
        ChkDR(Drm_LicenseAcq_ProcessResponse(m_poAppContext,
                                            DRM_PROCESS_LIC_RESPONSE_NO_FLAGS,
                                            const_cast<DRM_BYTE *>(f_pbKeyMessageResponse),
                                            f_cbKeyMessageResponse,
                                            &oLicenseResponse));
        
        LOGGER(LINFO_, "Binding License...");
        while ((dr = Drm_Reader_Bind(m_poAppContext,
                            g_rgpdstrRights,
                            DRM_NO_OF(g_rgpdstrRights),
                            PolicyCallback,
                            nullptr,
                            m_oDecryptContext)) == DRM_E_BUFFERTOOSMALL) {
            uint8_t *pbNewOpaqueBuffer = nullptr;
            m_cbOpaqueBuffer *= 2;

            ChkMem( pbNewOpaqueBuffer = ( uint8_t* )Oem_MemAlloc(m_cbOpaqueBuffer) );

            if( m_cbOpaqueBuffer > DRM_MAXIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE ) {
                ChkDR( DRM_E_OUTOFMEMORY );
            }
            ChkDR( Drm_ResizeOpaqueBuffer(
                    m_poAppContext,
                    pbNewOpaqueBuffer,
                    m_cbOpaqueBuffer ) );
            /*
            Free the old buffer and then transfer the new buffer ownership
            Free must happen after Drm_ResizeOpaqueBuffer because that
            function assumes the existing buffer is still valid
            */
            SAFE_OEM_FREE(m_pbOpaqueBuffer);
            m_pbOpaqueBuffer = pbNewOpaqueBuffer;
        }
        ChkDR(dr);

        ChkDR( Drm_Reader_Commit( m_poAppContext, nullptr, nullptr ) );
               
        m_eKeyState = KEY_READY;
        LOGGER(LINFO_, "Key processed, now ready for content decryption");
    }

    if((m_eKeyState == KEY_READY) && (DRM_SUCCEEDED(dr))){
        m_piCallback->OnKeyStatusUpdate("KeyUsable", nullptr, 0);
        LOGGER(LINFO_, "Send OnKeyStatusUpdate->KeyUsable");
    }

ErrorExit:
    if (DRM_FAILED(dr))
    {
        if (dr == DRM_E_LICENSE_NOT_FOUND) {
            /* could not find a license for the KID */
            LOGGER(LERROR_, "No licenses found in the license store. Please request one from the license server.");
        }
        else if(dr == DRM_E_LICENSE_EXPIRED) {
            /* License is expired */
            LOGGER(LERROR_, "License expired. Please request one from the license server.");
        }
        else if(  dr == DRM_E_RIV_TOO_SMALL ||
                  dr == DRM_E_LICEVAL_REQUIRED_REVOCATION_LIST_NOT_AVAILABLE )
        {
            /* Revocation Package must be update */
            LOGGER(LERROR_, "Revocation Package must be update. (error: 0x%08X)",(unsigned int)dr);
        }
        else {
            LOGGER(LERROR_, "Unexpected failure during bind. (error: 0x%08X)",(unsigned int)dr);
        }
        
        m_eKeyState = KEY_ERROR;
        m_piCallback->OnError(0, CDMi_S_FALSE, "KeyError");
    }
    return;
}

CDMi_RESULT MediaKeySession::Remove(void)
{
    return CDMi_S_FALSE;
}

CDMi_RESULT MediaKeySession::Close(void)
{
    m_eKeyState = KEY_CLOSED;

    if (mInitiateChallengeGeneration == true) {
        if (m_pbRevocationBuffer != nullptr) {
            SAFE_OEM_FREE(m_pbRevocationBuffer);
            m_pbRevocationBuffer = nullptr;
        }

        if (m_poAppContext !=  nullptr) {
            DRM_RESULT dr = Drm_StoreMgmt_DeleteInMemoryLicenses(m_poAppContext, &mBatchId);
            // Since there are multiple licenses in a batch, we might have already cleared
            // them all. Ignore DRM_E_NOMORE returned from Drm_StoreMgmt_DeleteInMemoryLicenses.
            if (DRM_FAILED(dr) && (dr != DRM_E_NOMORE)) {
                LOGGER(LERROR_, "Error in Drm_StoreMgmt_DeleteInMemoryLicenses 0x%08lX", dr);
            }

            LOGGER(LINFO_, "PlayReady Session Uninitialize");
            Drm_Uninitialize(m_poAppContext);

            SAFE_OEM_FREE(m_poAppContext);
            m_poAppContext = nullptr;
        }

        if (m_pbOpaqueBuffer != nullptr) {
            SAFE_OEM_FREE(m_pbOpaqueBuffer);
            m_cbOpaqueBuffer = nullptr;
        }
    }

    if (m_oDecryptContext != nullptr) {
        LOGGER(LINFO_, "PlayReady Session Destructed");
        Drm_Reader_Close(m_oDecryptContext);
        delete m_oDecryptContext;
        m_oDecryptContext = nullptr;
    }

    m_piCallback = nullptr;
    m_fCommit = FALSE;
    m_decryptInited = false;

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::Decrypt(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t *f_pdwSubSampleMapping,
        uint32_t f_cdwSubSampleMapping,
        const uint8_t *f_pbIV,
        uint32_t f_cbIV,
        const uint8_t *payloadData,
        uint32_t payloadDataSize,
        uint32_t *f_pcbOpaqueClearContent,
        uint8_t **f_ppbOpaqueClearContent,
        const uint8_t /* keyIdLength */,
        const uint8_t* /* keyId */,
        bool initWithLast15)
{
    SafeCriticalSection systemLock(drmAppContextMutex_); 
    
    if (!m_oDecryptContext) {
        LOGGER(LERROR_, "Error: no decrypt context (yet?)\n");
        return CDMi_S_FALSE;
    }

    DRM_RESULT dr = DRM_SUCCESS;
    CDMi_RESULT cr = CDMi_S_FALSE;
    DRM_AES_COUNTER_MODE_CONTEXT oAESContext = {0, 0, 0};
    Rpc_Secbuf_Info *pRPCsecureBufferInfo = const_cast<Rpc_Secbuf_Info*>(reinterpret_cast<const Rpc_Secbuf_Info*>(payloadData));
    B_Secbuf_Info   secureBufferInfo;
    void *pOpaqueData = nullptr;
    void *pOpaqueDataEnc = nullptr;

    {
        ChkArg(payloadData != nullptr && payloadDataSize > 0);
    }

    if (!initWithLast15) {
        if( f_pcbOpaqueClearContent == nullptr || f_ppbOpaqueClearContent == nullptr )
        {
            dr = DRM_E_INVALIDARG;
            goto ErrorExit;
        }

        {
            // The current state MUST be KEY_READY otherwise error out.
            ChkBOOL(m_eKeyState == KEY_READY, DRM_E_INVALIDARG);
            ChkArg(f_pbIV != nullptr && f_cbIV == sizeof(DRM_UINT64));
        }
    }

    // TODO: can be done in another way (now abusing "initWithLast15" variable)
    if (initWithLast15) {
        // Netflix case
       memcpy(&oAESContext, f_pbIV, sizeof(oAESContext));
    } else {
       // Regular case
       // FIXME: IV bytes need to be swapped ???
       // TODO: is this for-loop the same as "NETWORKBYTES_TO_QWORD"?
       unsigned char * ivDataNonConst = const_cast<unsigned char *>(f_pbIV); // TODO: this is ugly
       for (uint32_t i = 0; i < f_cbIV / 2; i++) {
          unsigned char temp = ivDataNonConst[i];
          ivDataNonConst[i] = ivDataNonConst[f_cbIV - i - 1];
          ivDataNonConst[f_cbIV - i - 1] = temp;
       }

       memcpy(&oAESContext.qwInitializationVector, f_pbIV, f_cbIV);
    }


    if (B_Secbuf_AllocWithToken(pRPCsecureBufferInfo->size, B_Secbuf_Type_eGeneric, pRPCsecureBufferInfo->token_enc, &pOpaqueDataEnc)) {
        LOGGER(LERROR_, "B_Secbuf_AllocWithToken(%d, B_Secbuf_Type_eGeneric, %p) failed!", pRPCsecureBufferInfo->size, &pOpaqueDataEnc);
        goto ErrorExit;
    }

    // copy data in the generic buffer to the secure buffer
    if (B_Secbuf_Alloc(pRPCsecureBufferInfo->size, B_Secbuf_Type_eSecure, &pOpaqueData)) {
        LOGGER(LERROR_, "B_Secbuf_Alloc(%d, B_Secbuf_Type_eSecure, %p) failed!", pRPCsecureBufferInfo->size, &pOpaqueData);
    }
     else {
        // Update token for WPE to get the secure buffer
        B_Secbuf_GetBufferInfo(pOpaqueData, &secureBufferInfo);
        pRPCsecureBufferInfo->token = secureBufferInfo.token;

        // Update payloadDataSize to the buffer size
        payloadDataSize = pRPCsecureBufferInfo->size;
    // copy all samples data including clear one too
    B_Secbuf_ImportData(pOpaqueData, 0, (unsigned char*)pOpaqueDataEnc, pRPCsecureBufferInfo->size, 1);

    ChkDR( Drm_Reader_DecryptOpaque(
            m_oDecryptContext,
            pRPCsecureBufferInfo->subsamples_count,
            pRPCsecureBufferInfo->subsamples,
            oAESContext.qwInitializationVector,
            payloadDataSize,
            (DRM_BYTE*)pOpaqueDataEnc,
            (DRM_DWORD*)&payloadDataSize,
            (DRM_BYTE**)&pOpaqueData));

        cr = CDMi_SUCCESS;
    }
    // Return clear content.
    *f_pcbOpaqueClearContent = 0;
    *f_ppbOpaqueClearContent = nullptr;
    

ErrorExit: 
    if (DRM_FAILED(dr))
    {
        if (pOpaqueData != nullptr) B_Secbuf_Free(pOpaqueData);

        LOGGER(LERROR_, "Decryption failed (error: 0x%08X)", static_cast<uint32_t>(dr));
    }

    // only freeing desc here, pOpaqueData will be freed by WPE in gstreamer
    else if(pOpaqueData != nullptr){
        B_Secbuf_FreeDesc(pOpaqueData);
    }

    // Encrypted data does not need anymore, freeing
    if(pOpaqueDataEnc != nullptr){
        B_Secbuf_Free(pOpaqueDataEnc);
    }

    return cr;
}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t  f_cbClearContentOpaque,
        uint8_t  *f_pbClearContentOpaque )
{

  return CDMi_SUCCESS;
}

#define MAX_TIME_CHALLENGE_RESPONSE_LENGTH (1024*64)
#define MAX_URL_LENGTH (512)

int MediaKeySession::InitSecureClock(DRM_APP_CONTEXT *pDrmAppCtx)
{
    int                   rc = 0;
    DRM_DWORD             cbChallenge     = 0;
    DRM_BYTE             *pbChallenge     = nullptr;
    DRM_BYTE             *pbResponse      = nullptr;
    char                 *pTimeChallengeURL = nullptr;
    char                  secureTimeUrlStr[MAX_URL_LENGTH];
    bool                  redirect = true;
    int32_t               petRC=0;
    uint32_t              petRespCode = 0;
    uint32_t              startOffset;
    uint32_t              length;
    uint32_t              post_ret;
    NEXUS_MemoryAllocationSettings allocSettings;
    DRM_RESULT            drResponse = DRM_SUCCESS;
    DRM_RESULT            dr = DRM_SUCCESS;

    dr = Drm_SecureTime_GenerateChallenge( pDrmAppCtx,
                                           &cbChallenge,
                                           &pbChallenge );
    ChkDR(dr);

    NEXUS_Memory_GetDefaultAllocationSettings(&allocSettings);
    rc = NEXUS_Memory_Allocate(MAX_URL_LENGTH, &allocSettings, (void **)(&pTimeChallengeURL ));
    if(rc != NEXUS_SUCCESS)
    {
        LOGGER(LERROR_, " NEXUS_Memory_Allocate failed for time challenge response buffer, rc = %d", rc);
        goto ErrorExit;
    }

    /* send the petition request to Microsoft with HTTP GET */
    petRC = PRDY_HTTP_Client_GetForwardLinkUrl((char*)g_dstrHttpSecureTimeServerUrl.pszString,
                                               &petRespCode,
                                               (char**)&pTimeChallengeURL);

    if( petRC != 0)
    {
        LOGGER(LERROR_, " Secure Time forward link petition request failed, rc = %d", petRC);
        rc = petRC;
        goto ErrorExit;
    }

    do
    {
        redirect = false;

        /* we need to check if the Pettion responded with redirection */
        if( petRespCode == 200)
        {
            redirect = false;
        }
        else if( petRespCode == 302 || petRespCode == 301)
        {
            redirect = true;
            memset(secureTimeUrlStr, 0, MAX_URL_LENGTH);
            strcpy(secureTimeUrlStr, pTimeChallengeURL);
            memset(pTimeChallengeURL, 0, MAX_URL_LENGTH);

            petRC = PRDY_HTTP_Client_GetSecureTimeUrl(secureTimeUrlStr,
                                                      &petRespCode,
                                                      (char**)&pTimeChallengeURL);

            if( petRC != 0)
            {
                LOGGER(LERROR_, " Secure Time URL petition request failed, rc = %d", petRC);
                rc = petRC;
                goto ErrorExit;
            }
        }
        else
        {
            LOGGER(LERROR_, "Secure Clock Petition responded with unsupported result, rc = %d, can't get the time challenge URL", petRespCode);
            rc = -1;
            goto ErrorExit;
        }
    } while (redirect);

    NEXUS_Memory_GetDefaultAllocationSettings(&allocSettings);
    rc = NEXUS_Memory_Allocate(MAX_TIME_CHALLENGE_RESPONSE_LENGTH, &allocSettings, (void **)(&pbResponse ));
    if(rc != NEXUS_SUCCESS)
    {
        LOGGER(LERROR_, "NEXUS_Memory_Allocate failed for time challenge response buffer, rc = %d", rc);
        goto ErrorExit;
    }

    BKNI_Memset(pbResponse, 0, MAX_TIME_CHALLENGE_RESPONSE_LENGTH);
    post_ret = PRDY_HTTP_Client_SecureTimeChallengePost(pTimeChallengeURL,
                                                        (char *)pbChallenge,
                                                        1,
                                                        150,
                                                        (unsigned char**)&(pbResponse),
                                                        &startOffset,
                                                        &length);
    if( post_ret != 0)
    {
        LOGGER(LERROR_, "Secure Time Challenge request failed, rc = %d", post_ret);
        rc = post_ret;
        goto ErrorExit;
    }

    drResponse = Drm_SecureTime_ProcessResponse(
            pDrmAppCtx,
            length,
            (uint8_t *) pbResponse);
    if ( drResponse != DRM_SUCCESS )
    {
        LOGGER(LERROR_, "Drm_SecureTime_ProcessResponse failed, drResponse = %x", (unsigned int)drResponse);
        dr = drResponse;
        ChkDR( drResponse);

    }
    LOGGER(LINFO_, "Initialized Playready Secure Clock success.");

    /* NOW testing the system time */

    ErrorExit:

    ChkVOID( SAFE_OEM_FREE( pbChallenge ) );

    if( pTimeChallengeURL    != nullptr)
        NEXUS_Memory_Free(pTimeChallengeURL  );

    if( pbResponse != nullptr )
        NEXUS_Memory_Free(pbResponse);

    return rc;
}

}  // namespace CDMi
