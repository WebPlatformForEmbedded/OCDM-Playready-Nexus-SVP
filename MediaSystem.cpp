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

#include "Module.h"

#include "MediaSession.h"

#include <interfaces/IDRM.h>
#include <cryptalgo/cryptalgo.h>
#include <plugins/plugins.h>

#include <drmconstants.h>
#include <drmversionconstants.h>
#include <oemcommon.h>
#include <drm_data.h>
#include <prdy_http.h>
#include <drmsecuretime.h>
#include <drmsecuretimeconstants.h>

//TODO: mirgrate this to Core
#include <openssl/sha.h>

using namespace WPEFramework;

using SafeCriticalSection = Core::SafeSyncType<WPEFramework::Core::CriticalSection>;
Core::CriticalSection drmAppContextMutex_;

// Each challenge saves a nonce to the PlayReady3 nonce store, and each license
// bind removes a nonce. The nonce store is also a FIFO, with the oldest nonce
// rolling off if the store is full when a new challenge is generated. This can
// be a problem if the client generates but does not process a number of licenses
// greater than the nonce fifo. So NONCE_STORE_SIZE is reported to the client
// via the getLdlSessionLimit() API.
const uint32_t NONCE_STORE_SIZE = 100;

// Creates a new DRM_WCHAR[] on the heap from the provided string.
// Note: Caller takes ownership of returned heap memory.
static DRM_WCHAR* createDrmWchar(std::string const& s) {
    DRM_WCHAR* w = new DRM_WCHAR[s.length() + 1];
    for (size_t i = 0; i < s.length(); ++i)
        w[i] = DRM_ONE_WCHAR(s[i], '\0');
    w[s.length()] = DRM_ONE_WCHAR('\0', '\0');
    return w;
}

bool calcFileSha256 (const std::string& filePath, uint8_t hash[], uint32_t hashLength )
{
    bool result(false); 

    ASSERT(filePath.empty() == false);

    Core::DataElementFile dataBuffer(filePath, Core::File::USER_READ);

    if ( dataBuffer.IsValid() == false ) {
        TRACE_L1("Failed to open %s", filePath.c_str());
    } else {
        WPEFramework::Crypto::SHA256 calculator; 
        ASSERT(hashLength == calculator.Length);
        
        if (hashLength == calculator.Length) {
            calculator.Input(dataBuffer.Buffer(), dataBuffer.Size());

            const uint8_t* fileHash = calculator.Result();
            
            ::memcpy(hash, fileHash, calculator.Length);

            result = true;
        } else {
            TRACE_L1("Output hash buffer has a incorrect size(%d), need %d bytes", hashLength, calculator.Length);
        }
    }

    return result;
}

namespace CDMi {

static const char *DRM_DEFAULT_REVOCATION_LIST_FILE="/tmp/revpackage.xml";

class PlayReady : public IMediaKeys, public IMediaKeysExt {
private:
    PlayReady (const PlayReady&) = delete;
    PlayReady& operator= (const PlayReady&) = delete;

    class Config : public Core::JSON::Container {
    public:
        Config(const Config&) = delete;
        Config& operator=(const Config&) = delete;
        Config()
            : Core::JSON::Container()
            , MeteringCertificate()
        {
            Add(_T("metering"), &MeteringCertificate);
        }
        ~Config()
        {
        }

    public:
        Core::JSON::String MeteringCertificate;
    };

public:
    PlayReady() 
        : m_drmOemContext(nullptr)
        , m_nxAllocResults() 
        , m_drmDirectory()
        , m_drmStore()
        , m_pbOpaqueBuffer(nullptr)
        , m_pbRevocationBuffer(nullptr)
        , m_poAppContext(nullptr)
        , m_readDir()
        , m_storeLocation()
        , m_meteringCertificate(nullptr)
        , m_meteringCertificateSize(0)
    {
        NxClient_JoinSettings joinSettings;
        NxClient_AllocSettings nxAllocSettings;
        NEXUS_Error rc;
        DRM_RESULT dr = DRM_SUCCESS;

        NxClient_GetDefaultJoinSettings(&joinSettings);
        strncpy(joinSettings.name, "playready3x", NXCLIENT_MAX_NAME);
        joinSettings.ignoreStandbyRequest = true;
        rc = NxClient_Join(&joinSettings);
        if (rc) {
            LOGGER(LERROR_, "Couldnt join nxserver [rc=0x%08X]", rc);
            goto ErrorExit;
        }

        NxClient_GetDefaultAllocSettings(&nxAllocSettings);
        rc = NxClient_Alloc(&nxAllocSettings, &m_nxAllocResults);       

        if (rc) {
            LOGGER(LERROR_, "NxClient_Alloc failed nxserver [rc=0x%08X]", rc);
            goto ErrorExit;
        }
    ErrorExit:
        if (DRM_FAILED(dr))
        {
            LOGGER(LERROR_, "Playready Initialize failed (error: 0x%08X)", static_cast<unsigned int>(dr));
        }
    }

    ~PlayReady(void) {
        if (m_meteringCertificate != nullptr) {
            delete [] m_meteringCertificate;
            m_meteringCertificate = nullptr;
        }
        ASSERT(m_poAppContext.get() == nullptr);
        NxClient_Free(&m_nxAllocResults);
        NxClient_Uninit();
    }

    void Initialize(const WPEFramework::PluginHost::IShell * shell, const std::string& configline)
    {
        string persistentPath = shell->PersistentPath() + string("playready/");
        m_readDir = persistentPath;
        m_storeLocation = persistentPath + "drmstore";

        LOGGER(LINFO_,  "m_readDir: %s", m_readDir.c_str());
        LOGGER(LINFO_,  "m_storeLocation: %s", m_storeLocation.c_str());
        
        WPEFramework::Core::SystemInfo::SetEnvironment(_T("HOME"), persistentPath);  

        Config config;
        config.FromString(configline);

        if (config.MeteringCertificate.IsSet() == true) {
            Core::DataElementFile dataBuffer(config.MeteringCertificate.Value(), Core::File::USER_READ | Core::File::GROUP_READ);
            
            if(dataBuffer.IsValid() == false) {
                TRACE_L1(_T("Failed to open %s"), config.MeteringCertificate.Value().c_str());
            } else {
                m_meteringCertificateSize = dataBuffer.Size();
                m_meteringCertificate     = new DRM_BYTE[m_meteringCertificateSize];
                
                ::memcpy(m_meteringCertificate, dataBuffer.Buffer(), dataBuffer.Size());
            }
        }

        InitializeSystem();      
    }

    void InitializeSystem(){
        LOGGER(LINFO_, "Initialize PlayReady System, Build: %s", __TIMESTAMP__ );

        if(m_poAppContext.get()){
            DeinitializeSystem();
        }

        WPEFramework::Core::Directory(m_readDir.c_str()).CreatePath();
        
        NEXUS_ClientConfiguration platformConfig;
        OEM_Settings oemSettings;
        NEXUS_MemoryAllocationSettings heapSettings;
        DRM_RESULT dr = DRM_SUCCESS;

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

        ChkDR(Drm_Platform_Initialize((void *)&oemSettings));
        
        m_drmOemContext = oemSettings.f_pOEMContext;
        ChkMem(m_drmOemContext);

        CreateSystemExt();
    ErrorExit:
        if (DRM_FAILED(dr))
        {
            LOGGER(LERROR_, "Playready System Initialize failed (error: 0x%08X)", static_cast<unsigned int>(dr));
        }
    }

    void Deinitialize(const WPEFramework::PluginHost::IShell * shell)
    {
        DeinitializeSystem();
    }

    void DeinitializeSystem() { 
        LOGGER(LINFO_, "Deinitialize PlayReady System, Build: %s", __TIMESTAMP__ );
        if(m_poAppContext.get()) {
            // Deletes all expired licenses from the license store and perform maintenance
            DRM_RESULT dr = Drm_StoreMgmt_CleanupStore(m_poAppContext.get(),
                                            DRM_STORE_CLEANUP_ALL,
                                            nullptr, 0, nullptr);
            if(DRM_FAILED(dr))
            {
                LOGGER(LERROR_,  "Warning, Drm_StoreMgmt_CleanupStore returned 0x%08lX", dr);
            }

            // Uninitialize drm context
            Drm_Uninitialize(m_poAppContext.get());
            m_poAppContext.reset();
        }

        Drm_Platform_Uninitialize(m_drmOemContext);
    }

    CDMi_RESULT CreateMediaKeySession(
        const std::string& keySystem,
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData, uint32_t f_cbInitData, 
        const uint8_t *f_pbCDMData, uint32_t f_cbCDMData, 
        IMediaKeySession **f_ppiMediaKeySession) {

        // ToDo: This needs to be solved a bit nicer... 
        // Since the OCDM server is not aware of the location of the store but exposes a "delete store" API,
        // we need to check somewhere if it's deleted and recover it. Sadly the only way to recover is to
        // reinitialize the system. ¯\_(ツ)_/¯ 
        //
        // For now I think this seems to be the most logical place... 

        Core::File file(m_storeLocation);
        if(file.Exists() == false){
            InitializeSystem();
        }

        *f_ppiMediaKeySession = new CDMi::MediaKeySession(
            f_pbInitData, f_cbInitData, 
            f_pbCDMData, f_cbCDMData, 
            m_drmOemContext, m_poAppContext.get()
            );

        return CDMi_SUCCESS; 
    }

    CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        return CDMi_S_FALSE;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession *f_piMediaKeySession) {
        SafeCriticalSection systemLock(drmAppContextMutex_);
        MediaKeySession * mediaKeySession = dynamic_cast<MediaKeySession *>(f_piMediaKeySession);
        ASSERT((mediaKeySession != nullptr) && "Expected a locally allocated MediaKeySession");

        delete f_piMediaKeySession;
        f_piMediaKeySession= nullptr;

        return CDMi_SUCCESS;
    }

public:
    // Ext interface.
    virtual uint64_t GetDrmSystemTime() const{
        // Playready3 supports client time completely within the opaque blobs sent
        // between the Playready client and server, so this function should really
        // not have to return a real time. However, the Netflix server still needs
        // a good client time for legacy reasons.
        // In this reference DPI we are cheating my just returning the linux system
        // time. A real implementation would be more complicated, perhaps getting
        // time from some sort of secure and/or anti-rollback resource.
        return static_cast<uint64_t>(time(NULL));
    }
    
    std::string GetVersionExt() const override
    {
        const uint32_t MAXLEN = 64;
        DRM_CHAR versionStr[MAXLEN];
        if (g_dstrReqTagPlayReadyClientVersionData.cchString >= MAXLEN)
            return std::string();
        DRM_UTL_DemoteUNICODEtoASCII(g_dstrReqTagPlayReadyClientVersionData.pwszString,
                versionStr, MAXLEN);
        ((DRM_BYTE*)versionStr)[g_dstrReqTagPlayReadyClientVersionData.cchString] = 0;
        PackedCharsToNative(versionStr, g_dstrReqTagPlayReadyClientVersionData.cchString + 1);
        LOGGER(LINFO_, "Version %s.", versionStr);
        
        //return std::string("2.5.0.0000");        
        return std::string(versionStr);
    }

    uint32_t GetLdlSessionLimit() const override
    {
        return NONCE_STORE_SIZE;
    }

    bool IsSecureStopEnabled() override
    {
        // methode not used for Playready3
        return true;
    }

    CDMi_RESULT EnableSecureStop(bool enable) override
    {
        // methode not used for Playready3
        return CDMi_SUCCESS;
    }

    uint32_t ResetSecureStops() override
    {
        // methode not used for Playready3
        return 0;
    }

    CDMi_RESULT GetSecureStopIds(uint8_t ids[], uint16_t idsLength, uint32_t & count)
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        CDMi_RESULT cr = CDMi_SUCCESS;

        DRM_ID *ssSessionIds = nullptr;

        DRM_RESULT dr;
        dr = Drm_SecureStop_EnumerateSessions(
                m_poAppContext.get(),
                m_meteringCertificateSize, //playready3MeteringCertSize,
                m_meteringCertificate,     //playready3MeteringCert,
                &count,
                &ssSessionIds);

        if (dr != DRM_SUCCESS && dr != DRM_E_NOMORE) {
            LOGGER(LERROR_, "Error in Drm_SecureStop_EnumerateSessions (error: 0x%08X)", static_cast<unsigned int>(dr));
            cr = CDMi_S_FALSE;
        } else {                 
            for (uint32_t i = 0; i < count; ++i)
            {
                ASSERT(sizeof(ssSessionIds[i].rgb) == DRM_ID_SIZE);
                memcpy(&ids[i * DRM_ID_SIZE], ssSessionIds[i].rgb, DRM_ID_SIZE);
            }

            if (count) {
                LOGGER(LINFO_, "Found %d pending secure stop%s", count, (count > 1) ? "s" : "");
            }
        }
        
        SAFE_OEM_FREE(ssSessionIds);

        return cr;
    }

    CDMi_RESULT GetSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            uint8_t * rawData,
            uint16_t & rawSize)
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        CDMi_RESULT cr = CDMi_SUCCESS;

        // Get the secure stop challenge
        DRM_ID ssSessionDrmId;
        ASSERT(sizeof(ssSessionDrmId.rgb) >= sessionIDLength);
        memcpy(ssSessionDrmId.rgb, sessionID, sessionIDLength);

        DRM_DWORD ssChallengeSize;
        DRM_BYTE *ssChallenge;

        DRM_RESULT dr = Drm_SecureStop_GenerateChallenge(
                m_poAppContext.get(),
                &ssSessionDrmId,
                m_meteringCertificateSize, //playready3MeteringCertSize,
                m_meteringCertificate,     //playready3MeteringCert,
                0, nullptr, // no custom data
                &ssChallengeSize,
                &ssChallenge);

        if (dr != DRM_SUCCESS) {
            LOGGER(LERROR_, "Error in Drm_SecureStop_GenerateChallenge (error: 0x%08X)", static_cast<unsigned int>(dr));
            cr = CDMi_S_FALSE;
        } else {
            if((rawData != nullptr) && (rawSize >= ssChallengeSize)){
                memcpy(rawData, ssChallenge, ssChallengeSize);
            } 
            rawSize = ssChallengeSize; 
        }

        return cr;
    }

    CDMi_RESULT CommitSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            const uint8_t serverResponse[],
            uint32_t serverResponseLength) override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        CDMi_RESULT cr = CDMi_SUCCESS;

        if (sessionIDLength == 0) {
            LOGGER(LERROR_, "Error: empty session id");
            cr = CDMi_S_FALSE;
        }
        if (serverResponseLength  == 0) {
            cr = CDMi_S_FALSE;
        }

        if (cr == CDMi_SUCCESS){
            DRM_ID sessionDrmId;
            ASSERT(sizeof(sessionDrmId.rgb) >= sessionIDLength);
            memcpy(sessionDrmId.rgb, sessionID, sessionIDLength);

            DRM_DWORD customDataSizeBytes = 0;
            DRM_CHAR *pCustomData = NULL;
            
            DRM_RESULT dr;
            dr = Drm_SecureStop_ProcessResponse(
                m_poAppContext.get(),
                &sessionDrmId,
                m_meteringCertificateSize, //playready3MeteringCertSize,
                m_meteringCertificate,     //playready3MeteringCert,
                serverResponseLength,
                serverResponse,
                &customDataSizeBytes,
                &pCustomData);
            if (dr == DRM_SUCCESS)
            {
                LOGGER(LINFO_, "secure stop commit successful");
                if (pCustomData && customDataSizeBytes)
                {
                    // We currently don't use custom data from the server. Just log here.
                    std::string customDataStr(pCustomData, customDataSizeBytes);
                    LOGGER(LINFO_, "custom data = \"%s\"", customDataStr.c_str());
                }
            }
            else
            {
                LOGGER(LERROR_, "Drm_SecureStop_ProcessResponse returned 0x%lx", static_cast<unsigned long>(dr));
            }

            SAFE_OEM_FREE(pCustomData);
        }

        return cr;
    }

    bool LoadRevocationList(const char *revListFile)
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
                m_poAppContext.get(),
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

    #define MAX_TIME_CHALLENGE_RESPONSE_LENGTH (1024*64)
    #define MAX_URL_LENGTH (512)

    int InitSecureClock(DRM_APP_CONTEXT *pDrmAppCtx)
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
        SAFE_OEM_FREE(pbChallenge);

        if (pTimeChallengeURL != nullptr) {
            NEXUS_Memory_Free(pTimeChallengeURL);
        }

        if (pbResponse != nullptr) {
            NEXUS_Memory_Free(pbResponse);
        }

        return rc;
    }

    CDMi_RESULT CreateSystemExt()
    {
        CDMi_RESULT cr = CDMi_SUCCESS;
        DRM_RESULT dr = DRM_SUCCESS;

        DRM_CONST_STRING dstrHDSPath = DRM_EMPTY_DRM_STRING;
        
        DRMFILETIME               ftSystemTime; /* Initialized by Drm_SecureTime_GetValue */
        DRM_SECURETIME_CLOCK_TYPE eClockType;   /* Initialized by Drm_SecureTime_GetValue */

        DRM_DWORD dwEncryptionMode  = OEM_TEE_DECRYPTION_MODE_NOT_SECURE;

        LOGGER(LINFO_, "Creating System Ext, Build: %s", __TIMESTAMP__ );

        std::string rdir(m_readDir);

        // Create wchar strings from the arguments.
        drmdir_ = createDrmWchar(rdir);

        // Initialize Ocdm directory.
        g_dstrDrmPath.pwszString = drmdir_;
        g_dstrDrmPath.cchString = rdir.length();

        m_poAppContext.reset(new DRM_APP_CONTEXT);
        memset(m_poAppContext.get(), 0, sizeof(DRM_APP_CONTEXT));

        m_pbOpaqueBuffer = (DRM_BYTE *)Oem_MemAlloc(MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE);
        m_cbOpaqueBuffer = MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE;
        
        // Store store location
        dstrHDSPath.pwszString =  createDrmWchar(m_storeLocation);
        dstrHDSPath.cchString = m_storeLocation.length();

        dr  = Drm_Initialize(m_poAppContext.get(), 
                            m_drmOemContext,
                            m_pbOpaqueBuffer,
                            m_cbOpaqueBuffer,
                            &dstrHDSPath);

        if(DRM_FAILED(dr)) {
            LOGGER(LERROR_, "Error in Drm_Initialize: 0x%08lX\n", dr);
            goto ErrorExit;
        }

            dr = Drm_SecureTime_GetValue( m_poAppContext.get(), &ftSystemTime, &eClockType  );
            if( (dr == DRM_E_SECURETIME_CLOCK_NOT_SET) || (dr == DRM_E_TEE_PROVISIONING_REQUIRED) )
            {
                /* setup the Playready secure clock */
                if(InitSecureClock(m_poAppContext.get()) != 0)
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

                if(Drm_AntiRollBackClock_Init(m_poAppContext.get(), &systemTime) != 0)
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
        dr = Drm_ResizeInMemoryLicenseStore(m_poAppContext.get(), MAX_NUM_LICENSES * LICENSE_SIZE_BYTES);
        if (DRM_FAILED(dr)) {
            LOGGER(LERROR_,  "Error in Drm_ResizeInMemoryLicenseStore 0x%08lX", dr);
            goto ErrorExit;
        }

        if (DRM_REVOCATION_IsRevocationSupported())
        {
            ChkMem(m_pbRevocationBuffer = (DRM_BYTE *)Oem_MemAlloc(REVOCATION_BUFFER_SIZE));

            ChkDR(Drm_Revocation_SetBuffer(m_poAppContext.get(),
                                        m_pbRevocationBuffer,
                                        REVOCATION_BUFFER_SIZE));

            if( !LoadRevocationList(DRM_DEFAULT_REVOCATION_LIST_FILE))
            {
                LOGGER(LERROR_,  "Error in Drm_Revocation_SetBuffer 0x%08lX", dr);
                goto ErrorExit;
            }
        }

            /* set encryption/decryption mode */
            dwEncryptionMode = OEM_TEE_DECRYPTION_MODE_HANDLE;
            ChkDR(Drm_Content_SetProperty(
                    m_poAppContext.get(),
                    DRM_CSP_DECRYPTION_OUTPUT_MODE,
                    (const DRM_BYTE*)&dwEncryptionMode,
                    sizeof( DRM_DWORD ) ) );
    ErrorExit:
        if (DRM_FAILED(dr)) {
            m_poAppContext.reset();
            cr =  CDMi_S_FALSE;
            LOGGER(LERROR_,  "Error in creating system ext,  0x%08lX", dr);
        }

        return cr;
    }

    CDMi_RESULT DeleteKeyStore() override
    {
        // There is no keyfile in PlayReady3, so we cannot implement this function.
        return CDMi_SUCCESS;
    }

    CDMi_RESULT DeleteSecureStore() override
    {
        SafeCriticalSection lock(drmAppContextMutex_);
        
        // As a linux reference implementation, we are cheating a bit by just using
        // stdio to delete the drm store from the filesystem. A real implementation
        // will be more complicated.

        if (remove(m_storeLocation.c_str()) != 0) {
            LOGGER(LINFO_, "Error removing DRM store file");
        }

        return CDMi_SUCCESS;
    }

    CDMi_RESULT GetKeyStoreHash(
            uint8_t keyStoreHash[],
            uint32_t keyStoreHashLength) override
    {
        // There is no keyfile in PlayReady3, so we cannot implement this function.
        return CDMi_SUCCESS;
    }

    CDMi_RESULT GetSecureStoreHash(
            uint8_t secureStoreHash[],
            uint32_t secureStoreHashLength) override
    {
        SafeCriticalSection lock(drmAppContextMutex_);

        if (calcFileSha256(m_storeLocation, secureStoreHash, secureStoreHashLength) == false)
        {
            LOGGER(LERROR_, "Error: calcFileSha256 failed");
            return CDMi_S_FALSE;
        }

        return CDMi_SUCCESS;
    }

private:
    DRM_WCHAR* drmdir_;

    DRM_VOID *m_drmOemContext;
    NxClient_AllocResults m_nxAllocResults;

    DRM_WCHAR* m_drmDirectory;
    DRM_CONST_STRING m_drmStore;

    DRM_BYTE *m_pbOpaqueBuffer;
    DRM_DWORD m_cbOpaqueBuffer;

    DRM_BYTE *m_pbRevocationBuffer ;
    std::unique_ptr<DRM_APP_CONTEXT> m_poAppContext;

    std::string m_readDir;
    std::string m_storeLocation;

    DRM_BYTE* m_meteringCertificate;
    uint32_t m_meteringCertificateSize;
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
