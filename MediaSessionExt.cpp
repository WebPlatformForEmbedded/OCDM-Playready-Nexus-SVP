/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include "MediaSession.h"

#include <drmbytemanip.h>
#include <drmsecurestoptypes.h>
#include <drmconstants.h>

#include <iostream>
#include <stdio.h>
#include <sstream>
#include <byteswap.h>

using SafeCriticalSection = WPEFramework::Core::SafeSyncType<WPEFramework::Core::CriticalSection>;
extern WPEFramework::Core::CriticalSection drmAppContextMutex_;

namespace CDMi {
const DRM_CONST_STRING  *g_rgpdstrRightsExt[1] = {&g_dstrWMDRM_RIGHT_PLAYBACK};

struct CallbackInfo
{
    IMediaKeySessionCallback * _callback;
    uint16_t _compressedVideo;
    uint16_t _uncompressedVideo;
    uint16_t _analogVideo;
    uint16_t _compressedAudio;
    uint16_t _uncompressedAudio;
    uint32_t _maxDecodeWidth;
    uint32_t _maxDecodeHeight;
};

static void * PlayLevelUpdateCallback(void * data)
{
    CallbackInfo * callbackInfo = static_cast<CallbackInfo *>(data);

    std::stringstream keyMessage;
    keyMessage << "{";
    keyMessage << "\"compressed-video\": " << callbackInfo->_compressedVideo << ",";
    keyMessage << "\"uncompressed-video\": " << callbackInfo->_uncompressedVideo << ",";
    keyMessage << "\"analog-video\": " << callbackInfo->_analogVideo << ",";
    keyMessage << "\"compressed-audio\": " << callbackInfo->_compressedAudio << ",";
    keyMessage << "\"uncompressed-audio\": " << callbackInfo->_uncompressedAudio << ",";
    keyMessage << "\"max-decode-width\": " << callbackInfo->_maxDecodeWidth << ",";
    keyMessage << "\"max-decode-height\": " << callbackInfo->_maxDecodeHeight;
    keyMessage << "}";

    std::string keyMessageStr = keyMessage.str();
    const uint8_t * messageBytes = reinterpret_cast<const uint8_t *>(keyMessageStr.c_str());

    char urlBuffer[64];
    strcpy(urlBuffer, "properties");
    callbackInfo->_callback->OnKeyMessage(messageBytes, keyMessageStr.length() + 1, urlBuffer);

    delete callbackInfo;
    return nullptr;
}

void UpdateSession(const MediaKeySession::DecryptContext* decryptContext)
{
    if (decryptContext->callback != nullptr) {
        CallbackInfo * callbackInfo = new CallbackInfo;
        callbackInfo->_callback = const_cast<IMediaKeySessionCallback *>(decryptContext->callback);
        callbackInfo->_compressedVideo = decryptContext->outputProtection.compressedDigitalVideoLevel;
        callbackInfo->_uncompressedVideo = decryptContext->outputProtection.uncompressedDigitalVideoLevel;
        callbackInfo->_analogVideo = decryptContext->outputProtection.analogVideoLevel;
        callbackInfo->_compressedAudio = decryptContext->outputProtection.compressedDigitalAudioLevel;
        callbackInfo->_uncompressedAudio = decryptContext->outputProtection.uncompressedDigitalAudioLevel;
        callbackInfo->_maxDecodeWidth = decryptContext->outputProtection.maxResDecodeWidth;
        callbackInfo->_maxDecodeHeight = decryptContext->outputProtection.maxResDecodeHeight;

        // Run on a new thread, so we don't go too deep in the IPC callstack.
        pthread_t threadId;
        pthread_create(&threadId, nullptr, PlayLevelUpdateCallback, callbackInfo);
    } 
}

DRM_RESULT opencdm_output_levels_callback(
    const DRM_VOID *outputLevels, 
    DRM_POLICY_CALLBACK_TYPE callbackType,    
    const DRM_KID */*f_pKID*/,
    const DRM_LID */*f_pLID*/,
    const DRM_VOID *data) {
    // We only care about the play callback.
    if (callbackType != DRM_PLAY_OPL_CALLBACK){
        return DRM_SUCCESS;
    } 

    MediaKeySession::DecryptContext * const decryptContext = const_cast<MediaKeySession::DecryptContext *>(static_cast<const MediaKeySession::DecryptContext*>(data));
    const DRM_PLAY_OPL_EX2 * const opl = static_cast<const DRM_PLAY_OPL_EX2 *>(outputLevels);

    ASSERT(opl->dwVersion == 0);

    decryptContext->outputProtection.setOutputLevels(opl->minOPL);

    // MaxRes Decode
    const DRM_VIDEO_OUTPUT_PROTECTION_IDS_EX &dvopi = opl->dvopi;
    for (size_t i = 0; i < dvopi.cEntries; ++i)
    {
        const DRM_OUTPUT_PROTECTION_EX &dope = dvopi.rgVop[i];
        if (DRM_IDENTICAL_GUIDS(&dope.guidId, &g_guidMaxResDecode))
        {
            ASSERT(dope.dwVersion == 3);
            uint32_t mrdWidth, mrdHeight;
            const int inc = sizeof(uint32_t);
            ASSERT(dope.cbConfigData >= 2*inc);
            std::copy(&dope.rgbConfigData[0],   &dope.rgbConfigData[0]   + inc, reinterpret_cast<uint8_t*>(&mrdWidth));
            std::copy(&dope.rgbConfigData[inc], &dope.rgbConfigData[inc] + inc, reinterpret_cast<uint8_t*>(&mrdHeight));
            #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                mrdWidth  = bswap_32(mrdWidth);
                mrdHeight = bswap_32(mrdHeight);
            #endif
            decryptContext->outputProtection.setMaxResDecode(mrdWidth, mrdHeight);
            printf("%s MaxResDecode: width : %d\theight: %d\n", __FUNCTION__,
                decryptContext->outputProtection.maxResDecodeWidth, 
                decryptContext->outputProtection.maxResDecodeHeight);
            break;
        }
    }
    
    UpdateSession(decryptContext);

    // All done.
    return DRM_SUCCESS;
}

uint32_t MediaKeySession::GetSessionIdExt() const
{
    return m_SessionId;
}

CDMi_RESULT MediaKeySession::SetDrmHeader(const uint8_t drmHeader[], uint32_t drmHeaderLength)
{
    mDrmHeader.resize(drmHeaderLength);
    memcpy(&mDrmHeader[0], drmHeader, drmHeaderLength);
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::StoreLicenseData(const uint8_t licenseData[], uint32_t licenseDataSize, uint8_t * secureStopId)
{
    // open scope for DRM_APP_CONTEXT mutex
    SafeCriticalSection systemLock(drmAppContextMutex_);

    //const std::string licStr(licenseData.begin(), licenseData.end());
    //LOGGER(LINFO_, "\n%s", licStr.c_str());

    // === Store the license and check for license processing errors.
    //
    // NOTE: Drm_LicenseAcq_ProcessResponse() is the PR3 API that creates a
    // secure stop. There is one secure stop per license response, regardless of
    // how many licenses are in the response data.
    //
    DRM_LICENSE_RESPONSE drmLicenseResponse;
    // MUST zero the input DRM_LICENSE_RESPONSE struct!
    ZEROMEM(&drmLicenseResponse, sizeof(DRM_LICENSE_RESPONSE));
    DRM_RESULT err;
    // Non-persistent licenses (the kind in use) have no signature, so the
    // LIC_RESPONSE_SIGNATURE_NOT_REQUIRED flag must be used.
    err = Drm_LicenseAcq_ProcessResponse(
            m_poAppContext,
            DRM_PROCESS_LIC_RESPONSE_SIGNATURE_NOT_REQUIRED,
            &licenseData[0],
            (DRM_DWORD)licenseDataSize,
            &drmLicenseResponse);

    if((m_piCallback != nullptr) && DRM_SUCCEEDED(err)) {
        for (uint8_t i = 0; i < drmLicenseResponse.m_cAcks; ++i) {
            if (DRM_SUCCEEDED(drmLicenseResponse.m_rgoAcks[i].m_dwResult)) {
                ToggleKeyIdFormat(DRM_ID_SIZE, drmLicenseResponse.m_rgoAcks[i].m_oKID.rgb);
                m_piCallback->OnKeyStatusUpdate("KeyUsable", drmLicenseResponse.m_rgoAcks[i].m_oKID.rgb, DRM_ID_SIZE);
            }
        }
        m_piCallback->OnKeyStatusesUpdated();
    }

    // First, check the return code of Drm_LicenseAcq_ProcessResponse()
    if (err ==  DRM_E_LICACQ_TOO_MANY_LICENSES) {
        // This means the server response contained more licenses than
        // DRM_MAX_LICENSE_ACK (usually 20). Should allocate space and retry.
        // FIXME NRDLIB-4481: This will need to be implemented when we start
        // using batch license requests.
        LOGGER(LERROR_, "Drm_LicenseAcq_ProcessResponse too many licenses in response.");
        return CDMi_S_FALSE;
    }
    else if (DRM_FAILED(err)) {
        LOGGER(LERROR_, "Drm_LicenseAcq_ProcessResponse failed (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    // Next, examine the returned drmLicenseResponse struct for a top-level error.
    if (DRM_FAILED(drmLicenseResponse.m_dwResult)) {
        LOGGER(LERROR_, "Error in DRM_LICENSE_RESPONSE");
        return CDMi_S_FALSE;
    }

    // Finally, ensure that each license in the response was processed
    // successfully.
    const DRM_DWORD nLicenses = drmLicenseResponse.m_cAcks;
    for (uint32_t i=0; i < nLicenses; ++i)
    {
        LOGGER(LINFO_, "Checking license %d", i);
        if (DRM_FAILED(drmLicenseResponse.m_rgoAcks[i].m_dwResult)) {
            // Special handling for DRM_E_DST_STORE_FULL. If this error is
            // detected for any license, reset the DRM appcontext and return error.
            if (drmLicenseResponse.m_rgoAcks[i].m_dwResult == DRM_E_DST_STORE_FULL) {
                LOGGER(LINFO_, "Found DRM_E_DST_STORE_FULL error in license %d, reinitializing!", i);
                
                err = Drm_Reinitialize(m_poAppContext);
                if (DRM_FAILED(err))
                {
                    LOGGER(LERROR_, "Error: Drm_Reinitialize returned (error: 0x%08X)", static_cast<unsigned int>(err));
                    return CDMi_S_FALSE;
                }

            }
            else {
                LOGGER(LERROR_, "Error 0x%08lX found in license %d", (unsigned long)drmLicenseResponse.m_rgoAcks[i].m_dwResult, i);
            }
            return CDMi_S_FALSE;
        }
    }

    // === Extract various ID's from drmLicenseResponse
    //
    // There are 3 ID's in the processed license response we are interested in:
    // BID - License batch ID. A GUID that uniquely identifies a batch of
    //       licenses that were processed in one challenge/response transaction.
    //       The BID is a nonce unique to the transaction. If the transaction
    //       contains a single license, this is identical to the license nonce.
    //       The secure stop ID is set to the BID value.
    // KID - Key ID. A GUID that uniquely identifies the media content key. This
    //       is the primary index for items in the license store. There can be
    //       multiple licenses with the same KID.
    // LID - License ID. A GUID that uniquely identifies a license. This is the
    //       secondary index for items in the license store.
    // When there are multiple licenses in the server response as in the PRK
    // case, there are correspondingly multiple KID/LID entries in the processed
    // response. There is always only a single BID per server response.

    // BID
    mBatchId = drmLicenseResponse.m_oBatchID; 
    PrintBase64(sizeof(mBatchId.rgb), mBatchId.rgb, "BatchId/SecureStopId");

    // Microsoft says that a batch ID of all zeros indicates some sort of error
    // for in-memory licenses. Hopefully this error was already caught above.
    const uint8_t zeros[sizeof(mBatchId.rgb)] = { 0 };
    if(memcmp(mBatchId.rgb, zeros, sizeof(mBatchId.rgb)) == 0){
        LOGGER(LERROR_, "No batch ID in processed response");
        return CDMi_S_FALSE;
    }
    // We take the batch ID as the secure stop ID
    memcpy(secureStopId, mBatchId.rgb, sizeof(mBatchId.rgb));

    // KID and LID
    LOGGER(LINFO_, "Found %d license%s in server response for :", nLicenses, (nLicenses > 1) ? "s" : "");
    for (uint32_t i=0; i < nLicenses; ++i)
    {
        const DRM_LICENSE_ACK * const licAck = &drmLicenseResponse.m_rgoAcks[i];
        LOGGER(LINFO_, "KID/LID[%d]:", i);
        PrintBase64(sizeof(licAck->m_oLID.rgb), licAck->m_oLID.rgb, "LID");
        PrintBase64(sizeof(licAck->m_oKID.rgb), licAck->m_oKID.rgb, "KID");
    }

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::SelectKeyId(const uint8_t keyLength, const uint8_t keyId[])
{
    // open scope for DRM_APP_CONTEXT mutex
    SafeCriticalSection systemLock(drmAppContextMutex_);
    ASSERT(m_poAppContext != nullptr);
    ASSERT(keyLength == DRM_ID_SIZE);
    
    DRM_RESULT err;
    uint8_t keyParam[keyLength];
    CDMi_RESULT result = CDMi_SUCCESS;
    // Seems like we no longer have to worry about invalid app context, make sure with this ASSERT.
    memcpy(keyParam, keyId, keyLength);

    ToggleKeyIdFormat(keyLength, keyParam);

    std::vector<uint8_t> keyIdVec(keyParam, keyParam + keyLength);
    // Select the license in the current DRM header by keyId

    DecryptContextMap::iterator index = mDecryptContextMap.find(keyIdVec);
    // switch from CENC to PlayReady format
    if ((index != mDecryptContextMap.end()) && (index->second.get())) {

        PrintBase64(sizeof(keyIdVec), &keyIdVec[0], 
                        "Found existing decrypt context for keyId");
        m_oDecryptContext = &(index->second->drmDecryptContext);
        UpdateSession(index->second.get());
    }
    else {
        if (SelectDrmHeader(m_poAppContext, mDrmHeader.size(), &mDrmHeader[0]) != CDMi_SUCCESS){
        return CDMi_S_FALSE;
        }

        if (SetKeyId(m_poAppContext, sizeof(keyParam), keyParam) != CDMi_SUCCESS){
            return CDMi_S_FALSE;
        }

        std::shared_ptr<DecryptContext> newDecryptContext(new DecryptContext(m_piCallback));

        LOGGER(LINFO_, "Drm_Reader_Bind");
        err = Drm_Reader_Bind(
                m_poAppContext,
                g_rgpdstrRightsExt,
                DRM_NO_OF(g_rgpdstrRightsExt),
                &opencdm_output_levels_callback, 
                static_cast<const void*>(newDecryptContext.get()),
                &(newDecryptContext->drmDecryptContext));
        if (DRM_FAILED(err))
        {
            LOGGER(LERROR_, "Error: Drm_Reader_Bind (error: 0x%08X)", static_cast<unsigned int>(err));
            return CDMi_S_FALSE;
        }

        // Commit all secure store transactions to the DRM store file. For the
        // Netflix use case, Drm_Reader_Commit only needs to be called after
        // Drm_Reader_Bind.
        LOGGER(LINFO_,"Drm_Reader_Commit");
        err = Drm_Reader_Commit(m_poAppContext, &opencdm_output_levels_callback, static_cast<const void*>(newDecryptContext.get()));
        if (DRM_FAILED(err))
        {
            LOGGER(LERROR_, "Error: Drm_Reader_Commit (error: 0x%08X)", static_cast<unsigned int>(err));
            return CDMi_S_FALSE;
        }

        // Save the new decryption context to our member map, and make it the
        // active one.
        if (index != mDecryptContextMap.end()) {
            index->second = newDecryptContext;
        } else {
            mDecryptContextMap.insert(std::make_pair(keyIdVec, newDecryptContext));
        }
        
        m_oDecryptContext =  &(newDecryptContext->drmDecryptContext);  
    }
    
    if (result == CDMi_SUCCESS) {
        m_fCommit = TRUE;
        m_eKeyState = KEY_READY;
        LOGGER(LINFO_, "Key processed, now ready for content decryption");
    }

    return result;
}

CDMi_RESULT MediaKeySession::CancelChallengeDataExt()
{
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CleanDecryptContext()
{
    SafeCriticalSection systemLock(drmAppContextMutex_);
    
    CleanDecryptContexts();

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::GetChallengeDataExt(uint8_t * challenge, uint32_t & challengeSize, uint32_t /* isLDL */)
{
    SafeCriticalSection systemLock(drmAppContextMutex_);

    // sanity check for drm header
    if (mDrmHeader.size() == 0) {
        LOGGER(LERROR_, "Error: No valid DRM header");
        return CDMi_S_FALSE;
    }

    DRM_RESULT err;

    // Seems like we no longer have to worry about invalid app context, make sure with this ASSERT.
    ASSERT(m_poAppContext != nullptr);

    // Set this session's DMR header in the PR3 app context.
     if (SelectDrmHeader(m_poAppContext, mDrmHeader.size(), &mDrmHeader[0]) != CDMi_SUCCESS){
        return CDMi_S_FALSE;
    }

    // PlayReady doesn't like valid pointer + size 0
    DRM_BYTE* passedChallenge = static_cast<DRM_BYTE*>(challenge);
    if (challengeSize == 0) {
        passedChallenge = nullptr;
    }

    // Find the size of the challenge.
    err = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                            g_rgpdstrRightsExt,
                                            DRM_NO_OF(g_rgpdstrRightsExt),
                                            nullptr,
                                            nullptr,
                                            0,
                                            nullptr,
                                            nullptr,
                                            nullptr,
                                            nullptr,
                                            passedChallenge, 
                                            &challengeSize,
                                            nullptr);

    if ((err != DRM_E_BUFFERTOOSMALL) && (DRM_FAILED(err))){
        LOGGER(LERROR_, "Error: Drm_LicenseAcq_GenerateChallenge (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    if ((passedChallenge != nullptr) && (err == DRM_E_BUFFERTOOSMALL)){
        LOGGER(LERROR_, "Error: Drm_LicenseAcq_GenerateChallenge (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_OUT_OF_MEMORY ;
    }

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::SetKeyId(DRM_APP_CONTEXT *pDrmAppCtx, const uint8_t keyLength, const uint8_t keyId[]){
    // To use the DRM_CSP_SELECT_KID feature of Drm_Content_SetProperty(), the
    // KID must be base64-encoded for some reason.
    DRM_WCHAR rgwchEncodedKid[CCH_BASE64_EQUIV(DRM_ID_SIZE)]= {0};
    DRM_DWORD cchEncodedKid = CCH_BASE64_EQUIV(DRM_ID_SIZE);
    
    DRM_RESULT err = DRM_B64_EncodeW(&keyId[0], sizeof(DRM_KID), rgwchEncodedKid, &cchEncodedKid, 0);
    if (DRM_FAILED(err)) {
        LOGGER(LERROR_, "Error: Error base64-encoding KID (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    PrintBase64(DRM_ID_SIZE, keyId, "keyId");

    LOGGER(LINFO_, "Drm_Content_SetProperty DRM_CSP_SELECT_KID");
    err = Drm_Content_SetProperty(
            pDrmAppCtx,
            DRM_CSP_SELECT_KID,
            (DRM_BYTE*)rgwchEncodedKid,
            sizeof(rgwchEncodedKid));
    if (DRM_FAILED(err)) {
        LOGGER(LERROR_, "Error in Drm_Content_SetProperty DRM_CSP_SELECT_KID (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }
    
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::SelectDrmHeader(DRM_APP_CONTEXT *pDrmAppCtx, 
    const uint32_t headerLength, const uint8_t header[])
{
    // Make the current app context contain the DRM header for this session.
    LOGGER(LINFO_, "Drm_Content_SetProperty DRM_CSP_AUTODETECT_HEADER");
    DRM_RESULT err = Drm_Content_SetProperty(
            pDrmAppCtx,
            DRM_CSP_AUTODETECT_HEADER,
            header,
            headerLength);
    if (DRM_FAILED(err)) {
        LOGGER(LERROR_, "Error: Drm_Content_SetProperty DRM_CSP_AUTODETECT_HEADER (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    return CDMi_SUCCESS;
}
}
