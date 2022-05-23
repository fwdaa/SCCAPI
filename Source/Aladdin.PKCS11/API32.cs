using System;
using System.Runtime.InteropServices;

///////////////////////////////////////////////////////////////////////////
// Определение простых типов
///////////////////////////////////////////////////////////////////////////
using CK_BBOOL          = System.Byte; 
using CK_BYTE           = System.Byte; 
using CK_CHAR           = System.Byte; 
using CK_UTF8CHAR       = System.Byte; 
using CK_VOID_PTR       = System.IntPtr; 
using CK_BYTE_PTR       = System.IntPtr; 
using CK_UTF8CHAR_PTR   = System.IntPtr; 
using CK_ATTRIBUTE_PTR  = System.IntPtr; 
using CK_LONG           = System.Int32; 
using CK_ULONG          = System.UInt32; 
using CK_RV             = System.UInt32; 
using CK_FLAGS          = System.UInt32; 
using CK_SLOT_ID        = System.UInt32; 
using CK_USER_TYPE      = System.UInt32; 
using CK_ATTRIBUTE_TYPE = System.UInt32; 
using CK_MECHANISM_TYPE = System.UInt32; 
using CK_SESSION_STATE  = System.UInt32; 
using CK_SESSION_HANDLE = System.UInt32; 
using CK_OBJECT_HANDLE  = System.UInt32; 
using CK_NOTIFICATION   = System.UInt32; 

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Интерфейс PKCS11
    ///////////////////////////////////////////////////////////////////////////
    public static class API32
    { 
        ///////////////////////////////////////////////////////////////////////
        // Функции обратного вызова
        ///////////////////////////////////////////////////////////////////////
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_CREATEMUTEX(
            [    Out] out CK_VOID_PTR   ppMutex               // location to receive ptr to mutex
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DESTROYMUTEX(
            [In     ] CK_VOID_PTR       pMutex                // pointer to mutex
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_LOCKMUTEX(
            [In     ] CK_VOID_PTR       pMutex                // pointer to mutex
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_UNLOCKMUTEX(
            [In     ] CK_VOID_PTR       pMutex                // pointer to mutex
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_NOTIFY(
            [In     ] CK_SESSION_HANDLE hSession,             // the session's handle
            [In     ] CK_NOTIFICATION   notification,
            [In     ] CK_VOID_PTR       pApplication          // passed to C_OpenSession
        );
        ///////////////////////////////////////////////////////////////////////
        // Параметры настройки библиотеки
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_C_INITIALIZE_ARGS {
            public CK_CREATEMUTEX  CreateMutex;
            public CK_DESTROYMUTEX DestroyMutex;
            public CK_LOCKMUTEX    LockMutex;
            public CK_UNLOCKMUTEX  UnlockMutex;
            public CK_FLAGS        Flags;
            public CK_VOID_PTR     Reserved;
        };
        ///////////////////////////////////////////////////////////////////////
        // Определения функций
        ///////////////////////////////////////////////////////////////////////
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETFUNCTIONLIST(
            [Out] out CK_VOID_PTR ppFunctionList
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_INITIALIZE(
            [In     ] IntPtr                            pInitArgs
        ); 
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_FINALIZE(
            [In     ] CK_VOID_PTR                       pReserved                   // reserved.  Should be NULL_PTR
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETINFO(
            [    Out] out CK_INFO                       pInfo                       // location that receives information
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETSLOTLIST(
            [In     ] CK_BBOOL                          tokenPresent,               // only slots with tokens?
            [In, Out] CK_SLOT_ID[]                      slotList,                   // receives array of slot IDs
            [In, Out] ref CK_LONG                       pulCount                    // receives number of slots
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETSLOTINFO(
            [In     ] CK_SLOT_ID                        slotID,                     // the ID of the slot
            [    Out] out CK_SLOT_INFO                  pInfo                       // receives the slot information
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_WAITFORSLOTEVENT(
            [In     ] CK_FLAGS                          flags,                      // blocking/nonblocking flag
            [In, Out] ref CK_SLOT_ID                    pSlot,                      // location that receives the slot ID
            [In     ] CK_VOID_PTR                       pReserved                   // reserved.  Should be NULL_PTR 
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETTOKENINFO(
            [In     ] CK_SLOT_ID                        slotID,                     // ID of the token's slot 
            [    Out] out CK_TOKEN_INFO                 pInfo                       // receives the token information 
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETMECHANISMLIST(
            [In     ] CK_SLOT_ID                        slotID,                     // ID of token's slot
            [In, Out] CK_MECHANISM_TYPE[]               mechanismList,              // gets mech. array 
            [In, Out] ref CK_LONG                       pulCount                    // gets # of mechs. 
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETMECHANISMINFO(
            [In     ] CK_SLOT_ID                        slotID,                     // ID of the token's slot
            [In     ] CK_MECHANISM_TYPE                 type,                       // type of mechanism 
            [    Out] out CK_MECHANISM_INFO             pInfo                       // receives mechanism info
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_INITTOKEN(
            [In     ] CK_SLOT_ID                        slotID,                     // ID of the token's slot
            [In     ] CK_UTF8CHAR[]                     pPin,                       // the SO's initial PIN
            [In     ] CK_LONG                           ulPinLen,                   // length in bytes of the PIN
            [In     ] CK_UTF8CHAR[]                     pLabel                      // 32-byte token label (blank padded)
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_OPENSESSION(
            [In     ] CK_SLOT_ID                        slotID,                     // the slot's ID 
            [In     ] CK_FLAGS                          flags,                      // from CK_SESSION_INFO
            [In     ] CK_VOID_PTR                       pApplication,               // passed to callback 
            [In     ] CK_NOTIFY                         Notify,                     // callback function 
            [    Out] out CK_SESSION_HANDLE             phSession                   // gets session handle 
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_CLOSESESSION(
            [In     ] CK_SESSION_HANDLE                 hSession                    // the session's handle
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_CLOSEALLSESSIONS(
            [In     ] CK_SLOT_ID                        slotID                      // the token's slot
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETSESSIONINFO(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [    Out] out CK_SESSION_INFO               pInfo                       // receives session info
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETOPERATIONSTATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In, Out] CK_BYTE[]                         pOperationState,            // gets state
            [In, Out] ref CK_LONG                       pulOperationStateLen        // gets state length
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SETOPERATIONSTATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In     ] CK_BYTE                           pOperationState,            // holds state
            [In     ] CK_LONG                           ulOperationStateLen,        // holds state length
            [In     ] CK_OBJECT_HANDLE                  hEncryptionKey,             // en/decryption key
            [In     ] CK_OBJECT_HANDLE                  hAuthenticationKey          // sign/verify key
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETFUNCTIONSTATUS(
            [In     ] CK_SESSION_HANDLE                 hSession                    // the session's handle
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_CANCELFUNCTION(
            [In     ] CK_SESSION_HANDLE                 hSession                    // the session's handle
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_LOGIN(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_USER_TYPE                      userType,                   // the user type
            [In     ] CK_UTF8CHAR[]                     pPin,                       // the user's PIN
            [In     ] CK_LONG                           ulPinLen                    // the length of the PIN
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_LOGOUT(
            [In     ] CK_SESSION_HANDLE                 hSession                    // the session's handle
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_INITPIN(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_UTF8CHAR[]                     pPin,                       // the normal user's PIN
            [In     ] CK_LONG                           ulPinLen                    // length in bytes of the PIN
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SETPIN(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_UTF8CHAR[]                     pOldPin,                    // the old PIN
            [In     ] CK_LONG                           ulOldLen,                   // length of the old PIN
            [In     ] CK_UTF8CHAR[]                     pNewPin,                    // the new PIN
            [In     ] CK_LONG                           ulNewLen                    // length of the new PIN
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_CREATEOBJECT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_ATTRIBUTE_PTR                  pTemplate,                  // the object's template
            [In     ] CK_LONG                           ulCount,                    // attributes in template
            [    Out] out CK_OBJECT_HANDLE              phObject                    // gets new object's handle.
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_COPYOBJECT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_OBJECT_HANDLE                  hObject,                    // the object's handle
            [In     ] CK_ATTRIBUTE_PTR                  pTemplate,                  // template for new object
            [In     ] CK_LONG                           ulCount,                    // attributes in template
            [    Out] out CK_OBJECT_HANDLE              phNewObject                 // receives handle of copy
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DESTROYOBJECT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_OBJECT_HANDLE                  hObject                     // the object's handle
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETOBJECTSIZE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_OBJECT_HANDLE                  hObject,                    // the object's handle
            [    Out] out CK_LONG                       pulSize                     // receives size of object
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GETATTRIBUTEVALUE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_OBJECT_HANDLE                  hObject,                    // the object's handle
            [In, Out] CK_ATTRIBUTE_PTR                  pTemplate,                  // specifies attrs; gets vals
            [In     ] CK_LONG                           ulCount                     // attributes in template
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SETATTRIBUTEVALUE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_OBJECT_HANDLE                  hObject,                    // the object's handle
            [In     ] CK_ATTRIBUTE_PTR                  pTemplate,                  // specifies attrs and values
            [In     ] CK_LONG                           ulCount                     // attributes in template
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_FINDOBJECTSINIT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_ATTRIBUTE_PTR                  pTemplate,                  // attribute values to match
            [In     ] CK_LONG                           ulCount                     // attrs in search template
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_FINDOBJECTS(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In, Out] CK_OBJECT_HANDLE[]                phObject,                   // gets obj. handles
            [In     ] CK_LONG                           ulMaxObjectCount,           // max handles to get
            [    Out] out CK_LONG                       pulObjectCount              // actual # returned
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_FINDOBJECTSFINAL(
            [In     ] CK_SESSION_HANDLE                 hSession                    // the session's handle
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GENERATEKEY(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] ref CK_MECHANISM                  pMechanism,                 // key generation mech.
            [In     ] CK_ATTRIBUTE_PTR                  pTemplate,                  // template for new key
            [In     ] CK_LONG                           ulCount,                    // # of attrs in template
            [    Out] out CK_OBJECT_HANDLE              phKey                       // gets handle of new key
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GENERATEKEYPAIR(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session handle
            [In     ] ref CK_MECHANISM                  pMechanism,                 // key-gen mech.
            [In     ] CK_ATTRIBUTE_PTR                  pPublicKeyTemplate,         // template for pub. key
            [In     ] CK_LONG                           ulPublicKeyAttributeCount,  // # pub. attrs.
            [In     ] CK_ATTRIBUTE_PTR                  pPrivateKeyTemplate,        // template for priv. key
            [In     ] CK_LONG                           ulPrivateKeyAttributeCount, // # priv. attrs.
            [    Out] out CK_OBJECT_HANDLE              phPublicKey,                // gets pub. key handle
            [    Out] out CK_OBJECT_HANDLE              phPrivateKey                // gets priv. key handle
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_ENCRYPTINIT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] ref CK_MECHANISM                  pMechanism,                 // the encryption mechanism
            [In     ] CK_OBJECT_HANDLE                  hKey                        // handle of encryption key
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_ENCRYPTUPDATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In     ] CK_BYTE[]                         pPart,                      // the plaintext data
            [In     ] CK_LONG                           ulPartLen,                  // plaintext data len
            [In, Out] CK_BYTE[]                         pEncryptedPart,             // gets ciphertext
            [In, Out] ref CK_LONG                       pulEncryptedPartLen         // gets c-text size
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_ENCRYPTFINAL(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session handle
            [In, Out] CK_BYTE[]                         pLastEncryptedPart,         // last c-text
            [In, Out] ref CK_LONG                       pulLastEncryptedPartLen     // gets last size
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_ENCRYPT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In     ] CK_BYTE[]                         pData,                      // the plaintext data
            [In     ] CK_LONG                           ulDataLen,                  // bytes of plaintext
            [In, Out] CK_BYTE[]                         pEncryptedData,             // gets ciphertext
            [In, Out] ref CK_LONG                       pulEncryptedDataLen         // gets c-text size
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DECRYPTINIT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] ref CK_MECHANISM                  pMechanism,                 // the decryption mechanism
            [In     ] CK_OBJECT_HANDLE                  hKey                        // handle of decryption key
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DECRYPTUPDATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In     ] CK_BYTE[]                         pEncryptedPart,             // encrypted data
            [In     ] CK_LONG                           ulEncryptedPartLen,         // input length
            [In, Out] CK_BYTE[]                         pPart,                      // gets plaintext
            [In, Out] ref CK_LONG                       pulPartLen                  // p-text size
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DECRYPTFINAL(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In, Out] CK_BYTE[]                         pLastPart,                  // gets plaintext
            [In, Out] ref CK_LONG                       pulLastPartLen              // p-text size
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DECRYPT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In     ] CK_BYTE[]                         pEncryptedData,             // ciphertext
            [In     ] CK_LONG                           ulEncryptedDataLen,         // ciphertext length
            [In, Out] CK_BYTE[]                         pData,                      // gets plaintext
            [In, Out] ref CK_LONG                       pulDataLen                  // gets p-text size
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DIGESTINIT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] ref CK_MECHANISM                  pMechanism                  // the digesting mechanism
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DIGESTUPDATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_BYTE[]                         pPart,                      // data to be digested
            [In     ] CK_LONG                           ulPartLen                   // bytes of data to be digested
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DIGESTKEY(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_OBJECT_HANDLE                  hKey                        // secret key to digest
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DIGESTFINAL(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In, Out] CK_BYTE[]                         pDigest,                    // gets the message digest
            [In, Out] ref CK_LONG                       pulDigestLen                // gets byte count of digest
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DIGEST(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_BYTE[]                         pData,                      // data to be digested
            [In     ] CK_LONG                           ulDataLen,                  // bytes of data to digest
            [In, Out] CK_BYTE[]                         pDigest,                    // gets the message digest
            [In, Out] ref CK_LONG                       pulDigestLen                // gets digest length
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SIGNINIT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] ref CK_MECHANISM                  pMechanism,                 // the signature mechanism
            [In     ] CK_OBJECT_HANDLE                  hKey                        // handle of signature key
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SIGNUPDATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_BYTE[]                         pPart,                      // the data to sign
            [In     ] CK_LONG                           ulPartLen                   // count of bytes to sign
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SIGNFINAL(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In, Out] CK_BYTE[]                         pSignature,                 // gets the signature
            [In, Out] ref CK_LONG                       pulSignatureLen             // gets signature length
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SIGN(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_BYTE[]                         pData,                      // the data to sign
            [In     ] CK_LONG                           ulDataLen,                  // count of bytes to sign
            [In, Out] CK_BYTE[]                         pSignature,                 // gets the signature
            [In, Out] ref CK_LONG                       pulSignatureLen             // gets signature length
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SIGNRECOVERINIT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] ref CK_MECHANISM                  pMechanism,                 // the signature mechanism
            [In     ] CK_OBJECT_HANDLE                  hKey                        // handle of the signature key
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SIGNRECOVER(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_BYTE[]                         pData,                      // the data to sign
            [In     ] CK_LONG                           ulDataLen,                  // count of bytes to sign
            [In, Out] CK_BYTE[]                         pSignature,                 // gets the signature
            [In, Out] ref CK_LONG                       pulSignatureLen             // gets signature length
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_VERIFYINIT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] ref CK_MECHANISM                  pMechanism,                 // the verification mechanism
            [In     ] CK_OBJECT_HANDLE                  hKey                        // verification key
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_VERIFYUPDATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_BYTE[]                         pPart,                      // signed data
            [In     ] CK_LONG                           ulPartLen                   // length of signed data
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_VERIFYFINAL(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_BYTE[]                         pSignature,                 // signature to verify
            [In     ] CK_LONG                           ulSignatureLen              // signature length
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_VERIFY(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_BYTE[]                         pData,                      // signed data
            [In     ] CK_LONG                           ulDataLen,                  // length of signed data
            [In     ] CK_BYTE[]                         pSignature,                 // signature
            [In     ] CK_LONG                           ulSignatureLen              // signature length
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_VERIFYRECOVERINIT(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] ref CK_MECHANISM                  pMechanism,                 // the verification mechanism
            [In     ] CK_OBJECT_HANDLE                  hKey                        // verification key
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_VERIFYRECOVER(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_BYTE[]                         pSignature,                 // signature to verify
            [In     ] CK_LONG                           ulSignatureLen,             // signature length
            [In, Out] CK_BYTE[]                         pData,                      // gets signed data
            [In, Out] ref CK_LONG                       pulDataLen                  // gets signed data len
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DIGESTENCRYPTUPDATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In     ] CK_BYTE[]                         pPart,                      // the plaintext data
            [In     ] CK_LONG                           ulPartLen,                  // plaintext length
            [In, Out] CK_BYTE[]                         pEncryptedPart,             // gets ciphertext
            [In, Out] ref CK_LONG                       pulEncryptedPartLen         // gets c-text length
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DECRYPTDIGESTUPDATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In     ] CK_BYTE[]                         pEncryptedPart,             // ciphertext
            [In     ] CK_LONG                           ulEncryptedPartLen,         // ciphertext length
            [In, Out] CK_BYTE[]                         pPart,                      // gets plaintext
            [In, Out] ref CK_LONG                       pulPartLen                  // gets plaintext len
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SIGNENCRYPTUPDATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In     ] CK_BYTE[]                         pPart,                      // the plaintext data
            [In     ] CK_LONG                           ulPartLen,                  // plaintext length
            [In, Out] CK_BYTE[]                         pEncryptedPart,             // gets ciphertext 
            [In, Out] ref CK_LONG                       pulEncryptedPartLen         // gets c-text length
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DECRYPTVERIFYUPDATE(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In     ] CK_BYTE[]                         pEncryptedPart,             // ciphertext
            [In     ] CK_LONG                           ulEncryptedPartLen,         // ciphertext length
            [In, Out] CK_BYTE[]                         pPart,                      // gets plaintext
            [In, Out] ref CK_LONG                       pulPartLen                  // gets p-text length
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_WRAPKEY(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] ref CK_MECHANISM                  pMechanism,                 // the wrapping mechanism
            [In     ] CK_OBJECT_HANDLE                  hWrappingKey,               // wrapping key
            [In     ] CK_OBJECT_HANDLE                  hKey,                       // key to be wrapped
            [In, Out] CK_BYTE[]                         pWrappedKey,                // gets wrapped key
            [In, Out] ref CK_LONG                       pulWrappedKeyLen            // gets wrapped key size
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_UNWRAPKEY(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle 
            [In     ] ref CK_MECHANISM                  pMechanism,                 // unwrapping mech. 
            [In     ] CK_OBJECT_HANDLE                  hUnwrappingKey,             // unwrapping key 
            [In     ] CK_BYTE[]                         pWrappedKey,                // the wrapped key 
            [In     ] CK_LONG                           ulWrappedKeyLen,            // wrapped key len 
            [In     ] CK_ATTRIBUTE_PTR                  pTemplate,                  // new key template
            [In     ] CK_LONG                           ulAttributeCount,           // template length 
            [    Out] out CK_OBJECT_HANDLE              phKey                       // gets new handle 
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_DERIVEKEY(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // session's handle
            [In     ] ref CK_MECHANISM                  pMechanism,                 // key deriv. mech.
            [In     ] CK_OBJECT_HANDLE                  hBaseKey,                   // base key
            [In     ] CK_ATTRIBUTE_PTR                  pTemplate,                  // new key template
            [In     ] CK_LONG                           ulAttributeCount,           // template length
            [    Out] out CK_OBJECT_HANDLE              phKey                       // gets new handle
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_SEEDRANDOM(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In     ] CK_BYTE[]                         pSeed,                      // the seed material
            [In     ] CK_LONG                           ulSeedLen                   // length of seed material
        );
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate CK_RV CK_GENERATERANDOM(
            [In     ] CK_SESSION_HANDLE                 hSession,                   // the session's handle
            [In, Out] CK_BYTE[]                         RandomData,                 // receives the random data
            [In     ] CK_LONG                           ulRandomLen                 // # of bytes to generate
        );
        ///////////////////////////////////////////////////////////////////////
        // Структура определения функций
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_FUNCTION_LIST  {
            public API.CK_VERSION            version;
            public CK_INITIALIZE             C_Initialize; 
            public CK_FINALIZE               C_Finalize; 
            public CK_GETINFO                C_GetInfo; 
            public CK_GETFUNCTIONLIST        C_GetFunctionList; 
            public CK_GETSLOTLIST            C_GetSlotList; 
            public CK_GETSLOTINFO            C_GetSlotInfo; 
            public CK_GETTOKENINFO           C_GetTokenInfo; 
            public CK_GETMECHANISMLIST       C_GetMechanismList; 
            public CK_GETMECHANISMINFO       C_GetMechanismInfo; 
            public CK_INITTOKEN              C_InitToken; 
            public CK_INITPIN                C_InitPIN; 
            public CK_SETPIN                 C_SetPIN; 
            public CK_OPENSESSION            C_OpenSession; 
            public CK_CLOSESESSION           C_CloseSession; 
            public CK_CLOSEALLSESSIONS       C_CloseAllSessions; 
            public CK_GETSESSIONINFO         C_GetSessionInfo; 
            public CK_GETOPERATIONSTATE      C_GetOperationState; 
            public CK_SETOPERATIONSTATE      C_SetOperationState; 
            public CK_LOGIN                  C_Login; 
            public CK_LOGOUT                 C_Logout; 
            public CK_CREATEOBJECT           C_CreateObject; 
            public CK_COPYOBJECT             C_CopyObject; 
            public CK_DESTROYOBJECT          C_DestroyObject; 
            public CK_GETOBJECTSIZE          C_GetObjectSize; 
            public CK_GETATTRIBUTEVALUE      C_GetAttributeValue; 
            public CK_SETATTRIBUTEVALUE      C_SetAttributeValue; 
            public CK_FINDOBJECTSINIT        C_FindObjectsInit; 
            public CK_FINDOBJECTS            C_FindObjects; 
            public CK_FINDOBJECTSFINAL       C_FindObjectsFinal; 
            public CK_ENCRYPTINIT            C_EncryptInit; 
            public CK_ENCRYPT                C_Encrypt; 
            public CK_ENCRYPTUPDATE          C_EncryptUpdate; 
            public CK_ENCRYPTFINAL           C_EncryptFinal; 
            public CK_DECRYPTINIT            C_DecryptInit; 
            public CK_DECRYPT                C_Decrypt; 
            public CK_DECRYPTUPDATE          C_DecryptUpdate; 
            public CK_DECRYPTFINAL           C_DecryptFinal; 
            public CK_DIGESTINIT             C_DigestInit; 
            public CK_DIGEST                 C_Digest; 
            public CK_DIGESTUPDATE           C_DigestUpdate; 
            public CK_DIGESTKEY              C_DigestKey; 
            public CK_DIGESTFINAL            C_DigestFinal; 
            public CK_SIGNINIT               C_SignInit; 
            public CK_SIGN                   C_Sign; 
            public CK_SIGNUPDATE             C_SignUpdate; 
            public CK_SIGNFINAL              C_SignFinal; 
            public CK_SIGNRECOVERINIT        C_SignRecoverInit; 
            public CK_SIGNRECOVER            C_SignRecover; 
            public CK_VERIFYINIT             C_VerifyInit; 
            public CK_VERIFY                 C_Verify; 
            public CK_VERIFYUPDATE           C_VerifyUpdate; 
            public CK_VERIFYFINAL            C_VerifyFinal; 
            public CK_VERIFYRECOVERINIT      C_VerifyRecoverInit; 
            public CK_VERIFYRECOVER          C_VerifyRecover; 
            public CK_DIGESTENCRYPTUPDATE    C_DigestEncryptUpdate; 
            public CK_DECRYPTDIGESTUPDATE    C_DecryptDigestUpdate; 
            public CK_SIGNENCRYPTUPDATE      C_SignEncryptUpdate; 
            public CK_DECRYPTVERIFYUPDATE    C_DecryptVerifyUpdate; 
            public CK_GENERATEKEY            C_GenerateKey; 
            public CK_GENERATEKEYPAIR        C_GenerateKeyPair; 
            public CK_WRAPKEY                C_WrapKey; 
            public CK_UNWRAPKEY              C_UnwrapKey; 
            public CK_DERIVEKEY              C_DeriveKey; 
            public CK_SEEDRANDOM             C_SeedRandom; 
            public CK_GENERATERANDOM         C_GenerateRandom; 
            public CK_GETFUNCTIONSTATUS      C_GetFunctionStatus; 
            public CK_CANCELFUNCTION         C_CancelFunction; 
            public CK_WAITFORSLOTEVENT       C_WaitForSlotEvent; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Информация о модуле
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_INFO {
            public API.CK_VERSION      cryptokiVersion;     // номер версии интерфейса 

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public CK_UTF8CHAR[]       manufacturerID;      // имя производителя
            public CK_FLAGS            flags;               // 

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public CK_UTF8CHAR[]       libraryDescription;  // описание модуля
            public API.CK_VERSION      libraryVersion;      // номер версии модуля
        };
        ///////////////////////////////////////////////////////////////////////
        // Информация о считывателе
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_SLOT_INFO {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            public CK_UTF8CHAR[]       slotDescription;     // описание считывателя

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public CK_UTF8CHAR[]       manufacturerID;      // имя производителя
            public CK_FLAGS            flags;               // атрибуты считывателя

            public API.CK_VERSION      hardwareVersion;     // версия аппаратного обеспечения
            public API.CK_VERSION      firmwareVersion;     // версия программного обеспечения
        };
        ///////////////////////////////////////////////////////////////////////
        // Информация о смарт-карте
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_TOKEN_INFO {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public CK_UTF8CHAR[]       label;                // метка смарт-карты
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public CK_UTF8CHAR[]       manufacturerID;       // имя производителя
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public CK_UTF8CHAR[]       model;                // модель смарт-карты
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public CK_CHAR    []       serialNumber;         // серийный номер смарт-карты
            public CK_FLAGS            flags;                // атрибуты смарт-карты

            public CK_LONG            ulMaxSessionCount;     // максимальное число сеансов
            public CK_LONG            ulSessionCount;        // число открытых сеансов
            public CK_LONG            ulMaxRwSessionCount;   // максимальное число сеансов для записи 
            public CK_LONG            ulRwSessionCount;      // число открытых сеансов для записи
            public CK_LONG            ulMaxPinLen;           // максимальная длина пин-кода
            public CK_LONG            ulMinPinLen;           // минимальная длина пин-кода
            public CK_LONG            ulTotalPublicMemory;   // размер открытой памяти
            public CK_LONG            ulFreePublicMemory;    // оставшийся размер открытой памяти
            public CK_LONG            ulTotalPrivateMemory;  // размер закрытой памяти
            public CK_LONG            ulFreePrivateMemory;   // оставшийся размер закрытой памяти

            public API.CK_VERSION      hardwareVersion;       // версия аппаратного обеспечения
            public API.CK_VERSION      firmwareVersion;       // версия программного обеспечения

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public CK_CHAR[]           utcTime;               // время создания смарт-карты
        };
        ////////////////////////////////////////////////////////////////////////
        // Информация о сеансе
        ////////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_SESSION_INFO {
            public CK_SLOT_ID        slotID;               // идентификатор устройства
            public CK_SESSION_STATE  state;                // состояние сеанса
            public CK_FLAGS          flags;                // атрибуты сеанса
            public CK_LONG           ulDeviceError;  
        };
        ///////////////////////////////////////////////////////////////////////
        // Информация об атрибуте
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_ATTRIBUTE {
            public CK_ATTRIBUTE_TYPE    type;               // тип атрибута
            public CK_VOID_PTR          pValue;             // адрес значения атрибута
            public CK_LONG              ulValueLen;         // размер значения атрибута
        };
        ///////////////////////////////////////////////////////////////////////
        // Информация об алгоритме
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_MECHANISM_INFO {
            public CK_LONG            ulMinKeySize;       // минимальный размер ключа
            public CK_LONG            ulMaxKeySize;       // максимальный размер ключа
            public CK_FLAGS           flags;              // поддерживаемые типы операций
        };
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритма
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_MECHANISM 
        {
            // конструктор
            public CK_MECHANISM(CK_MECHANISM_TYPE mechanism, CK_VOID_PTR pParameter, CK_LONG ulParameterLen)
            {
                // сохранить переданные параметры
                this.mechanism      = mechanism;        // идентификатор алгоритма 
                this.pParameter     = pParameter;       // адрес параметров алгоритма
                this.ulParameterLen = ulParameterLen;   // размер параметров алгоритма
            }
            public CK_MECHANISM_TYPE  mechanism;        // идентификатор алгоритма 
            public CK_VOID_PTR        pParameter;       // адрес параметров алгоритма
            public CK_LONG            ulParameterLen;   // размер параметров алгоритма
        };
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов RC2
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_RC2_CBC_PARAMS {
            public CK_LONG     ulEffectiveBits;    // effective bits (1-1024)

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public CK_BYTE[]    iv;                // IV for CBC mode
        };
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_RC2_MAC_GENERAL_PARAMS {
            public CK_LONG     ulEffectiveBits;    // effective bits (1-1024)
            public CK_LONG     ulMacLength;        // Length of MAC in bytes
        };
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов RC5
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_RC5_PARAMS {
            public CK_LONG     ulWordsize;         // wordsize in bits
            public CK_LONG     ulRounds;           // number of rounds
        };
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_RC5_CBC_PARAMS {
            public CK_LONG     ulWordsize;         // wordsize in bits
            public CK_LONG     ulRounds;           // number of rounds
            public CK_BYTE_PTR  pIv;                // pointer to IV
            public CK_LONG     ulIvLen;            // length of IV in bytes
        };
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_RC5_MAC_GENERAL_PARAMS {
            public CK_LONG      ulWordsize;    // wordsize in bits
            public CK_LONG      ulRounds;      // number of rounds
            public CK_LONG      ulMacLength;   // Length of MAC in bytes
        };
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов AES
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_AES_CTR_PARAMS {
            public CK_LONG     ulCounterBits;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public CK_BYTE[]    cb;                
        };        
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов PBE
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_PBE_PARAMS {
            public CK_BYTE_PTR      pInitVector;
            public CK_UTF8CHAR_PTR  pPassword;
            public CK_LONG          ulPasswordLen;
            public CK_BYTE_PTR      pSalt;
            public CK_LONG          ulSaltLen;
            public CK_LONG          ulIteration;
        };
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_PKCS5_PBKD2_PARAMS {
            public CK_ULONG           saltSource;
            public CK_VOID_PTR        pSaltSourceData;
            public CK_LONG            ulSaltSourceDataLen;
            public CK_LONG            iterations;
            public CK_ULONG           prf;
            public CK_VOID_PTR        pPrfData;
            public CK_LONG            ulPrfDataLen;
            public CK_UTF8CHAR_PTR    pPassword;
            public CK_VOID_PTR        pulPasswordLen;
        };
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_PKCS5_PBKD2_PARAMS2 {
            public CK_ULONG           saltSource;
            public CK_VOID_PTR        pSaltSourceData;
            public CK_LONG            ulSaltSourceDataLen;
            public CK_LONG            iterations;
            public CK_ULONG           prf;
            public CK_VOID_PTR        pPrfData;
            public CK_LONG            ulPrfDataLen;
            public CK_UTF8CHAR_PTR    pPassword;
            public CK_LONG            ulPasswordLen;
        };
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов RSA
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_RSA_PKCS_OAEP_PARAMS {
            public CK_MECHANISM_TYPE    hashAlg;
            public CK_ULONG             mgf;
            public CK_ULONG             source;
            public CK_VOID_PTR          pSourceData;
            public CK_LONG              ulSourceDataLen;
        };
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_RSA_PKCS_PSS_PARAMS {
            public CK_MECHANISM_TYPE    hashAlg;
            public CK_ULONG             mgf;
            public CK_LONG             sLen;
        };
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов DH
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_X9_42_DH1_DERIVE_PARAMS {
           public CK_ULONG      kdf;
           public CK_LONG       ulOtherInfoLen;
           public CK_VOID_PTR   pOtherInfo;
           public CK_LONG       ulPublicDataLen;
           public CK_VOID_PTR   pPublicData;
        };
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов ECDH
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_ECDH1_DERIVE_PARAMS {
           public CK_ULONG      kdf;
           public CK_LONG       ulSharedDataLen;
           public CK_VOID_PTR   pSharedData;
           public CK_LONG       ulPublicDataLen;
           public CK_VOID_PTR   pPublicData;
        };
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов согласования ГОСТ Р34.10
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_GOSTR3410_DERIVE_PARAMS {
	        public CK_ULONG	        kdf;
	        public CK_VOID_PTR      pPublicData;
	        public CK_LONG		    ulPublicDataLen;
	        public CK_BYTE_PTR		pUKM;
	        public CK_LONG		    ulUKMLen;
        }
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов шифрования ключа ГОСТ Р34.10
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_GOSTR3410_KEY_WRAP_PARAMS {
	        public CK_VOID_PTR      pWrapOID;
	        public CK_LONG          ulWrapOIDLen;
	        public CK_BYTE_PTR      pUKM;
	        public CK_LONG          ulUKMLen;
	        public CK_OBJECT_HANDLE hKey;
        }
    }
}
