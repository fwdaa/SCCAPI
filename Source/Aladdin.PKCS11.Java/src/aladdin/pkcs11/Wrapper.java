package aladdin.pkcs11;
import aladdin.*; 
import aladdin.pkcs11.jni.*;
import java.io.*;
import java.security.*;

public class Wrapper extends RefObject
{
    // адрес глобальных данных для библиотеки поддержки
    private long pNativeData; private boolean initialized; 
    static {
        // cannot use LoadLibraryAction because that would make the native
        // library available to the bootclassloader, but we run in the
        // extension classloader.
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            @Override
            public Object run()   
            {
                // определить URL-путь к файлу с классом
                CodeSource codeSource = Wrapper.class.getProtectionDomain().getCodeSource(); 

                // определить файл с классом
                File jarFile = new File(codeSource.getLocation().getPath());                
                
                // определить каталог класса
                String jarDir = jarFile.getParentFile().getPath();
                
                // указать разделитель
                if (!jarDir.endsWith(File.separator)) jarDir += File.separator; 
                
                // загрузить библиотеку поддержки
                System.load(jarDir + "pkcs11jni.dll"); return null;
            }
        });
    }
    // Connects this object to the specified PKCS#11 library. This method is for
    // internal use only. Declared private, because incorrect handling may 
    // result in errors in the native part.
    private native void init(String pkcs11ModulePath) throws IOException;

    // Disconnects the PKCS#11 library from this object. After calling this
    // method, this object is no longer connected to a native PKCS#11 module
    // and any subsequent calls to C_ methods will fail. This method is for
    // internal use only. Declared private, because incorrect handling may 
    // result in errors in the native part.
    private native void done();

    public static synchronized Wrapper createInstance(String pkcs11ModulePath, long initFlags)
        throws Exception, IOException
    {
        // проверить наличие аргументов синхронизации
        if ((initFlags & API.CKF_OS_LOCKING_OK) != 0)
        {
            // подключиться к модулю
            return new Wrapper(pkcs11ModulePath, initFlags);
        }
        // подключиться к модулю
        else return new SyncLibrary(pkcs11ModulePath);
    }
    // конструктор
    Wrapper(String pkcs11ModulePath, long initFlags) throws Exception, IOException 
    { 
        // инициализировать глобальные данные
        init(pkcs11ModulePath); 
        try { 
            // инициализировать модуль
            C_Initialize(initFlags); initialized = false;  
        } 
        // обработать возможную ошибку
        catch (Exception e) 
        { 
            // проверить код ошибки
            if (e.getErrorCode() == API.CKR_CRYPTOKI_ALREADY_INITIALIZED) initialized = true; 
            
            // выбросить исключение
            else { done(); throw e; }
        }
    }
    // деструктор
    @Override protected final void onClose() throws IOException
    { 
        // освободить ресурсы модуля
        if (!initialized) C_Finalize(null); done(); super.onClose();
    } 
    ///////////////////////////////////////////////////////////////////////////
    // General-purpose
    ///////////////////////////////////////////////////////////////////////////

    // C_Initialize initializes the Cryptoki library.
    native final void C_Initialize(long initFlags) throws Exception;

    // C_Finalize indicates that an application is done with the
    // Cryptoki library
    native void C_Finalize(Object pReserved) throws Exception;


    // C_GetInfo returns general information about Cryptoki.
    public native CK_INFO C_GetInfo() throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Slot and token management
    ///////////////////////////////////////////////////////////////////////////

    // C_GetSlotList obtains a list of slots in the system.
    public native long[] C_GetSlotList(boolean tokenPresent) throws Exception;

    // C_GetSlotInfo obtains information about a particular slot in
    // the system.
    public native CK_SLOT_INFO C_GetSlotInfo(long slotID) throws Exception;

    // C_GetTokenInfo obtains information about a particular token
    // in the system.
    public native CK_TOKEN_INFO C_GetTokenInfo(long slotID) throws Exception;

    // C_WaitForSlotEvent waits for a slot event (token insertion,
    // removal, etc.) to occur.
    public native long C_WaitForSlotEvent(long flags, Object pReserved)
        throws Exception;

    // C_GetMechanismList obtains a list of mechanism types
    // supported by a token.
    public native long[] C_GetMechanismList(long slotID) throws Exception;

    // C_GetMechanismInfo obtains information about a particular
    // mechanism possibly supported by a token.
    public native CK_MECHANISM_INFO C_GetMechanismInfo(long slotID, long type)
        throws Exception;

    // C_InitToken initializes a token.
    public native void C_InitToken(long slotID, byte[] pPin, byte[] pLabel)
        throws Exception;

    // C_InitPIN initializes the normal user's PIN.
    public native void C_InitPIN(long hSession, byte[] pPin) throws Exception;

    // C_SetPIN modifies the PIN of the user who is logged in.
    public native void C_SetPIN(long hSession, byte[] pOldPin, byte[] pNewPin)
        throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Session management
    ///////////////////////////////////////////////////////////////////////////

    // C_OpenSession opens a session between an application and a
    // token.
    public native long C_OpenSession(long slotID, 
        long flags, Object pApplication, Notify notify) throws Exception;

    // C_CloseSession closes a session between an application and a
    // token.
    public native void C_CloseSession(long hSession) throws Exception;

    // C_CloseAllSessions closes all sessions with a token.
    public native void C_CloseAllSessions(long slotID) throws Exception;

    // C_GetSessionInfo obtains information about the session.
    public native CK_SESSION_INFO C_GetSessionInfo(long hSession) throws Exception;

    // C_GetFunctionStatus is a legacy function; it obtains an
    // updated status of a function running in parallel with an
    // application.
    public native void C_GetFunctionStatus(long hSession) throws Exception;

    // C_CancelFunction is a legacy function; it cancels a function
    // running in parallel.
    public native void C_CancelFunction(long hSession) throws Exception;

    // C_GetOperationState obtains the state of the cryptographic operation
    // in a session.
    public native byte[] C_GetOperationState(long hSession) throws Exception;

    // C_SetOperationState restores the state of the cryptographic
    // operation in a session.
    public native void C_SetOperationState(long hSession, 
        byte[] operationState, long hEncryptionKey, 
        long hAuthenticationKey) throws Exception;

    // C_Login logs a user into a token.
    public native void C_Login(long hSession, long userType, byte[] pPin)
        throws Exception;

    // C_Logout logs a user out from a token.
    public native void C_Logout(long hSession) throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Object management
    ///////////////////////////////////////////////////////////////////////////

    // C_CreateObject creates a new object.
    public native long C_CreateObject(long hSession, CK_ATTRIBUTE[] pTemplate)
        throws Exception;

    // C_CopyObject copies an object, creating a new object for the
    // copy.
    public native long C_CopyObject(long hSession, 
        long hObject, CK_ATTRIBUTE[] pTemplate) throws Exception;

    // C_DestroyObject destroys an object.
    public native void C_DestroyObject(long hSession, long hObject)
        throws Exception;

    // C_GetObjectSize gets the size of an object in bytes.
    public native long C_GetObjectSize(long hSession, long hObject)
        throws Exception;

    // C_GetAttributeValue obtains the value of one or more object
    // attributes. The template attributes also receive the values.
    // note: in PKCS#11 pTemplate and the result template are the same
    public native void C_GetAttributeValue(long hSession, 
        long hObject, CK_ATTRIBUTE[] pTemplate) throws Exception;

    // C_SetAttributeValue modifies the value of one or more object
    // attributes
    public native void C_SetAttributeValue(long hSession, 
        long hObject, CK_ATTRIBUTE[] pTemplate) throws Exception;

    // C_FindObjectsInit initializes a search for token and session
    // objects that match a template.
    public native void C_FindObjectsInit(long hSession, CK_ATTRIBUTE[] pTemplate)
        throws Exception;

    // C_FindObjects continues a search for token and session
    // objects that match a template, obtaining additional object
    // handles.
    public native long[] C_FindObjects(long hSession, long ulMaxObjectCount)
        throws Exception;

    // C_FindObjectsFinal finishes a search for token and session
    // objects.
    public native void C_FindObjectsFinal(long hSession) throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Key management
    ///////////////////////////////////////////////////////////////////////////

    // C_GenerateKey generates a secret key, creating a new key
    // object.
    public native long C_GenerateKey(long hSession, 
        CK_MECHANISM pMechanism, CK_ATTRIBUTE[] pTemplate) throws Exception;

    // C_GenerateKeyPair generates a public-key/private-key pair,
    // creating new key objects.
    public native long[] C_GenerateKeyPair(long hSession, 
        CK_MECHANISM pMechanism, CK_ATTRIBUTE[] pPublicKeyTemplate, 
        CK_ATTRIBUTE[] pPrivateKeyTemplate) throws Exception;

    // C_WrapKey wraps (i.e., encrypts) a key.
    public native int C_WrapKey(long hSession, CK_MECHANISM pMechanism,
        long hWrappingKey, long hKey, byte[] out, int outOfs) throws Exception;

    // C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
    // key object.
    public native long C_UnwrapKey(long hSession, CK_MECHANISM pMechanism,
        long hUnwrappingKey, byte[] in, int inOfs, int inLen,
        CK_ATTRIBUTE[] pTemplate) throws Exception;

    // C_DeriveKey derives a key from a base key, creating a new key
    // object.
    public native long C_DeriveKey(long hSession, CK_MECHANISM pMechanism,
        long hBaseKey, CK_ATTRIBUTE[] pTemplate) throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Random number generation
    ///////////////////////////////////////////////////////////////////////////

    // C_SeedRandom mixes additional seed material into the token's
    // random number generator.
    public native void C_SeedRandom(long hSession, 
        byte[] in, int inOfs, int inLen) throws Exception;

    // C_GenerateRandom generates random data.
    public native void C_GenerateRandom(long hSession, 
        byte[] out, int outOfs, int outLen) throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Encryption and decryption
    ///////////////////////////////////////////////////////////////////////////

    // C_EncryptInit initializes an encryption operation.
    public native void C_EncryptInit(long hSession, 
        CK_MECHANISM pMechanism, long hKey) throws Exception;

    // C_Encrypt encrypts single-part data.
    public native int C_Encrypt(long hSession, 
        byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception;

    // C_EncryptUpdate continues a multiple-part encryption
    // operation.
    public native int C_EncryptUpdate(long hSession, 
        byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception;

    // C_EncryptFinal finishes a multiple-part encryption
    // operation.
    public native int C_EncryptFinal(long hSession, byte[] out, int outOfs)
        throws Exception;

    // C_DecryptInit initializes a decryption operation.
    public native void C_DecryptInit(long hSession, 
        CK_MECHANISM pMechanism, long hKey) throws Exception;

    // C_Decrypt decrypts encrypted data in a single part.
    public native int C_Decrypt(long hSession, 
        byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception;

    // C_DecryptUpdate continues a multiple-part decryption
    // operation.
    public native int C_DecryptUpdate(long hSession, 
        byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception;

    // C_DecryptFinal finishes a multiple-part decryption
    // operation.
    public native int C_DecryptFinal(long hSession, byte[] out, int outOfs)
        throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Message digesting
    ///////////////////////////////////////////////////////////////////////////

    // C_DigestInit initializes a message-digesting operation.
    public native void C_DigestInit(long hSession, CK_MECHANISM pMechanism)
        throws Exception;

    // C_DigestUpdate continues a multiple-part message-digesting
    // operation.
    public native void C_DigestUpdate(long hSession, 
        byte[] in, int inOfs, int inLen) throws Exception;

    // C_DigestKey continues a multi-part message-digesting
    // operation, by digesting the value of a secret key as part of
    // the data already digested.
    public native void C_DigestKey(long hSession, long hKey) throws Exception;

    // C_DigestFinal finishes a multiple-part message-digesting
    // operation.
    public native int C_DigestFinal(long hSession, 
        byte[] digest, int digestOfs) throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Signing and MACing
    ///////////////////////////////////////////////////////////////////////////

    // C_SignInit initializes a signature (private key encryption)
    // operation, where the signature is (will be) an appendix to
    // the data, and plaintext cannot be recovered from the
    // signature.
    public native void C_SignInit(long hSession, 
        CK_MECHANISM pMechanism, long hKey) throws Exception;

    // C_Sign signs (encrypts with private key) data in a single
    // part, where the signature is (will be) an appendix to the
    // data, and plaintext cannot be recovered from the signature.
    public native int C_Sign(long hSession, 
        byte[] data, int dataOfs, int dataLen, 
        byte[] sign, int signOfs) throws Exception;

    // C_SignUpdate continues a multiple-part signature operation,
    // where the signature is (will be) an appendix to the data,
    // and plaintext cannot be recovered from the signature.
    public native void C_SignUpdate(long hSession, 
        byte[] data, int dataOfs, int dataLen) throws Exception;

    // C_SignFinal finishes a multiple-part signature operation,
    // returning the signature.
    public native int C_SignFinal(long hSession, byte[] sign, int signOfs)
        throws Exception;

    // C_SignRecoverInit initializes a signature operation, where
    // the data can be recovered from the signature.
    public native void C_SignRecoverInit(long hSession, 
        CK_MECHANISM pMechanism, long hKey) throws Exception;

    // C_SignRecover signs data in a single operation, where the
    // data can be recovered from the signature.
    public native int C_SignRecover(long hSession, 
        byte[] data, int dataOfs, int dataLen, 
        byte[] envelope, int envelopeOfs) throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Verifying signatures and MACs
    ///////////////////////////////////////////////////////////////////////////

    // C_VerifyInit initializes a verification operation, where the
    // signature is an appendix to the data, and plaintext cannot
    // cannot be recovered from the signature (e.g. DSA).
    public native void C_VerifyInit(long hSession, 
        CK_MECHANISM pMechanism, long hKey) throws Exception;

    // C_Verify verifies a signature in a single-part operation,
    // where the signature is an appendix to the data, and plaintext
    // cannot be recovered from the signature.
    public native void C_Verify(long hSession, 
        byte[] data, int dataOfs, int dataLen, 
        byte[] sign, int signOfs, int signLen) throws Exception;

    // C_VerifyUpdate continues a multiple-part verification
    // operation, where the signature is an appendix to the data,
    // and plaintext cannot be recovered from the signature.
    public native void C_VerifyUpdate(long hSession, 
        byte[] data, int dataOfs, int dataLen) throws Exception;

    // C_VerifyFinal finishes a multiple-part verification
    // operation, checking the signature.
    public native void C_VerifyFinal(long hSession, 
        byte[] sign, int signOfs, int signLen) throws Exception;

    // C_VerifyRecoverInit initializes a signature verification
    // operation, where the data is recovered from the signature.
    public native void C_VerifyRecoverInit(long hSession, 
        CK_MECHANISM pMechanism, long hKey) throws Exception;

    // C_VerifyRecover verifies a signature in a single-part
    // operation, where the data is recovered from the signature.
    public native int C_VerifyRecover(long hSession, 
        byte[] envelope, int envelopeOfs, int envelopeLen, 
        byte[] data, int dataOfs) throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Dual-function cryptographic operations
    ///////////////////////////////////////////////////////////////////////////

    // C_DigestEncryptUpdate continues a multiple-part digesting
    // and encryption operation.
    public native int C_DigestEncryptUpdate(long hSession, 
        byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception;

    // C_DecryptDigestUpdate continues a multiple-part decryption and
    // digesting operation.
    public native int C_DecryptDigestUpdate(long hSession, 
        byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception;

    // C_SignEncryptUpdate continues a multiple-part signing and
    // encryption operation.
    public native int C_SignEncryptUpdate(long hSession, 
        byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception;

    // C_DecryptVerifyUpdate continues a multiple-part decryption and
    // verify operation.
    public native int C_DecryptVerifyUpdate(long hSession, 
        byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // PKCS11 subclass that has all methods synchronized and delegating to the
    // parent. Used for tokens that only support single threaded access
    ///////////////////////////////////////////////////////////////////////////
    static class SyncLibrary extends Wrapper
    {
        public SyncLibrary(String pkcs11ModulePath) throws Exception, IOException
        {
            super(pkcs11ModulePath, 0);
        }
        ///////////////////////////////////////////////////////////////////////
        // General-purpose
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized void C_Finalize(Object pReserved) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_Finalize(pReserved);
        }
        @Override
        public synchronized CK_INFO C_GetInfo() throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GetInfo();
        }
        ///////////////////////////////////////////////////////////////////////
        // Slot and token management
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized long[] C_GetSlotList(boolean tokenPresent)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GetSlotList(tokenPresent);
        }
        @Override
        public synchronized CK_SLOT_INFO C_GetSlotInfo(long slotID)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GetSlotInfo(slotID);
        }
        @Override
        public synchronized CK_TOKEN_INFO C_GetTokenInfo(long slotID)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GetTokenInfo(slotID);
        }
        @Override
        public synchronized long C_WaitForSlotEvent(long flags, Object pReserved)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_WaitForSlotEvent(flags, pReserved);
        }
        @Override
        public synchronized long[] C_GetMechanismList(long slotID)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GetMechanismList(slotID);
        }
        @Override
        public synchronized CK_MECHANISM_INFO C_GetMechanismInfo(
            long slotID, long type) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GetMechanismInfo(slotID, type);
        }
        @Override
        public synchronized void C_InitToken(long slotID, 
            byte[] pPin, byte[] pLabel) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_InitToken(slotID, pPin, pLabel);
        }
        @Override
        public synchronized void C_InitPIN(long hSession, byte[] pPin)
            throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_InitPIN(hSession, pPin);
        }
        @Override
        public synchronized void C_SetPIN(long hSession, byte[] pOldPin, byte[] pNewPin)
            throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_SetPIN(hSession, pOldPin, pNewPin);
        }
        ///////////////////////////////////////////////////////////////////////
        // Session management
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized long C_OpenSession(long slotID, 
            long flags, Object pApplication, Notify notify) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_OpenSession(slotID, flags, pApplication, notify);
        }
        @Override
        public synchronized void C_CloseSession(long hSession) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_CloseSession(hSession);
        }
        @Override
        public synchronized void C_CloseAllSessions(long slotID) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_CloseAllSessions(slotID);
        }
        @Override
        public synchronized CK_SESSION_INFO C_GetSessionInfo(long hSession)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GetSessionInfo(hSession);
        }
        @Override
        public synchronized void C_GetFunctionStatus(long hSession)
            throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_GetFunctionStatus(hSession);
        }
        @Override
        public synchronized void C_CancelFunction(long hSession)
            throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_CancelFunction(hSession);
        }
        @Override
        public synchronized byte[] C_GetOperationState(long hSession)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GetOperationState(hSession);
        }
        @Override
        public synchronized void C_SetOperationState(long hSession, 
            byte[] pOperationState, long hEncryptionKey, 
            long hAuthenticationKey) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_SetOperationState(hSession, 
                pOperationState, hEncryptionKey, hAuthenticationKey
            );
        }
        @Override
        public synchronized void C_Login(long hSession, long userType, byte[] pPin)
            throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_Login(hSession, userType, pPin);
        }
        @Override
        public synchronized void C_Logout(long hSession) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_Logout(hSession);
        }
        ///////////////////////////////////////////////////////////////////////
        // Object management
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized long C_CreateObject(long hSession,
            CK_ATTRIBUTE[] pTemplate) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_CreateObject(hSession, pTemplate);
        }
        @Override
        public synchronized long C_CopyObject(long hSession, 
            long hObject, CK_ATTRIBUTE[] pTemplate) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_CopyObject(hSession, hObject, pTemplate);
        }
        @Override
        public synchronized void C_DestroyObject(long hSession, long hObject)
            throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_DestroyObject(hSession, hObject);
        }
        @Override
        public synchronized long C_GetObjectSize(long hSession, long hObject)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GetObjectSize(hSession, hObject);
        }
        @Override
        public synchronized void C_GetAttributeValue(long hSession, 
            long hObject, CK_ATTRIBUTE[] pTemplate) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_GetAttributeValue(hSession, hObject, pTemplate);
        }
        @Override
        public synchronized void C_SetAttributeValue(long hSession, 
            long hObject, CK_ATTRIBUTE[] pTemplate) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_SetAttributeValue(hSession, hObject, pTemplate);
        }
        @Override
        public synchronized void C_FindObjectsInit(
            long hSession, CK_ATTRIBUTE[] pTemplate) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_FindObjectsInit(hSession, pTemplate);
        }
        @Override
        public synchronized long[] C_FindObjects(long hSession, long ulMaxObjectCount)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_FindObjects(hSession, ulMaxObjectCount);
        }
        @Override
        public synchronized void C_FindObjectsFinal(long hSession)
            throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_FindObjectsFinal(hSession);
        }
        ///////////////////////////////////////////////////////////////////////
        // Key management
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized long C_GenerateKey(long hSession,
            CK_MECHANISM pMechanism, CK_ATTRIBUTE[] pTemplate)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GenerateKey(hSession, pMechanism, pTemplate);
        }
        @Override
        public synchronized long[] C_GenerateKeyPair(long hSession,
            CK_MECHANISM pMechanism, CK_ATTRIBUTE[] pPublicKeyTemplate,
            CK_ATTRIBUTE[] pPrivateKeyTemplate) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_GenerateKeyPair(hSession, 
                pMechanism, pPublicKeyTemplate, pPrivateKeyTemplate
            );
        }
        @Override
        public synchronized int C_WrapKey(long hSession,
            CK_MECHANISM pMechanism, long hWrappingKey, long hKey, 
            byte[] out, int outOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, out, outOfs);
        }
        @Override
        public synchronized long C_UnwrapKey(
            long hSession, CK_MECHANISM pMechanism, long hUnwrappingKey, 
            byte[] in, int inOfs, int inLen, CK_ATTRIBUTE[] pTemplate) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_UnwrapKey(hSession, pMechanism, 
                hUnwrappingKey, in, inOfs, inLen, pTemplate
            );
        }
        @Override
        public synchronized long C_DeriveKey(long hSession,
            CK_MECHANISM pMechanism, long hBaseKey, CK_ATTRIBUTE[] pTemplate)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate);
        }
        ///////////////////////////////////////////////////////////////////////
        // Random number generation
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized void C_SeedRandom(long hSession, 
            byte[] in, int inOfs, int inLen) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_SeedRandom(hSession, in, inOfs, inLen);
        }
        @Override
        public synchronized void C_GenerateRandom(long hSession, 
            byte[] out, int outOfs, int outLen) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_GenerateRandom(hSession, out, outOfs, outLen);
        }
        ///////////////////////////////////////////////////////////////////////
        // Encryption and decryption
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized void C_EncryptInit(long hSession,
            CK_MECHANISM pMechanism, long hKey) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_EncryptInit(hSession, pMechanism, hKey);
        }
        @Override
        public synchronized int C_Encrypt(long hSession, 
            byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_Encrypt(hSession, in, inOfs, inLen, out, outOfs);
        }
        @Override
        public synchronized int C_EncryptUpdate(long hSession, 
            byte[] in, int inOfs, int inLen, byte[] out, int outOfs)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_EncryptUpdate(hSession, in, inOfs, inLen, out, outOfs);
        }
        @Override
        public synchronized int C_EncryptFinal(long hSession, 
            byte[] out, int outOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_EncryptFinal(hSession, out, outOfs);
        }
        @Override
        public synchronized void C_DecryptInit(long hSession,
            CK_MECHANISM pMechanism, long hKey) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_DecryptInit(hSession, pMechanism, hKey);
        }
        @Override
        public synchronized int C_Decrypt(long hSession, 
            byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_Decrypt(hSession, in, inOfs, inLen, out, outOfs);
        }
        @Override
        public synchronized int C_DecryptUpdate(long hSession, byte[] in,
            int inOfs, int inLen, byte[] out, int outOfs)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_DecryptUpdate(hSession, in, inOfs, inLen, out, outOfs);
        }
        @Override
        public synchronized int C_DecryptFinal(long hSession, 
            byte[] out, int outOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_DecryptFinal(hSession, out, outOfs);
        }
        ///////////////////////////////////////////////////////////////////////
        // Message digesting
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized void C_DigestInit(long hSession,
            CK_MECHANISM pMechanism) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_DigestInit(hSession, pMechanism);
        }
        @Override
        public synchronized void C_DigestUpdate(long hSession, 
            byte[] in, int inOfs, int inLen) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_DigestUpdate(hSession, in, inOfs, inLen);
        }
        @Override
        public synchronized void C_DigestKey(long hSession, long hKey)
            throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_DigestKey(hSession, hKey);
        }
        @Override
        public synchronized int C_DigestFinal(long hSession, 
            byte[] digest, int digestOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_DigestFinal(hSession, digest, digestOfs);
        }
        ///////////////////////////////////////////////////////////////////////
        // Signing and MACing
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized void C_SignInit(long hSession,
            CK_MECHANISM pMechanism, long hKey) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_SignInit(hSession, pMechanism, hKey);
        }
        @Override
        public synchronized int C_Sign(long hSession, 
            byte[] data, int dataOfs, int dataLen, byte[] sign, int signOfs)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_Sign(hSession, data, dataOfs, dataLen, sign, signOfs);
        }
        @Override
        public synchronized void C_SignUpdate(long hSession, 
            byte[] data, int dataOfs, int dataLen) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_SignUpdate(hSession, data, dataOfs, dataLen);
        }
        @Override
        public synchronized int C_SignFinal(long hSession, 
            byte[] sign, int signOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_SignFinal(hSession, sign, signOfs);
        }
        @Override
        public synchronized void C_SignRecoverInit(long hSession,
            CK_MECHANISM pMechanism, long hKey) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_SignRecoverInit(hSession, pMechanism, hKey);
        }
        @Override
        public synchronized int C_SignRecover(long hSession, 
            byte[] data, int dataOfs, int dataLen, byte[] envelope, int envelopeOfs)
            throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_SignRecover(hSession, data, dataOfs, dataLen, envelope, envelopeOfs);
        }
        ///////////////////////////////////////////////////////////////////////
        // Verifying signatures and MACs
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized void C_VerifyInit(long hSession,
            CK_MECHANISM pMechanism, long hKey) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_VerifyInit(hSession, pMechanism, hKey);
        }
        @Override
        public synchronized void C_Verify(long hSession, 
            byte[] data, int dataOfs, int dataLen, 
            byte[] sign, int signOfs, int signLen) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_Verify(hSession, data, dataOfs, dataLen, sign, signOfs, signLen);
        }
        @Override
        public synchronized void C_VerifyUpdate(long hSession, 
            byte[] data, int dataOfs, int dataLen) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_VerifyUpdate(hSession, data, dataOfs, dataLen);
        }
        @Override
        public synchronized void C_VerifyFinal(long hSession, 
            byte[] sign, int signOfs, int signLen) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_VerifyFinal(hSession, sign, signOfs, signLen);
        }
        @Override
        public synchronized void C_VerifyRecoverInit(long hSession,
            CK_MECHANISM pMechanism, long hKey) throws Exception
        {
            // использовать встроенную синхронизацию
            super.C_VerifyRecoverInit(hSession, pMechanism, hKey);
        }
        @Override
        public synchronized int C_VerifyRecover(long hSession, 
            byte[] envelope, int envelopeOfs, int envelopeLen, 
            byte[] data, int dataOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_VerifyRecover(hSession, 
                envelope, envelopeOfs, envelopeLen, data, dataOfs
            );
        }
        ///////////////////////////////////////////////////////////////////////
        // Dual-function cryptographic operations
        ///////////////////////////////////////////////////////////////////////
        @Override
        public synchronized int C_DigestEncryptUpdate(long hSession, 
            byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_DigestEncryptUpdate(hSession, in, inOfs, inLen, out, outOfs);
        }
        @Override
        public synchronized int C_DecryptDigestUpdate(long hSession, 
            byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_DecryptDigestUpdate(hSession, in, inOfs, inLen, out, outOfs);
        }
        @Override
        public synchronized int C_SignEncryptUpdate(long hSession, 
            byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_SignEncryptUpdate(hSession, in, inOfs, inLen, out, outOfs);
        }
        @Override
        public synchronized int C_DecryptVerifyUpdate(long hSession, 
            byte[] in, int inOfs, int inLen, byte[] out, int outOfs) throws Exception
        {
            // использовать встроенную синхронизацию
            return super.C_DecryptVerifyUpdate(hSession, in, inOfs, inLen, out, outOfs);
        }
    }
}
