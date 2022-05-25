using System;
using System.Security.Authentication;

namespace Aladdin.CAPI
{
	//////////////////////////////////////////////////////////////////////////////
	// Объект не найден 
	//////////////////////////////////////////////////////////////////////////////
    [Serializable]
	public class NotFoundException : SystemException
    {
        // конструктор
        public NotFoundException(string message, Exception exception) : base(message, exception) {} 
        // конструктор
        public NotFoundException(string message) : base(message) {} 
        // конструктор
        public NotFoundException(Exception exception) : base(Resource.ObjectNotFound, exception) {} 
        // конструктор
        public NotFoundException() : base(Resource.ObjectNotFound) {} 
    }
	//////////////////////////////////////////////////////////////////////////////
	// Некорректный тип ключа 
	//////////////////////////////////////////////////////////////////////////////
    [Serializable]
	public class InvalidKeyException : System.Security.Cryptography.CryptographicException
    {
        // конструктор
        public InvalidKeyException(string message, Exception exception) : base(message, exception) {} 
        // конструктор
        public InvalidKeyException(string message) : base(message) {} 
        // конструктор
        public InvalidKeyException(Exception exception) : base(Resource.InvalidKeyType, exception) {} 
        // конструктор
        public InvalidKeyException() : base(Resource.InvalidKeyType) {} 
    }
	//////////////////////////////////////////////////////////////////////////////
	// Некорректная подпись 
	//////////////////////////////////////////////////////////////////////////////
    [Serializable]
	public class SignatureException : System.Security.Cryptography.CryptographicException
    {
        // конструктор
        public SignatureException(string message, Exception exception) : base(message, exception) {} 
        // конструктор
        public SignatureException(string message) : base(message) {} 
        // конструктор
        public SignatureException(Exception exception) : base(Resource.InvalidSignature, exception) {} 
        // конструктор
        public SignatureException() : base(Resource.InvalidSignature) {} 
    }
	//////////////////////////////////////////////////////////////////////////////
	// Объект не найден 
	//////////////////////////////////////////////////////////////////////////////
    [Serializable]
	public class AuthenticationException : System.Security.Authentication.AuthenticationException
    {
        // конструктор
        public AuthenticationException(string message, Exception exception) : base(message, exception) {} 
        // конструктор
        public AuthenticationException(string message) : base(message) {} 
        // конструктор
        public AuthenticationException(Exception exception) : base(Resource.AuthenticationFailed, exception) {} 
        // конструктор
        public AuthenticationException() : base(Resource.ObjectNotFound) {} 
    }
}
