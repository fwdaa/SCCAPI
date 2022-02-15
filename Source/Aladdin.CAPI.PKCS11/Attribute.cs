namespace Aladdin.CAPI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Атрибут PKCS11
    ///////////////////////////////////////////////////////////////////////////
    public class Attribute : Aladdin.PKCS11.Attribute
    {
	    // конструктор
        public Attribute(ulong type) : base(type) {}
	    // конструктор
	    public Attribute(ulong type, byte[] value) : base(type, value) {}
	    // конструктор
	    public Attribute(ulong type, byte value) : base(type, value) {}
	    // конструктор
	    public Attribute(ulong type, string value) : base(type, value) {}
    }
}
