package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*;
import java.io.*; 

// Addresses ::= SET OF OCTET STRING 

public final class Addresses extends Set<OctetString>
{
    private static final long serialVersionUID = -2827132673026678726L;
    
    // конструктор при раскодировании
    public Addresses(IEncodable encodable) throws IOException { super(OctetString.class, encodable); }

    // конструктор при закодировании
    public Addresses(OctetString... values) { super(OctetString.class, values); }
}

