package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*;

//	E163-4-address ::= SEQUENCE {
//		number      [0] IMPLICIT NumericString (SIZE (1..ub-e163-4-number-length)),
//		sub-address [1] IMPLICIT NumericString (SIZE (1..ub-e163-4-sub-address-length)) OPTIONAL 
//	}
//	ub-e163-4-number-length			INTEGER ::= 15
//	ub-e163-4-sub-address-length	INTEGER ::= 40

public final class E1634Address extends Sequence<NumericString>
{
    // информация о структуре
    private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(NumericString.class).factory(1, 15), Cast.N, Tag.context(0)), 
        new ObjectInfo(new ObjectCreator(NumericString.class).factory(1, 40), Cast.O, Tag.context(1)), 
    }; 
    // конструктор при раскодировании
    public E1634Address(IEncodable encodable) throws IOException 
    {
         super(encodable, info); 
    } 
    // конструктор при закодировании
    public E1634Address(NumericString number, NumericString subAddress) 
    {   
        super(info, number, subAddress); 
    }
    public final NumericString number    () { return get(0); }
    public final NumericString subAddress() { return get(1); }
}
