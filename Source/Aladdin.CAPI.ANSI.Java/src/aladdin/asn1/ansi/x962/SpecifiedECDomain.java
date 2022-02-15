package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.ansi.*; 
import java.math.*;
import java.io.*;
import java.util.*;

////////////////////////////////////////////////////////////////////////////////
// ECPVer ::= INTEGER {ecdpVer1(1), ecdpVer1(2), ecdpVer1(3)}
// ECPoint ::= OCTET STRING
// ECParameters ::= SEQUENCE {
//      version ECPVer,
//      fieldID FieldID,
//      curve Curve,
//      base ECPoint,
//      order INTEGER,
//      cofactor INTEGER OPTIONAL, 
//      hash AlgorithmIdentifier OPTIONAL 
// }
////////////////////////////////////////////////////////////////////////////////
public final class SpecifiedECDomain extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
        
		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(FieldID            .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Curve              .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.O), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public SpecifiedECDomain(IEncodable encodable) throws IOException 
    { 
        // вызвать базовую функцию
        super(encodable, info); Curve curve = curve(); 
        
        // проверить корректность данных
        if (curve.seed() == null && version().value().intValue() > 1) throw new IOException(); 
    }
	// конструктор при закодировании
	public SpecifiedECDomain(Integer version, FieldID fieldID, Curve curve, 
        OctetString base, Integer order, Integer cofactor, AlgorithmIdentifier hash)
	{
        // вызвать базовую функцию
		super(info, version, fieldID, curve, base, order, cofactor, hash); 

        // проверить корректность данных
        if (curve.seed() == null && version().value().intValue() > 1)
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException();
        } 
    }
	public final Integer             version () { return (Integer            )get(0); } 
	public final FieldID             fieldID () { return (FieldID            )get(1); } 
	public final Curve               curve   () { return (Curve              )get(2); } 
	public final OctetString         base    () { return (OctetString        )get(3); } 
	public final Integer             order   () { return (Integer            )get(4); } 
	public final Integer             cofactor() { return (Integer            )get(5); } 
	public final AlgorithmIdentifier hash    () { return (AlgorithmIdentifier)get(6); } 
    
    ////////////////////////////////////////////////////////////////////////////
    // Наборы c2pnb163v1, c2pnb163v2, c2pnb163v3
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2PNB163 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(163), 
            new ObjectIdentifier(OID.X962_C2_BASIS_PP), 
            new Pentanomial(new Integer(1), new Integer(2), new Integer(8))
        )
    );
    private static final Curve CURVE_C2PNB163V1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x07, (byte)0x25, (byte)0x46, (byte)0xB5, 
            (byte)0x43, (byte)0x52, (byte)0x34, (byte)0xA4, 
            (byte)0x22, (byte)0xE0, (byte)0x78, (byte)0x96, 
            (byte)0x75, (byte)0xF4, (byte)0x32, (byte)0xC8, 
            (byte)0x94, (byte)0x35, (byte)0xDE, (byte)0x52, 
            (byte)0x42
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0xC9, (byte)0x51, (byte)0x7D, 
            (byte)0x06, (byte)0xD5, (byte)0x24, (byte)0x0D, 
            (byte)0x3C, (byte)0xFF, (byte)0x38, (byte)0xC7, 
            (byte)0x4B, (byte)0x20, (byte)0xB6, (byte)0xCD, 
            (byte)0x4D, (byte)0x6F, (byte)0x9D, (byte)0xD4, 
            (byte)0xD9
        }), new BitString(new byte[] {
            (byte)0xD2, (byte)0xC0, (byte)0xFB, (byte)0x15, 
            (byte)0x76, (byte)0x08, (byte)0x60, (byte)0xDE, 
            (byte)0xF1, (byte)0xEE, (byte)0xF4, (byte)0xD6, 
            (byte)0x96, (byte)0xE6, (byte)0x76, (byte)0x87, 
            (byte)0x56, (byte)0x15, (byte)0x17, (byte)0x54
        })
    ); 
    private static final SpecifiedECDomain EC_C2PNB163V1 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2PNB163, CURVE_C2PNB163V1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x07, (byte)0xAF, (byte)0x69, (byte)0x98, 
            (byte)0x95, (byte)0x46, (byte)0x10, (byte)0x3D, (byte)0x79, 
            (byte)0x32, (byte)0x9F, (byte)0xCC, (byte)0x3D, (byte)0x74, 
            (byte)0x88, (byte)0x0F, (byte)0x33, (byte)0xBB, (byte)0xE8, 
            (byte)0x03, (byte)0xCB
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x01, (byte)0xE6, (byte)0x0F, (byte)0xC8, (byte)0x82, 
            (byte)0x1C, (byte)0xC7, (byte)0x4D, (byte)0xAE, (byte)0xAF, 
            (byte)0xC1
        })), new Integer(0x02), null
    ); 
    private static final Curve CURVE_C2PNB163V2 = new Curve(
        new OctetString(new byte[] {
            (byte)0x01, (byte)0x08, (byte)0xB3, (byte)0x9E, 
            (byte)0x77, (byte)0xC4, (byte)0xB1, (byte)0x08, 
            (byte)0xBE, (byte)0xD9, (byte)0x81, (byte)0xED, 
            (byte)0x0E, (byte)0x89, (byte)0x0E, (byte)0x11, 
            (byte)0x7C, (byte)0x51, (byte)0x1C, (byte)0xF0, 
            (byte)0x72
        }), new OctetString(new byte[] {
            (byte)0x06, (byte)0x67, (byte)0xAC, (byte)0xEB, 
            (byte)0x38, (byte)0xAF, (byte)0x4E, (byte)0x48, 
            (byte)0x8C, (byte)0x40, (byte)0x74, (byte)0x33, 
            (byte)0xFF, (byte)0xAE, (byte)0x4F, (byte)0x1C, 
            (byte)0x81, (byte)0x16, (byte)0x38, (byte)0xDF, 
            (byte)0x20 
        }), new BitString(new byte[] {
            (byte)0x53, (byte)0x81, (byte)0x4C, (byte)0x05, 
            (byte)0x0D, (byte)0x44, (byte)0xD6, (byte)0x96, 
            (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
            (byte)0x15, (byte)0x17, (byte)0x58, (byte)0x0C, 
            (byte)0xA4, (byte)0xE2, (byte)0x9F, (byte)0xFD
        })
    ); 
    private static final SpecifiedECDomain EC_C2PNB163V2 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2PNB163, CURVE_C2PNB163V2, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x00, (byte)0x24, (byte)0x26, 
            (byte)0x6E, (byte)0x4E, (byte)0xB5, (byte)0x10, 
            (byte)0x6D, (byte)0x0A, (byte)0x96, (byte)0x4D, 
            (byte)0x92, (byte)0xC4, (byte)0x86, (byte)0x0E, 
            (byte)0x26, (byte)0x71, (byte)0xDB, (byte)0x9B, 
            (byte)0x6C, (byte)0xC5
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x03, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFD, (byte)0xF6, 
            (byte)0x4D, (byte)0xE1, (byte)0x15, (byte)0x1A, 
            (byte)0xDB, (byte)0xB7, (byte)0x8F, (byte)0x10, 
            (byte)0xA7
        })), new Integer(0x02), null
    ); 
    private static final Curve CURVE_C2PNB163V3 = new Curve(
        new OctetString(new byte[] {
            (byte)0x07, (byte)0xA5, (byte)0x26, (byte)0xC6, 
            (byte)0x3D, (byte)0x3E, (byte)0x25, (byte)0xA2, 
            (byte)0x56, (byte)0xA0, (byte)0x07, (byte)0x69, 
            (byte)0x9F, (byte)0x54, (byte)0x47, (byte)0xE3, 
            (byte)0x2A, (byte)0xE4, (byte)0x56, (byte)0xB5, 
            (byte)0x0E
        }), new OctetString(new byte[] {
            (byte)0x03, (byte)0xF7, (byte)0x06, (byte)0x17, 
            (byte)0x98, (byte)0xEB, (byte)0x99, (byte)0xE2, 
            (byte)0x38, (byte)0xFD, (byte)0x6F, (byte)0x1B, 
            (byte)0xF9, (byte)0x5B, (byte)0x48, (byte)0xFE, 
            (byte)0xEB, (byte)0x48, (byte)0x54, (byte)0x25, 
            (byte)0x2B
        }), new BitString(new byte[] {
            (byte)0x50, (byte)0xCB, (byte)0xF1, (byte)0xD9, 
            (byte)0x5C, (byte)0xA9, (byte)0x4D, (byte)0x69, 
            (byte)0x6E, (byte)0x67, (byte)0x68, (byte)0x75, 
            (byte)0x61, (byte)0x51, (byte)0x75, (byte)0xF1, 
            (byte)0x6A, (byte)0x36, (byte)0xA3, (byte)0xB8
        })
    ); 
    private static final SpecifiedECDomain EC_C2PNB163V3 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2PNB163, CURVE_C2PNB163V3, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x02, (byte)0xF9, (byte)0xF8, 
            (byte)0x7B, (byte)0x7C, (byte)0x57, (byte)0x4D, 
            (byte)0x0B, (byte)0xDE, (byte)0xCF, (byte)0x8A, 
            (byte)0x22, (byte)0xE6, (byte)0x52, (byte)0x47, 
            (byte)0x75, (byte)0xF9, (byte)0x8C, (byte)0xDE, 
            (byte)0xBD, (byte)0xCB
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x03, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFE, (byte)0x1A, 
            (byte)0xEE, (byte)0x14, (byte)0x0F, (byte)0x11, 
            (byte)0x0A, (byte)0xFF, (byte)0x96, (byte)0x13, 
            (byte)0x09
        })), new Integer(0x02), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор c2pnb176w1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2PNB176 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(176), 
            new ObjectIdentifier(OID.X962_C2_BASIS_PP), 
            new Pentanomial(new Integer(1), new Integer(2), new Integer(43))
        )
    );
    private static final Curve CURVE_C2PNB176W1 = new Curve(
        new OctetString(new byte[] {
            (byte)0xE4, (byte)0xE6, (byte)0xDB, (byte)0x29, 
            (byte)0x95, (byte)0x06, (byte)0x5C, (byte)0x40, 
            (byte)0x7D, (byte)0x9D, (byte)0x39, (byte)0xB8, 
            (byte)0xD0, (byte)0x96, (byte)0x7B, (byte)0x96, 
            (byte)0x70, (byte)0x4B, (byte)0xA8, (byte)0xE9, 
            (byte)0xC9, (byte)0x0B
        }), new OctetString(new byte[] {
            (byte)0x5D, (byte)0xDA, (byte)0x47, (byte)0x0A, 
            (byte)0xBE, (byte)0x64, (byte)0x14, (byte)0xDE, 
            (byte)0x8E, (byte)0xC1, (byte)0x33, (byte)0xAE, 
            (byte)0x28, (byte)0xE9, (byte)0xBB, (byte)0xD7, 
            (byte)0xFC, (byte)0xEC, (byte)0x0A, (byte)0xE0, 
            (byte)0xFF, (byte)0xF2
        }), null
    ); 
    private static final SpecifiedECDomain EC_C2PNB176W1 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2PNB176, CURVE_C2PNB176W1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x8D, (byte)0x16, (byte)0xC2, 
            (byte)0x86, (byte)0x67, (byte)0x98, (byte)0xB6, 
            (byte)0x00, (byte)0xF9, (byte)0xF0, (byte)0x8B, 
            (byte)0xB4, (byte)0xA8, (byte)0xE8, (byte)0x60, 
            (byte)0xF3, (byte)0x29, (byte)0x8C, (byte)0xE0, 
            (byte)0x4A, (byte)0x57, (byte)0x98
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x92, (byte)0x53, 
            (byte)0x73, (byte)0x97, (byte)0xEC, (byte)0xA4, 
            (byte)0xF6, (byte)0x14, (byte)0x57, (byte)0x99, 
            (byte)0xD6, (byte)0x2B, (byte)0x0A, (byte)0x19, 
            (byte)0xCE, (byte)0x06, (byte)0xFE, (byte)0x26, 
            (byte)0xAD
        })), new Integer(0xFF6E), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы c2tnb191v1, c2tnb191v2, c2tnb191v3
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2TNB191 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(191), 
            new ObjectIdentifier(OID.X962_C2_BASIS_TP), 
            new Integer(9)
        )
    );
    private static final Curve CURVE_C2TNB191V1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x28, (byte)0x66, (byte)0x53, (byte)0x7B, 
            (byte)0x67, (byte)0x67, (byte)0x52, (byte)0x63, 
            (byte)0x6A, (byte)0x68, (byte)0xF5, (byte)0x65, 
            (byte)0x54, (byte)0xE1, (byte)0x26, (byte)0x40, 
            (byte)0x27, (byte)0x6B, (byte)0x64, (byte)0x9E, 
            (byte)0xF7, (byte)0x52, (byte)0x62, (byte)0x67
        }), new OctetString(new byte[] {
            (byte)0x2E, (byte)0x45, (byte)0xEF, (byte)0x57, 
            (byte)0x1F, (byte)0x00, (byte)0x78, (byte)0x6F, 
            (byte)0x67, (byte)0xB0, (byte)0x08, (byte)0x1B, 
            (byte)0x94, (byte)0x95, (byte)0xA3, (byte)0xD9, 
            (byte)0x54, (byte)0x62, (byte)0xF5, (byte)0xDE, 
            (byte)0x0A, (byte)0xA1, (byte)0x85, (byte)0xEC
        }), new BitString(new byte[] {
            (byte)0x4E, (byte)0x13, (byte)0xCA, (byte)0x54, 
            (byte)0x27, (byte)0x44, (byte)0xD6, (byte)0x96, 
            (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
            (byte)0x15, (byte)0x17, (byte)0x55, (byte)0x2F, 
            (byte)0x27, (byte)0x9A, (byte)0x8C, (byte)0x84
        })
    ); 
    private static final SpecifiedECDomain EC_C2TNB191V1 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2TNB191, CURVE_C2TNB191V1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x36, (byte)0xB3, (byte)0xDA, 
            (byte)0xF8, (byte)0xA2, (byte)0x32, (byte)0x06, 
            (byte)0xF9, (byte)0xC4, (byte)0xF2, (byte)0x99, 
            (byte)0xD7, (byte)0xB2, (byte)0x1A, (byte)0x9C, 
            (byte)0x36, (byte)0x91, (byte)0x37, (byte)0xF2, 
            (byte)0xC8, (byte)0x4A, (byte)0xE1, (byte)0xAA, 
            (byte)0x0D
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x40, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x04, (byte)0xA2, (byte)0x0E, (byte)0x90, 
            (byte)0xC3, (byte)0x90, (byte)0x67, (byte)0xC8, 
            (byte)0x93, (byte)0xBB, (byte)0xB9, (byte)0xA5
        })), new Integer(0x02), null
    ); 
    private static final Curve CURVE_C2TNB191V2 = new Curve(
        new OctetString(new byte[] {
            (byte)0x40, (byte)0x10, (byte)0x28, (byte)0x77, 
            (byte)0x4D, (byte)0x77, (byte)0x77, (byte)0xC7, 
            (byte)0xB7, (byte)0x66, (byte)0x6D, (byte)0x13, 
            (byte)0x66, (byte)0xEA, (byte)0x43, (byte)0x20, 
            (byte)0x71, (byte)0x27, (byte)0x4F, (byte)0x89, 
            (byte)0xFF, (byte)0x01, (byte)0xE7, (byte)0x18
        }), new OctetString(new byte[] {
            (byte)0x06, (byte)0x20, (byte)0x04, (byte)0x8D, 
            (byte)0x28, (byte)0xBC, (byte)0xBD, (byte)0x03, 
            (byte)0xB6, (byte)0x24, (byte)0x9C, (byte)0x99, 
            (byte)0x18, (byte)0x2B, (byte)0x7C, (byte)0x8C, 
            (byte)0xD1, (byte)0x97, (byte)0x00, (byte)0xC3, 
            (byte)0x62, (byte)0xC4, (byte)0x6A, (byte)0x01
        }), new BitString(new byte[] {
            (byte)0x08, (byte)0x71, (byte)0xEF, (byte)0x2F, 
            (byte)0xEF, (byte)0x24, (byte)0xD6, (byte)0x96, 
            (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
            (byte)0x15, (byte)0x17, (byte)0x58, (byte)0xBE, 
            (byte)0xE0, (byte)0xD9, (byte)0x5C, (byte)0x15        
        })
    ); 
    private static final SpecifiedECDomain EC_C2TNB191V2 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2TNB191, CURVE_C2TNB191V2, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x38, (byte)0x09, (byte)0xB2, 
            (byte)0xB7, (byte)0xCC, (byte)0x1B, (byte)0x28, 
            (byte)0xCC, (byte)0x5A, (byte)0x87, (byte)0x92, 
            (byte)0x6A, (byte)0xAD, (byte)0x83, (byte)0xFD, 
            (byte)0x28, (byte)0x78, (byte)0x9E, (byte)0x81, 
            (byte)0xE2, (byte)0xC9, (byte)0xE3, (byte)0xBF, 
            (byte)0x10        
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x50, (byte)0x50, (byte)0x8C, (byte)0xB8, 
            (byte)0x9F, (byte)0x65, (byte)0x28, (byte)0x24, 
            (byte)0xE0, (byte)0x6B, (byte)0x81, (byte)0x73
        })), new Integer(0x04), null
    ); 
    private static final Curve CURVE_C2TNB191V3 = new Curve(
        new OctetString(new byte[] {
            (byte)0x6C, (byte)0x01, (byte)0x07, (byte)0x47, 
            (byte)0x56, (byte)0x09, (byte)0x91, (byte)0x22, 
            (byte)0x22, (byte)0x10, (byte)0x56, (byte)0x91, 
            (byte)0x1C, (byte)0x77, (byte)0xD7, (byte)0x7E, 
            (byte)0x77, (byte)0xA7, (byte)0x77, (byte)0xE7, 
            (byte)0xE7, (byte)0xE7, (byte)0x7F, (byte)0xCB
        }), new OctetString(new byte[] {
            (byte)0x71, (byte)0xFE, (byte)0x1A, (byte)0xF9, 
            (byte)0x26, (byte)0xCF, (byte)0x84, (byte)0x79, 
            (byte)0x89, (byte)0xEF, (byte)0xEF, (byte)0x8D, 
            (byte)0xB4, (byte)0x59, (byte)0xF6, (byte)0x63, 
            (byte)0x94, (byte)0xD9, (byte)0x0F, (byte)0x32, 
            (byte)0xAD, (byte)0x3F, (byte)0x15, (byte)0xE8
        }), new BitString(new byte[] {
            (byte)0xE0, (byte)0x53, (byte)0x51, (byte)0x2D, 
            (byte)0xC6, (byte)0x84, (byte)0xD6, (byte)0x96, 
            (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
            (byte)0x15, (byte)0x17, (byte)0x50, (byte)0x67, 
            (byte)0xAE, (byte)0x78, (byte)0x6D, (byte)0x1F        
        })
    ); 
    private static final SpecifiedECDomain EC_C2TNB191V3 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2TNB191, CURVE_C2TNB191V3, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x37, (byte)0x5D, (byte)0x4C, 
            (byte)0xE2, (byte)0x4F, (byte)0xDE, (byte)0x43, 
            (byte)0x44, (byte)0x89, (byte)0xDE, (byte)0x87, 
            (byte)0x46, (byte)0xE7, (byte)0x17, (byte)0x86, 
            (byte)0x01, (byte)0x50, (byte)0x09, (byte)0xE6, 
            (byte)0x6E, (byte)0x38, (byte)0xA9, (byte)0x26, 
            (byte)0xDD
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x15, (byte)0x55, (byte)0x55, (byte)0x55, 
            (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
            (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
            (byte)0x61, (byte)0x0C, (byte)0x0B, (byte)0x19, 
            (byte)0x68, (byte)0x12, (byte)0xBF, (byte)0xB6, 
            (byte)0x28, (byte)0x8A, (byte)0x3E, (byte)0xA3
        })), new Integer(0x06), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы c2onb191v4, c2onb191v5
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2ONB191 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(191), 
            new ObjectIdentifier(OID.X962_C2_BASIS_GN), 
            Null.INSTANCE
        )
    );
    private static final Curve CURVE_C2ONB191V4 = new Curve(
        new OctetString(new byte[] {
            (byte)0x65, (byte)0x90, (byte)0x3E, (byte)0x04, 
            (byte)0xE1, (byte)0xE4, (byte)0x92, (byte)0x42, 
            (byte)0x53, (byte)0xE2, (byte)0x6A, (byte)0x3C, 
            (byte)0x9A, (byte)0xC2, (byte)0x8C, (byte)0x75, 
            (byte)0x8B, (byte)0xD8, (byte)0x18, (byte)0x4A, 
            (byte)0x3F, (byte)0xB6, (byte)0x80, (byte)0xE8
        }), new OctetString(new byte[] {
            (byte)0x54, (byte)0x67, (byte)0x86, (byte)0x21, 
            (byte)0xB1, (byte)0x90, (byte)0xCF, (byte)0xCE, 
            (byte)0x28, (byte)0x2A, (byte)0xDE, (byte)0x21, 
            (byte)0x9D, (byte)0x5B, (byte)0x3A, (byte)0x06, 
            (byte)0x5E, (byte)0x3F, (byte)0x4B, (byte)0x3F, 
            (byte)0xFD, (byte)0xEB, (byte)0xB2, (byte)0x9B
        }), new BitString(new byte[] {
            (byte)0xA3, (byte)0x99, (byte)0x38, (byte)0x7E, 
            (byte)0xAE, (byte)0x54, (byte)0xD6, (byte)0x96, 
            (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
            (byte)0x15, (byte)0x17, (byte)0x50, (byte)0xE5, 
            (byte)0x8B, (byte)0x41, (byte)0x6D, (byte)0x57
        })
    ); 
    private static final SpecifiedECDomain EC_C2ONB191V4 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2ONB191, CURVE_C2ONB191V4, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x5A, (byte)0x2C, (byte)0x69, 
            (byte)0xA3, (byte)0x2E, (byte)0x86, (byte)0x38, 
            (byte)0xE5, (byte)0x1C, (byte)0xCE, (byte)0xFA, 
            (byte)0xAD, (byte)0x05, (byte)0x35, (byte)0x0A, 
            (byte)0x97, (byte)0x84, (byte)0x57, (byte)0xCB, 
            (byte)0x5F, (byte)0xB6, (byte)0xDF, (byte)0x99, 
            (byte)0x4A
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x40, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x9C, (byte)0xF2, (byte)0xD6, (byte)0xE3, 
            (byte)0x90, (byte)0x1D, (byte)0xAC, (byte)0x4C, 
            (byte)0x32, (byte)0xEE, (byte)0xC6, (byte)0x5D
        })), new Integer(0x02), null
    ); 
    private static final Curve CURVE_C2ONB191V5 = new Curve(
        new OctetString(new byte[] {
            (byte)0x25, (byte)0xF8, (byte)0xD0, (byte)0x6C, 
            (byte)0x97, (byte)0xC8, (byte)0x22, (byte)0x53, 
            (byte)0x6D, (byte)0x46, (byte)0x9C, (byte)0xD5, 
            (byte)0x17, (byte)0x0C, (byte)0xDD, (byte)0x7B, 
            (byte)0xB9, (byte)0xF5, (byte)0x00, (byte)0xBD, 
            (byte)0x6D, (byte)0xB1, (byte)0x10, (byte)0xFB
        }), new OctetString(new byte[] {
            (byte)0x75, (byte)0xFF, (byte)0x57, (byte)0x0E, 
            (byte)0x35, (byte)0xCA, (byte)0x94, (byte)0xFB, 
            (byte)0x37, (byte)0x80, (byte)0xC2, (byte)0x61, 
            (byte)0x9D, (byte)0x08, (byte)0x1C, (byte)0x17, 
            (byte)0xAA, (byte)0x59, (byte)0xFB, (byte)0xD5, 
            (byte)0xE5, (byte)0x91, (byte)0xC1, (byte)0xC4
        }), new BitString(new byte[] {
            (byte)0x2D, (byte)0x88, (byte)0xF7, (byte)0xBC, 
            (byte)0x54, (byte)0x57, (byte)0x94, (byte)0xD6, 
            (byte)0x96, (byte)0xE6, (byte)0x76, (byte)0x87, 
            (byte)0x56, (byte)0x15, (byte)0x17, (byte)0x59, 
            (byte)0x73, (byte)0x39, (byte)0x15, (byte)0x55        
        })
    ); 
    private static final SpecifiedECDomain EC_C2ONB191V5 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2ONB191, CURVE_C2ONB191V5, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x2A, (byte)0x16, (byte)0x91, 
            (byte)0x0E, (byte)0x8F, (byte)0x6C, (byte)0x4B, 
            (byte)0x19, (byte)0x9B, (byte)0xE2, (byte)0x42, 
            (byte)0x13, (byte)0x85, (byte)0x7A, (byte)0xBC, 
            (byte)0x9C, (byte)0x99, (byte)0x2E, (byte)0xDF, 
            (byte)0xB2, (byte)0x47, (byte)0x1F, (byte)0x3C, 
            (byte)0x68
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x0F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xEE, (byte)0xB3, (byte)0x54, (byte)0xB7, 
            (byte)0x27, (byte)0x0B, (byte)0x29, (byte)0x92, 
            (byte)0xB7, (byte)0x81, (byte)0x86, (byte)0x27
        })), new Integer(0x08), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор c2pnb208w1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2PNB208 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(208), 
            new ObjectIdentifier(OID.X962_C2_BASIS_PP), 
            new Pentanomial(new Integer(1), new Integer(2), new Integer(83))
        )
    );
    private static final Curve CURVE_C2PNB208W1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00
        }), new OctetString(new byte[] {
            (byte)0xC8, (byte)0x61, (byte)0x9E, (byte)0xD4, 
            (byte)0x5A, (byte)0x62, (byte)0xE6, (byte)0x21, 
            (byte)0x2E, (byte)0x11, (byte)0x60, (byte)0x34, 
            (byte)0x9E, (byte)0x2B, (byte)0xFA, (byte)0x84, 
            (byte)0x44, (byte)0x39, (byte)0xFA, (byte)0xFC, 
            (byte)0x2A, (byte)0x3F, (byte)0xD1, (byte)0x63, 
            (byte)0x8F, (byte)0x9E
        }), null
    ); 
    private static final SpecifiedECDomain EC_C2PNB208W1 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2PNB208, CURVE_C2PNB208W1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x89, (byte)0xFD, (byte)0xFB, 
            (byte)0xE4, (byte)0xAB, (byte)0xE1, (byte)0x93, 
            (byte)0xDF, (byte)0x95, (byte)0x59, (byte)0xEC, 
            (byte)0xF0, (byte)0x7A, (byte)0xC0, (byte)0xCE, 
            (byte)0x78, (byte)0x55, (byte)0x4E, (byte)0x27, 
            (byte)0x84, (byte)0xEB, (byte)0x8C, (byte)0x1E, 
            (byte)0xD1, (byte)0xA5, (byte)0x7A
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x01, (byte)0xBA, (byte)0xF9, 
            (byte)0x5C, (byte)0x97, (byte)0x23, (byte)0xC5, 
            (byte)0x7B, (byte)0x6C, (byte)0x21, (byte)0xDA, 
            (byte)0x2E, (byte)0xFF, (byte)0x2D, (byte)0x5E, 
            (byte)0xD5, (byte)0x88, (byte)0xBD, (byte)0xD5, 
            (byte)0x71, (byte)0x7E, (byte)0x21, (byte)0x2F, 
            (byte)0x9D
        })), new Integer(0xFE48), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы c2tnb239v1, c2tnb239v2, c2tnb239v3
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2TNB239 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(239), 
            new ObjectIdentifier(OID.X962_C2_BASIS_TP), 
            new Integer(36)
        )
    );
    private static final Curve CURVE_C2TNB239V1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x32, (byte)0x01, (byte)0x08, (byte)0x57, 
            (byte)0x07, (byte)0x7C, (byte)0x54, (byte)0x31, 
            (byte)0x12, (byte)0x3A, (byte)0x46, (byte)0xB8, 
            (byte)0x08, (byte)0x90, (byte)0x67, (byte)0x56, 
            (byte)0xF5, (byte)0x43, (byte)0x42, (byte)0x3E, 
            (byte)0x8D, (byte)0x27, (byte)0x87, (byte)0x75, 
            (byte)0x78, (byte)0x12, (byte)0x57, (byte)0x78, 
            (byte)0xAC, (byte)0x76        
        }), new OctetString(new byte[] {
            (byte)0x79, (byte)0x04, (byte)0x08, (byte)0xF2, 
            (byte)0xEE, (byte)0xDA, (byte)0xF3, (byte)0x92, 
            (byte)0xB0, (byte)0x12, (byte)0xED, (byte)0xEF, 
            (byte)0xB3, (byte)0x39, (byte)0x2F, (byte)0x30, 
            (byte)0xF4, (byte)0x32, (byte)0x7C, (byte)0x0C, 
            (byte)0xA3, (byte)0xF3, (byte)0x1F, (byte)0xC3, 
            (byte)0x83, (byte)0xC4, (byte)0x22, (byte)0xAA, 
            (byte)0x8C, (byte)0x16
        }), new BitString(new byte[] {
            (byte)0xD3, (byte)0x4B, (byte)0x9A, (byte)0x4D, 
            (byte)0x69, (byte)0x6E, (byte)0x67, (byte)0x68, 
            (byte)0x75, (byte)0x61, (byte)0x51, (byte)0x75, 
            (byte)0xCA, (byte)0x71, (byte)0xB9, (byte)0x20, 
            (byte)0xBF, (byte)0xEF, (byte)0xB0, (byte)0x5D
        })
    ); 
    private static final SpecifiedECDomain EC_C2TNB239V1 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2TNB239, CURVE_C2TNB239V1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x57, (byte)0x92, (byte)0x70, 
            (byte)0x98, (byte)0xFA, (byte)0x93, (byte)0x2E, 
            (byte)0x7C, (byte)0x0A, (byte)0x96, (byte)0xD3, 
            (byte)0xFD, (byte)0x5B, (byte)0x70, (byte)0x6E, 
            (byte)0xF7, (byte)0xE5, (byte)0xF5, (byte)0xC1, 
            (byte)0x56, (byte)0xE1, (byte)0x6B, (byte)0x7E, 
            (byte)0x7C, (byte)0x86, (byte)0x03, (byte)0x85, 
            (byte)0x52, (byte)0xE9, (byte)0x1D
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x0F, 
            (byte)0x4D, (byte)0x42, (byte)0xFF, (byte)0xE1, 
            (byte)0x49, (byte)0x2A, (byte)0x49, (byte)0x93, 
            (byte)0xF1, (byte)0xCA, (byte)0xD6, (byte)0x66, 
            (byte)0xE4, (byte)0x47
        })), new Integer(0x04), null
    ); 
    private static final Curve CURVE_C2TNB239V2 = new Curve(
        new OctetString(new byte[] {
            (byte)0x42, (byte)0x30, (byte)0x01, (byte)0x77, 
            (byte)0x57, (byte)0xA7, (byte)0x67, (byte)0xFA, 
            (byte)0xE4, (byte)0x23, (byte)0x98, (byte)0x56, 
            (byte)0x9B, (byte)0x74, (byte)0x63, (byte)0x25, 
            (byte)0xD4, (byte)0x53, (byte)0x13, (byte)0xAF, 
            (byte)0x07, (byte)0x66, (byte)0x26, (byte)0x64, 
            (byte)0x79, (byte)0xB7, (byte)0x56, (byte)0x54, 
            (byte)0xE6, (byte)0x5F
        }), new OctetString(new byte[] {
            (byte)0x50, (byte)0x37, (byte)0xEA, (byte)0x65, 
            (byte)0x41, (byte)0x96, (byte)0xCF, (byte)0xF0, 
            (byte)0xCD, (byte)0x82, (byte)0xB2, (byte)0xC1, 
            (byte)0x4A, (byte)0x2F, (byte)0xCF, (byte)0x2E, 
            (byte)0x3F, (byte)0xF8, (byte)0x77, (byte)0x52, 
            (byte)0x85, (byte)0xB5, (byte)0x45, (byte)0x72, 
            (byte)0x2F, (byte)0x03, (byte)0xEA, (byte)0xCD, 
            (byte)0xB7, (byte)0x4B
        }), new BitString(new byte[] {
            (byte)0x2A, (byte)0xA6, (byte)0x98, (byte)0x2F, 
            (byte)0xDF, (byte)0xA4, (byte)0xD6, (byte)0x96, 
            (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
            (byte)0x15, (byte)0x17, (byte)0x5D, (byte)0x26, 
            (byte)0x67, (byte)0x27, (byte)0x27, (byte)0x7D        
        })
    ); 
    private static final SpecifiedECDomain EC_C2TNB239V2 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2TNB239, CURVE_C2TNB239V2, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x28, (byte)0xF9, (byte)0xD0, 
            (byte)0x4E, (byte)0x90, (byte)0x00, (byte)0x69, 
            (byte)0xC8, (byte)0xDC, (byte)0x47, (byte)0xA0, 
            (byte)0x85, (byte)0x34, (byte)0xFE, (byte)0x76, 
            (byte)0xD2, (byte)0xB9, (byte)0x00, (byte)0xB7, 
            (byte)0xD7, (byte)0xEF, (byte)0x31, (byte)0xF5, 
            (byte)0x70, (byte)0x9F, (byte)0x20, (byte)0x0C, 
            (byte)0x4C, (byte)0xA2, (byte)0x05
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x15, (byte)0x55, (byte)0x55, (byte)0x55, 
            (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
            (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
            (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x3C, 
            (byte)0x6F, (byte)0x28, (byte)0x85, (byte)0x25, 
            (byte)0x9C, (byte)0x31, (byte)0xE3, (byte)0xFC, 
            (byte)0xDF, (byte)0x15, (byte)0x46, (byte)0x24, 
            (byte)0x52, (byte)0x2D
        })), new Integer(0x06), null
    ); 
    private static final Curve CURVE_C2TNB239V3 = new Curve(
        new OctetString(new byte[] {
            (byte)0x01, (byte)0x23, (byte)0x87, (byte)0x74, 
            (byte)0x66, (byte)0x6A, (byte)0x67, (byte)0x76, 
            (byte)0x6D, (byte)0x66, (byte)0x76, (byte)0xF7, 
            (byte)0x78, (byte)0xE6, (byte)0x76, (byte)0xB6, 
            (byte)0x69, (byte)0x99, (byte)0x17, (byte)0x66, 
            (byte)0x66, (byte)0xE6, (byte)0x87, (byte)0x66, 
            (byte)0x6D, (byte)0x87, (byte)0x66, (byte)0xC6, 
            (byte)0x6A, (byte)0x9F
        }), new OctetString(new byte[] {
            (byte)0x6A, (byte)0x94, (byte)0x19, (byte)0x77, 
            (byte)0xBA, (byte)0x9F, (byte)0x6A, (byte)0x43, 
            (byte)0x51, (byte)0x99, (byte)0xAC, (byte)0xFC, 
            (byte)0x51, (byte)0x06, (byte)0x7E, (byte)0xD5, 
            (byte)0x87, (byte)0xF5, (byte)0x19, (byte)0xC5, 
            (byte)0xEC, (byte)0xB5, (byte)0x41, (byte)0xB8, 
            (byte)0xE4, (byte)0x41, (byte)0x11, (byte)0xDE, 
            (byte)0x1D, (byte)0x40
        }), new BitString(new byte[] {
            (byte)0x9E, (byte)0x07, (byte)0x6F, (byte)0x4D, 
            (byte)0x69, (byte)0x6E, (byte)0x67, (byte)0x68, 
            (byte)0x75, (byte)0x61, (byte)0x51, (byte)0x75, 
            (byte)0xE1, (byte)0x1E, (byte)0x9F, (byte)0xDD, 
            (byte)0x77, (byte)0xF9, (byte)0x20, (byte)0x41
        })
    ); 
    private static final SpecifiedECDomain EC_C2TNB239V3 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2TNB239, CURVE_C2TNB239V3, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x70, (byte)0xF6, (byte)0xE9, 
            (byte)0xD0, (byte)0x4D, (byte)0x28, (byte)0x9C, 
            (byte)0x4E, (byte)0x89, (byte)0x91, (byte)0x3C, 
            (byte)0xE3, (byte)0x53, (byte)0x0B, (byte)0xFD, 
            (byte)0xE9, (byte)0x03, (byte)0x97, (byte)0x7D, 
            (byte)0x42, (byte)0xB1, (byte)0x46, (byte)0xD5, 
            (byte)0x39, (byte)0xBF, (byte)0x1B, (byte)0xDE, 
            (byte)0x4E, (byte)0x9C, (byte)0x92
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x0C, (byte)0xCC, (byte)0xCC, (byte)0xCC, 
            (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xCC, 
            (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xCC, 
            (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xAC, 
            (byte)0x49, (byte)0x12, (byte)0xD2, (byte)0xD9, 
            (byte)0xDF, (byte)0x90, (byte)0x3E, (byte)0xF9, 
            (byte)0x88, (byte)0x8B, (byte)0x8A, (byte)0x0E, 
            (byte)0x4C, (byte)0xFF        
        })), new Integer(0x0A), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы c2onb239v4, c2onb239v5
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2ONB239 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(239), 
            new ObjectIdentifier(OID.X962_C2_BASIS_GN), 
            Null.INSTANCE
        )
    );
    private static final Curve CURVE_C2ONB239V4 = new Curve(
        new OctetString(new byte[] {
            (byte)0x18, (byte)0x2D, (byte)0xD4, (byte)0x5F, 
            (byte)0x5D, (byte)0x47, (byte)0x02, (byte)0x39, 
            (byte)0xB8, (byte)0x98, (byte)0x3F, (byte)0xEA, 
            (byte)0x47, (byte)0xB8, (byte)0xB2, (byte)0x92, 
            (byte)0x64, (byte)0x1C, (byte)0x57, (byte)0xF9, 
            (byte)0xBF, (byte)0x84, (byte)0xBA, (byte)0xEC, 
            (byte)0xDE, (byte)0x8B, (byte)0xB3, (byte)0xAD, 
            (byte)0xCE, (byte)0x30
        }), new OctetString(new byte[] {
            (byte)0x14, (byte)0x7A, (byte)0x9C, (byte)0x1D, 
            (byte)0x4C, (byte)0x2C, (byte)0xE9, (byte)0xBE, 
            (byte)0x5D, (byte)0x34, (byte)0xEC, (byte)0x02, 
            (byte)0x79, (byte)0x7F, (byte)0x76, (byte)0x66,
            (byte)0x7E, (byte)0xBA, (byte)0xD5, (byte)0xA3, 
            (byte)0xF9, (byte)0x3F, (byte)0xA2, (byte)0xA5, 
            (byte)0x24, (byte)0xBF, (byte)0xDE, (byte)0x91, 
            (byte)0xEF, (byte)0x28
        }), new BitString(new byte[] {
            (byte)0xF8, (byte)0x51, (byte)0x63, (byte)0x8C, 
            (byte)0xFA, (byte)0x4D, (byte)0x69, (byte)0x6E, 
            (byte)0x67, (byte)0x68, (byte)0x75, (byte)0x61, 
            (byte)0x51, (byte)0x75, (byte)0x56, (byte)0x51, 
            (byte)0x38, (byte)0x41, (byte)0xBF, (byte)0xAC
        })
    ); 
    private static final SpecifiedECDomain EC_C2ONB239V4 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2ONB239, CURVE_C2ONB239V4, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x49, (byte)0x12, (byte)0xAD, 
            (byte)0x65, (byte)0x7F, (byte)0x1D, (byte)0x1C, 
            (byte)0x6B, (byte)0x32, (byte)0xED, (byte)0xB9, 
            (byte)0x94, (byte)0x2C, (byte)0x95, (byte)0xE2, 
            (byte)0x26, (byte)0xB0, (byte)0x6F, (byte)0xB0, 
            (byte)0x12, (byte)0xCD, (byte)0x40, (byte)0xFD, 
            (byte)0xEA, (byte)0x0D, (byte)0x72, (byte)0x19, 
            (byte)0x7C, (byte)0x81, (byte)0x04
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x47, 
            (byte)0x4F, (byte)0x7E, (byte)0x69, (byte)0xF4, 
            (byte)0x2F, (byte)0xE4, (byte)0x30, (byte)0x93, 
            (byte)0x1D, (byte)0x0B, (byte)0x45, (byte)0x5A, 
            (byte)0xAE, (byte)0x8B
        })), new Integer(0x04), null
    ); 
    private static final Curve CURVE_C2ONB239V5 = new Curve(
        new OctetString(new byte[] {
            (byte)0x1E, (byte)0xCF, (byte)0x1B, (byte)0x9D, 
            (byte)0x28, (byte)0xD8, (byte)0x01, (byte)0x75, 
            (byte)0x05, (byte)0xE1, (byte)0x74, (byte)0x75, 
            (byte)0xD3, (byte)0xDF, (byte)0x29, (byte)0x82, 
            (byte)0xE2, (byte)0x43, (byte)0xCA, (byte)0x5C, 
            (byte)0xB5, (byte)0xE9, (byte)0xF9, (byte)0x4A, 
            (byte)0x3F, (byte)0x36, (byte)0x12, (byte)0x4A, 
            (byte)0x48, (byte)0x6E
        }), new OctetString(new byte[] {
            (byte)0x3E, (byte)0xE2, (byte)0x57, (byte)0x25, 
            (byte)0x0D, (byte)0x1A, (byte)0x2E, (byte)0x66, 
            (byte)0xCE, (byte)0xF2, (byte)0x3A, (byte)0xA0, 
            (byte)0xF2, (byte)0x5B, (byte)0x12, (byte)0x38, 
            (byte)0x8D, (byte)0xE8, (byte)0xA1, (byte)0x0F, 
            (byte)0xF9, (byte)0x55, (byte)0x4F, (byte)0x90, 
            (byte)0xAF, (byte)0xBA, (byte)0xA9, (byte)0xA0, 
            (byte)0x8B, (byte)0x6D
        }), new BitString(new byte[] {
            (byte)0x2C, (byte)0x04, (byte)0xF4, (byte)0x4D, 
            (byte)0x69, (byte)0x6E, (byte)0x67, (byte)0x68, 
            (byte)0x75, (byte)0x61, (byte)0x51, (byte)0x75, 
            (byte)0xC5, (byte)0x86, (byte)0xB4, (byte)0x1F, 
            (byte)0x6C, (byte)0xA1, (byte)0x50, (byte)0xC9
        })
    ); 
    private static final SpecifiedECDomain EC_C2ONB239V5 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2ONB239, CURVE_C2ONB239V5, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x19, (byte)0x32, (byte)0x79, 
            (byte)0xFC, (byte)0x54, (byte)0x3E, (byte)0x9F, 
            (byte)0x5F, (byte)0x71, (byte)0x19, (byte)0x18, 
            (byte)0x97, (byte)0x85, (byte)0xB9, (byte)0xC6, 
            (byte)0x0B, (byte)0x24, (byte)0x9B, (byte)0xE4, 
            (byte)0x82, (byte)0x0B, (byte)0xAF, (byte)0x6C, 
            (byte)0x24, (byte)0xBD, (byte)0xFA, (byte)0x28, 
            (byte)0x13, (byte)0xF8, (byte)0xB8
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x15, (byte)0x55, (byte)0x55, (byte)0x55, 
            (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
            (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
            (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x8C, 
            (byte)0xF7, (byte)0x7A, (byte)0x5D, (byte)0x05, 
            (byte)0x89, (byte)0xD2, (byte)0xA9, (byte)0x34, 
            (byte)0x0D, (byte)0x96, (byte)0x3B, (byte)0x7A, 
            (byte)0xD7, (byte)0x03
        })), new Integer(0x06), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор c2pnb208w1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2PNB272 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(272), 
            new ObjectIdentifier(OID.X962_C2_BASIS_PP), 
            new Pentanomial(new Integer(1), new Integer(3), new Integer(56))
        )
    );
    private static final Curve CURVE_C2PNB272W1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x91, (byte)0xA0, (byte)0x91, (byte)0xF0, 
            (byte)0x3B, (byte)0x5F, (byte)0xBA, (byte)0x4A, 
            (byte)0xB2, (byte)0xCC, (byte)0xF4, (byte)0x9C, 
            (byte)0x4E, (byte)0xDD, (byte)0x22, (byte)0x0F, 
            (byte)0xB0, (byte)0x28, (byte)0x71, (byte)0x2D, 
            (byte)0x42, (byte)0xBE, (byte)0x75, (byte)0x2B, 
            (byte)0x2C, (byte)0x40, (byte)0x09, (byte)0x4D, 
            (byte)0xBA, (byte)0xCD, (byte)0xB5, (byte)0x86, 
            (byte)0xFB, (byte)0x20
        }), new OctetString(new byte[] {
            (byte)0x71, (byte)0x67, (byte)0xEF, (byte)0xC9, 
            (byte)0x2B, (byte)0xB2, (byte)0xE3, (byte)0xCE, 
            (byte)0x7C, (byte)0x8A, (byte)0xAA, (byte)0xFF, 
            (byte)0x34, (byte)0xE1, (byte)0x2A, (byte)0x9C, 
            (byte)0x55, (byte)0x70, (byte)0x03, (byte)0xD7, 
            (byte)0xC7, (byte)0x3A, (byte)0x6F, (byte)0xAF, 
            (byte)0x00, (byte)0x3F, (byte)0x99, (byte)0xF6, 
            (byte)0xCC, (byte)0x84, (byte)0x82, (byte)0xE5, 
            (byte)0x40, (byte)0xF7
        }), null
    ); 
    private static final SpecifiedECDomain EC_C2PNB272W1 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2PNB272, CURVE_C2PNB272W1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x61, (byte)0x08, (byte)0xBA, 
            (byte)0xBB, (byte)0x2C, (byte)0xEE, (byte)0xBC, 
            (byte)0xF7, (byte)0x87, (byte)0x05, (byte)0x8A, 
            (byte)0x05, (byte)0x6C, (byte)0xBE, (byte)0x0C, 
            (byte)0xFE, (byte)0x62, (byte)0x2D, (byte)0x77, 
            (byte)0x23, (byte)0xA2, (byte)0x89, (byte)0xE0, 
            (byte)0x8A, (byte)0x07, (byte)0xAE, (byte)0x13, 
            (byte)0xEF, (byte)0x0D, (byte)0x10, (byte)0xD1, 
            (byte)0x71, (byte)0xDD, (byte)0x8D
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0xFA, (byte)0xF5, 
            (byte)0x13, (byte)0x54, (byte)0xE0, (byte)0xE3, 
            (byte)0x9E, (byte)0x48, (byte)0x92, (byte)0xDF, 
            (byte)0x6E, (byte)0x31, (byte)0x9C, (byte)0x72, 
            (byte)0xC8, (byte)0x16, (byte)0x16, (byte)0x03, 
            (byte)0xFA, (byte)0x45, (byte)0xAA, (byte)0x7B, 
            (byte)0x99, (byte)0x8A, (byte)0x16, (byte)0x7B, 
            (byte)0x8F, (byte)0x1E, (byte)0x62, (byte)0x95, 
            (byte)0x21
        })), new Integer(0xFF06), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор c2pnb304w1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2PNB304 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(304), 
            new ObjectIdentifier(OID.X962_C2_BASIS_PP), 
            new Pentanomial(new Integer(1), new Integer(2), new Integer(11))
        )
    );
    private static final Curve CURVE_C2PNB304W1 = new Curve(
        new OctetString(new byte[] {
            (byte)0xFD, (byte)0x0D, (byte)0x69, (byte)0x31, 
            (byte)0x49, (byte)0xA1, (byte)0x18, (byte)0xF6, 
            (byte)0x51, (byte)0xE6, (byte)0xDC, (byte)0xE6, 
            (byte)0x80, (byte)0x20, (byte)0x85, (byte)0x37, 
            (byte)0x7E, (byte)0x5F, (byte)0x88, (byte)0x2D, 
            (byte)0x1B, (byte)0x51, (byte)0x0B, (byte)0x44, 
            (byte)0x16, (byte)0x00, (byte)0x74, (byte)0xC1, 
            (byte)0x28, (byte)0x80, (byte)0x78, (byte)0x36, 
            (byte)0x5A, (byte)0x03, (byte)0x96, (byte)0xC8, 
            (byte)0xE6, (byte)0x81
        }), new OctetString(new byte[] {
            (byte)0xBD, (byte)0xDB, (byte)0x97, (byte)0xE5, 
            (byte)0x55, (byte)0xA5, (byte)0x0A, (byte)0x90, 
            (byte)0x8E, (byte)0x43, (byte)0xB0, (byte)0x1C, 
            (byte)0x79, (byte)0x8E, (byte)0xA5, (byte)0xDA, 
            (byte)0xA6, (byte)0x78, (byte)0x8F, (byte)0x1E, 
            (byte)0xA2, (byte)0x79, (byte)0x4E, (byte)0xFC, 
            (byte)0xF5, (byte)0x71, (byte)0x66, (byte)0xB8, 
            (byte)0xC1, (byte)0x40, (byte)0x39, (byte)0x60, 
            (byte)0x1E, (byte)0x55, (byte)0x82, (byte)0x73, 
            (byte)0x40, (byte)0xBE
        }), null
    ); 
    private static final SpecifiedECDomain EC_C2PNB304W1 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2PNB304, CURVE_C2PNB304W1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x19, (byte)0x7B, (byte)0x07, 
            (byte)0x84, (byte)0x5E, (byte)0x9B, (byte)0xE2, 
            (byte)0xD9, (byte)0x6A, (byte)0xDB, (byte)0x0F, 
            (byte)0x5F, (byte)0x3C, (byte)0x7F, (byte)0x2C, 
            (byte)0xFF, (byte)0xBD, (byte)0x7A, (byte)0x3E, 
            (byte)0xB8, (byte)0xB6, (byte)0xFE, (byte)0xC3, 
            (byte)0x5C, (byte)0x7F, (byte)0xD6, (byte)0x7F, 
            (byte)0x26, (byte)0xDD, (byte)0xF6, (byte)0x28, 
            (byte)0x5A, (byte)0x64, (byte)0x4F, (byte)0x74, 
            (byte)0x0A, (byte)0x26, (byte)0x14
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x01, (byte)0xD5, (byte)0x56, 
            (byte)0x57, (byte)0x2A, (byte)0xAB, (byte)0xAC, 
            (byte)0x80, (byte)0x01, (byte)0x01, (byte)0xD5, 
            (byte)0x56, (byte)0x57, (byte)0x2A, (byte)0xAB, 
            (byte)0xAC, (byte)0x80, (byte)0x01, (byte)0x02, 
            (byte)0x2D, (byte)0x5C, (byte)0x91, (byte)0xDD, 
            (byte)0x17, (byte)0x3F, (byte)0x8F, (byte)0xB5, 
            (byte)0x61, (byte)0xDA, (byte)0x68, (byte)0x99, 
            (byte)0x16, (byte)0x44, (byte)0x43, (byte)0x05, 
            (byte)0x1D
        })), new Integer(0xFE2E), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор c2tnb359v1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2TNB359 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(359), 
            new ObjectIdentifier(OID.X962_C2_BASIS_TP), 
            new Integer(68)
        )
    );
    private static final Curve CURVE_C2TNB359V1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x56, (byte)0x67, (byte)0x67, (byte)0x6A, 
            (byte)0x65, (byte)0x4B, (byte)0x20, (byte)0x75, 
            (byte)0x4F, (byte)0x35, (byte)0x6E, (byte)0xA9, 
            (byte)0x20, (byte)0x17, (byte)0xD9, (byte)0x46, 
            (byte)0x56, (byte)0x7C, (byte)0x46, (byte)0x67, 
            (byte)0x55, (byte)0x56, (byte)0xF1, (byte)0x95, 
            (byte)0x56, (byte)0xA0, (byte)0x46, (byte)0x16, 
            (byte)0xB5, (byte)0x67, (byte)0xD2, (byte)0x23, 
            (byte)0xA5, (byte)0xE0, (byte)0x56, (byte)0x56, 
            (byte)0xFB, (byte)0x54, (byte)0x90, (byte)0x16, 
            (byte)0xA9, (byte)0x66, (byte)0x56, (byte)0xA5, 
            (byte)0x57
        }), new OctetString(new byte[] {
            (byte)0x24, (byte)0x72, (byte)0xE2, (byte)0xD0, 
            (byte)0x19, (byte)0x7C, (byte)0x49, (byte)0x36, 
            (byte)0x3F, (byte)0x1F, (byte)0xE7, (byte)0xF5, 
            (byte)0xB6, (byte)0xDB, (byte)0x07, (byte)0x5D, 
            (byte)0x52, (byte)0xB6, (byte)0x94, (byte)0x7D, 
            (byte)0x13, (byte)0x5D, (byte)0x8C, (byte)0xA4, 
            (byte)0x45, (byte)0x80, (byte)0x5D, (byte)0x39, 
            (byte)0xBC, (byte)0x34, (byte)0x56, (byte)0x26, 
            (byte)0x08, (byte)0x96, (byte)0x87, (byte)0x74, 
            (byte)0x2B, (byte)0x63, (byte)0x29, (byte)0xE7, 
            (byte)0x06, (byte)0x80, (byte)0x23, (byte)0x19, 
            (byte)0x88
        }), new BitString(new byte[] {
            (byte)0x2B, (byte)0x35, (byte)0x49, (byte)0x20, 
            (byte)0xB7, (byte)0x24, (byte)0xD6, (byte)0x96, 
            (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
            (byte)0x15, (byte)0x17, (byte)0x58, (byte)0x5B, 
            (byte)0xA1, (byte)0x33, (byte)0x2D, (byte)0xC6
        })
    ); 
    private static final SpecifiedECDomain EC_C2TNB359V1 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2TNB359, CURVE_C2TNB359V1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x3C, (byte)0x25, (byte)0x8E, 
            (byte)0xF3, (byte)0x04, (byte)0x77, (byte)0x67, 
            (byte)0xE7, (byte)0xED, (byte)0xE0, (byte)0xF1, 
            (byte)0xFD, (byte)0xAA, (byte)0x79, (byte)0xDA, 
            (byte)0xEE, (byte)0x38, (byte)0x41, (byte)0x36, 
            (byte)0x6A, (byte)0x13, (byte)0x2E, (byte)0x16, 
            (byte)0x3A, (byte)0xCE, (byte)0xD4, (byte)0xED, 
            (byte)0x24, (byte)0x01, (byte)0xDF, (byte)0x9C, 
            (byte)0x6B, (byte)0xDC, (byte)0xDE, (byte)0x98, 
            (byte)0xE8, (byte)0xE7, (byte)0x07, (byte)0xC0, 
            (byte)0x7A, (byte)0x22, (byte)0x39, (byte)0xB1, 
            (byte)0xB0, (byte)0x97
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0xAF, (byte)0x28, (byte)0x6B, 
            (byte)0xCA, (byte)0x1A, (byte)0xF2, (byte)0x86, 
            (byte)0xBC, (byte)0xA1, (byte)0xAF, (byte)0x28, 
            (byte)0x6B, (byte)0xCA, (byte)0x1A, (byte)0xF2, 
            (byte)0x86, (byte)0xBC, (byte)0xA1, (byte)0xAF, 
            (byte)0x28, (byte)0x6B, (byte)0xC9, (byte)0xFB, 
            (byte)0x8F, (byte)0x6B, (byte)0x85, (byte)0xC5, 
            (byte)0x56, (byte)0x89, (byte)0x2C, (byte)0x20, 
            (byte)0xA7, (byte)0xEB, (byte)0x96, (byte)0x4F, 
            (byte)0xE7, (byte)0x71, (byte)0x9E, (byte)0x74, 
            (byte)0xF4, (byte)0x90, (byte)0x75, (byte)0x8D, 
            (byte)0x3B
        })), new Integer(0x4C), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор c2pnb368w1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2PNB368 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(368), 
            new ObjectIdentifier(OID.X962_C2_BASIS_PP), 
            new Pentanomial(new Integer(1), new Integer(2), new Integer(85))
        )
    );
    private static final Curve CURVE_C2PNB368W1 = new Curve(
        new OctetString(new byte[] {
            (byte)0xE0, (byte)0xD2, (byte)0xEE, (byte)0x25, 
            (byte)0x09, (byte)0x52, (byte)0x06, (byte)0xF5, 
            (byte)0xE2, (byte)0xA4, (byte)0xF9, (byte)0xED, 
            (byte)0x22, (byte)0x9F, (byte)0x1F, (byte)0x25, 
            (byte)0x6E, (byte)0x79, (byte)0xA0, (byte)0xE2, 
            (byte)0xB4, (byte)0x55, (byte)0x97, (byte)0x0D, 
            (byte)0x8D, (byte)0x0D, (byte)0x86, (byte)0x5B, 
            (byte)0xD9, (byte)0x47, (byte)0x78, (byte)0xC5, 
            (byte)0x76, (byte)0xD6, (byte)0x2F, (byte)0x0A, 
            (byte)0xB7, (byte)0x51, (byte)0x9C, (byte)0xCD, 
            (byte)0x2A, (byte)0x1A, (byte)0x90, (byte)0x6A, 
            (byte)0xE3, (byte)0x0D
        }), new OctetString(new byte[] {
            (byte)0xFC, (byte)0x12, (byte)0x17, (byte)0xD4, 
            (byte)0x32, (byte)0x0A, (byte)0x90, (byte)0x45, 
            (byte)0x2C, (byte)0x76, (byte)0x0A, (byte)0x58, 
            (byte)0xED, (byte)0xCD, (byte)0x30, (byte)0xC8, 
            (byte)0xDD, (byte)0x06, (byte)0x9B, (byte)0x3C, 
            (byte)0x34, (byte)0x45, (byte)0x38, (byte)0x37, 
            (byte)0xA3, (byte)0x4E, (byte)0xD5, (byte)0x0C, 
            (byte)0xB5, (byte)0x49, (byte)0x17, (byte)0xE1, 
            (byte)0xC2, (byte)0x11, (byte)0x2D, (byte)0x84, 
            (byte)0xD1, (byte)0x64, (byte)0xF4, (byte)0x44, 
            (byte)0xF8, (byte)0xF7, (byte)0x47, (byte)0x86, 
            (byte)0x04, (byte)0x6A
        }), null
    ); 
    private static final SpecifiedECDomain EC_C2PNB368W1 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2PNB368, CURVE_C2PNB368W1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x10, (byte)0x85, (byte)0xE2, 
            (byte)0x75, (byte)0x53, (byte)0x81, (byte)0xDC, 
            (byte)0xCC, (byte)0xE3, (byte)0xC1, (byte)0x55, 
            (byte)0x7A, (byte)0xFA, (byte)0x10, (byte)0xC2, 
            (byte)0xF0, (byte)0xC0, (byte)0xC2, (byte)0x82, 
            (byte)0x56, (byte)0x46, (byte)0xC5, (byte)0xB3, 
            (byte)0x4A, (byte)0x39, (byte)0x4C, (byte)0xBC, 
            (byte)0xFA, (byte)0x8B, (byte)0xC1, (byte)0x6B, 
            (byte)0x22, (byte)0xE7, (byte)0xE7, (byte)0x89, 
            (byte)0xE9, (byte)0x27, (byte)0xBE, (byte)0x21, 
            (byte)0x6F, (byte)0x02, (byte)0xE1, (byte)0xFB, 
            (byte)0x13, (byte)0x6A, (byte)0x5F
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x90, (byte)0x51, 
            (byte)0x2D, (byte)0xA9, (byte)0xAF, (byte)0x72, 
            (byte)0xB0, (byte)0x83, (byte)0x49, (byte)0xD9, 
            (byte)0x8A, (byte)0x5D, (byte)0xD4, (byte)0xC7, 
            (byte)0xB0, (byte)0x53, (byte)0x2E, (byte)0xCA, 
            (byte)0x51, (byte)0xCE, (byte)0x03, (byte)0xE2, 
            (byte)0xD1, (byte)0x0F, (byte)0x3B, (byte)0x7A, 
            (byte)0xC5, (byte)0x79, (byte)0xBD, (byte)0x87, 
            (byte)0xE9, (byte)0x09, (byte)0xAE, (byte)0x40, 
            (byte)0xA6, (byte)0xF1, (byte)0x31, (byte)0xE9, 
            (byte)0xCF, (byte)0xCE, (byte)0x5B, (byte)0xD9, 
            (byte)0x67
        })), new Integer(0xFF70), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор c2tnb431r1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_C2TNB431 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(431), 
            new ObjectIdentifier(OID.X962_C2_BASIS_TP), 
            new Integer(120)
        )
    );
    private static final Curve CURVE_C2TNB431R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x1A, (byte)0x82, (byte)0x7E, (byte)0xF0, 
            (byte)0x0D, (byte)0xD6, (byte)0xFC, (byte)0x0E, 
            (byte)0x23, (byte)0x4C, (byte)0xAF, (byte)0x04, 
            (byte)0x6C, (byte)0x6A, (byte)0x5D, (byte)0x8A, 
            (byte)0x85, (byte)0x39, (byte)0x5B, (byte)0x23, 
            (byte)0x6C, (byte)0xC4, (byte)0xAD, (byte)0x2C, 
            (byte)0xF3, (byte)0x2A, (byte)0x0C, (byte)0xAD, 
            (byte)0xBD, (byte)0xC9, (byte)0xDD, (byte)0xF6, 
            (byte)0x20, (byte)0xB0, (byte)0xEB, (byte)0x99, 
            (byte)0x06, (byte)0xD0, (byte)0x95, (byte)0x7F, 
            (byte)0x6C, (byte)0x6F, (byte)0xEA, (byte)0xCD, 
            (byte)0x61, (byte)0x54, (byte)0x68, (byte)0xDF, 
            (byte)0x10, (byte)0x4D, (byte)0xE2, (byte)0x96, 
            (byte)0xCD, (byte)0x8F
        }), new OctetString(new byte[] {
            (byte)0x10, (byte)0xD9, (byte)0xB4, (byte)0xA3, 
            (byte)0xD9, (byte)0x04, (byte)0x7D, (byte)0x8B, 
            (byte)0x15, (byte)0x43, (byte)0x59, (byte)0xAB, 
            (byte)0xFB, (byte)0x1B, (byte)0x7F, (byte)0x54, 
            (byte)0x85, (byte)0xB0, (byte)0x4C, (byte)0xEB, 
            (byte)0x86, (byte)0x82, (byte)0x37, (byte)0xDD, 
            (byte)0xC9, (byte)0xDE, (byte)0xDA, (byte)0x98, 
            (byte)0x2A, (byte)0x67, (byte)0x9A, (byte)0x5A, 
            (byte)0x91, (byte)0x9B, (byte)0x62, (byte)0x6D, 
            (byte)0x4E, (byte)0x50, (byte)0xA8, (byte)0xDD, 
            (byte)0x73, (byte)0x1B, (byte)0x10, (byte)0x7A, 
            (byte)0x99, (byte)0x62, (byte)0x38, (byte)0x1F, 
            (byte)0xB5, (byte)0xD8, (byte)0x07, (byte)0xBF, 
            (byte)0x26, (byte)0x18
        }), null
    ); 
    private static final SpecifiedECDomain EC_C2TNB431R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_C2TNB431, CURVE_C2TNB431R1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x12, (byte)0x0F, (byte)0xC0, 
            (byte)0x5D, (byte)0x3C, (byte)0x67, (byte)0xA9, 
            (byte)0x9D, (byte)0xE1, (byte)0x61, (byte)0xD2, 
            (byte)0xF4, (byte)0x09, (byte)0x26, (byte)0x22, 
            (byte)0xFE, (byte)0xCA, (byte)0x70, (byte)0x1B, 
            (byte)0xE4, (byte)0xF5, (byte)0x0F, (byte)0x47, 
            (byte)0x58, (byte)0x71, (byte)0x4E, (byte)0x8A, 
            (byte)0x87, (byte)0xBB, (byte)0xF2, (byte)0xA6, 
            (byte)0x58, (byte)0xEF, (byte)0x8C, (byte)0x21, 
            (byte)0xE7, (byte)0xC5, (byte)0xEF, (byte)0xE9, 
            (byte)0x65, (byte)0x36, (byte)0x1F, (byte)0x6C, 
            (byte)0x29, (byte)0x99, (byte)0xC0, (byte)0xC2, 
            (byte)0x47, (byte)0xB0, (byte)0xDB, (byte)0xD7, 
            (byte)0x0C, (byte)0xE6, (byte)0xB7
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x03, (byte)0x40, (byte)0x34, (byte)0x03, 
            (byte)0x40, (byte)0x34, (byte)0x03, (byte)0x40, 
            (byte)0x34, (byte)0x03, (byte)0x40, (byte)0x34, 
            (byte)0x03, (byte)0x40, (byte)0x34, (byte)0x03, 
            (byte)0x40, (byte)0x34, (byte)0x03, (byte)0x40, 
            (byte)0x34, (byte)0x03, (byte)0x40, (byte)0x34, 
            (byte)0x03, (byte)0x40, (byte)0x34, (byte)0x03, 
            (byte)0x23, (byte)0xC3, (byte)0x13, (byte)0xFA, 
            (byte)0xB5, (byte)0x05, (byte)0x89, (byte)0x70, 
            (byte)0x3B, (byte)0x5E, (byte)0xC6, (byte)0x8D, 
            (byte)0x35, (byte)0x87, (byte)0xFE, (byte)0xC6, 
            (byte)0x0D, (byte)0x16, (byte)0x1C, (byte)0xC1, 
            (byte)0x49, (byte)0xC1, (byte)0xAD, (byte)0x4A, 
            (byte)0x91
        })), new Integer(0x2760), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы prime192v1, prime192v2, prime192v3
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_PRIME192 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
        }))
    );
    private static final Curve CURVE_PRIME192V1 = new Curve(
        new OctetString(new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0x64, (byte)0x21, (byte)0x05, (byte)0x19, 
            (byte)0xE5, (byte)0x9C, (byte)0x80, (byte)0xE7, 
            (byte)0x0F, (byte)0xA7, (byte)0xE9, (byte)0xAB, 
            (byte)0x72, (byte)0x24, (byte)0x30, (byte)0x49, 
            (byte)0xFE, (byte)0xB8, (byte)0xDE, (byte)0xEC, 
            (byte)0xC1, (byte)0x46, (byte)0xB9, (byte)0xB1
        }), new BitString(new byte[] {
            (byte)0x30, (byte)0x45, (byte)0xAE, (byte)0x6F, 
            (byte)0xC8, (byte)0x42, (byte)0x2F, (byte)0x64, 
            (byte)0xED, (byte)0x57, (byte)0x95, (byte)0x28, 
            (byte)0xD3, (byte)0x81, (byte)0x20, (byte)0xEA, 
            (byte)0xE1, (byte)0x21, (byte)0x96, (byte)0xD5
        })
    ); 
    private static final SpecifiedECDomain EC_PRIME192V1 = new SpecifiedECDomain(
        new Integer(1), FIELD_PRIME192, CURVE_PRIME192V1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x18, (byte)0x8D, (byte)0xA8, 
            (byte)0x0E, (byte)0xB0, (byte)0x30, (byte)0x90, 
            (byte)0xF6, (byte)0x7C, (byte)0xBF, (byte)0x20, 
            (byte)0xEB, (byte)0x43, (byte)0xA1, (byte)0x88, 
            (byte)0x00, (byte)0xF4, (byte)0xFF, (byte)0x0A, 
            (byte)0xFD, (byte)0x82, (byte)0xFF, (byte)0x10, 
            (byte)0x12
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x99, (byte)0xDE, (byte)0xF8, (byte)0x36, 
            (byte)0x14, (byte)0x6B, (byte)0xC9, (byte)0xB1, 
            (byte)0xB4, (byte)0xD2, (byte)0x28, (byte)0x31
        })), new Integer(0x01), null
    ); 
    private static final Curve CURVE_PRIME192V2 = new Curve(
        new OctetString(new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0xCC, (byte)0x22, (byte)0xD6, (byte)0xDF, 
            (byte)0xB9, (byte)0x5C, (byte)0x6B, (byte)0x25, 
            (byte)0xE4, (byte)0x9C, (byte)0x0D, (byte)0x63, 
            (byte)0x64, (byte)0xA4, (byte)0xE5, (byte)0x98, 
            (byte)0x0C, (byte)0x39, (byte)0x3A, (byte)0xA2, 
            (byte)0x16, (byte)0x68, (byte)0xD9, (byte)0x53
        }), new BitString(new byte[] {
            (byte)0x31, (byte)0xA9, (byte)0x2E, (byte)0xE2, 
            (byte)0x02, (byte)0x9F, (byte)0xD1, (byte)0x0D, 
            (byte)0x90, (byte)0x1B, (byte)0x11, (byte)0x3E, 
            (byte)0x99, (byte)0x07, (byte)0x10, (byte)0xF0, 
            (byte)0xD2, (byte)0x1A, (byte)0xC6, (byte)0xB6
        })
    ); 
    private static final SpecifiedECDomain EC_PRIME192V2 = new SpecifiedECDomain(
        new Integer(1), FIELD_PRIME192, CURVE_PRIME192V2, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0xEE, (byte)0xA2, (byte)0xBA, 
            (byte)0xE7, (byte)0xE1, (byte)0x49, (byte)0x78, 
            (byte)0x42, (byte)0xF2, (byte)0xDE, (byte)0x77, 
            (byte)0x69, (byte)0xCF, (byte)0xE9, (byte)0xC9, 
            (byte)0x89, (byte)0xC0, (byte)0x72, (byte)0xAD, 
            (byte)0x69, (byte)0x6F, (byte)0x48, (byte)0x03, 
            (byte)0x4A
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0x5F, (byte)0xB1, (byte)0xA7, (byte)0x24, 
            (byte)0xDC, (byte)0x80, (byte)0x41, (byte)0x86, 
            (byte)0x48, (byte)0xD8, (byte)0xDD, (byte)0x31
        })), new Integer(0x01), null
    ); 
    private static final Curve CURVE_PRIME192V3 = new Curve(
        new OctetString(new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0x22, (byte)0x12, (byte)0x3D, (byte)0xC2, 
            (byte)0x39, (byte)0x5A, (byte)0x05, (byte)0xCA, 
            (byte)0xA7, (byte)0x42, (byte)0x3D, (byte)0xAE, 
            (byte)0xCC, (byte)0xC9, (byte)0x47, (byte)0x60, 
            (byte)0xA7, (byte)0xD4, (byte)0x62, (byte)0x25, 
            (byte)0x6B, (byte)0xD5, (byte)0x69, (byte)0x16
        }), new BitString(new byte[] {
            (byte)0xC4, (byte)0x69, (byte)0x68, (byte)0x44, 
            (byte)0x35, (byte)0xDE, (byte)0xB3, (byte)0x78, 
            (byte)0xC4, (byte)0xB6, (byte)0x5C, (byte)0xA9, 
            (byte)0x59, (byte)0x1E, (byte)0x2A, (byte)0x57, 
            (byte)0x63, (byte)0x05, (byte)0x9A, (byte)0x2E
        })
    ); 
    private static final SpecifiedECDomain EC_PRIME192V3 = new SpecifiedECDomain(
        new Integer(1), FIELD_PRIME192, CURVE_PRIME192V3, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x7D, (byte)0x29, (byte)0x77, 
            (byte)0x81, (byte)0x00, (byte)0xC6, (byte)0x5A, 
            (byte)0x1D, (byte)0xA1, (byte)0x78, (byte)0x37, 
            (byte)0x16, (byte)0x58, (byte)0x8D, (byte)0xCE, 
            (byte)0x2B, (byte)0x8B, (byte)0x4A, (byte)0xEE, 
            (byte)0x8E, (byte)0x22, (byte)0x8F, (byte)0x18, 
            (byte)0x96
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x7A, (byte)0x62, (byte)0xD0, (byte)0x31, 
            (byte)0xC8, (byte)0x3F, (byte)0x42, (byte)0x94, 
            (byte)0xF6, (byte)0x40, (byte)0xEC, (byte)0x13
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы prime239v1, prime239v2, prime239v3
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_PRIME239 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0x80, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF            
        }))
    );
    private static final Curve CURVE_PRIME239V1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0x80, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0x6B, (byte)0x01, (byte)0x6C, (byte)0x3B, 
            (byte)0xDC, (byte)0xF1, (byte)0x89, (byte)0x41, 
            (byte)0xD0, (byte)0xD6, (byte)0x54, (byte)0x92, 
            (byte)0x14, (byte)0x75, (byte)0xCA, (byte)0x71, 
            (byte)0xA9, (byte)0xDB, (byte)0x2F, (byte)0xB2, 
            (byte)0x7D, (byte)0x1D, (byte)0x37, (byte)0x79, 
            (byte)0x61, (byte)0x85, (byte)0xC2, (byte)0x94, 
            (byte)0x2C, (byte)0x0A
        }), new BitString(new byte[] {
            (byte)0xE4, (byte)0x3B, (byte)0xB4, (byte)0x60, 
            (byte)0xF0, (byte)0xB8, (byte)0x0C, (byte)0xC0, 
            (byte)0xC0, (byte)0xB0, (byte)0x75, (byte)0x79, 
            (byte)0x8E, (byte)0x94, (byte)0x80, (byte)0x60, 
            (byte)0xF8, (byte)0x32, (byte)0x1B, (byte)0x7D
        })
    ); 
    private static final SpecifiedECDomain EC_PRIME239V1 = new SpecifiedECDomain(
        new Integer(1), FIELD_PRIME239, CURVE_PRIME239V1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x0F, (byte)0xFA, (byte)0x96, 
            (byte)0x3C, (byte)0xDC, (byte)0xA8, (byte)0x81, 
            (byte)0x6C, (byte)0xCC, (byte)0x33, (byte)0xB8, 
            (byte)0x64, (byte)0x2B, (byte)0xED, (byte)0xF9, 
            (byte)0x05, (byte)0xC3, (byte)0xD3, (byte)0x58, 
            (byte)0x57, (byte)0x3D, (byte)0x3F, (byte)0x27, 
            (byte)0xFB, (byte)0xBD, (byte)0x3B, (byte)0x3C, 
            (byte)0xB9, (byte)0xAA, (byte)0xAF
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0x9E, 
            (byte)0x5E, (byte)0x9A, (byte)0x9F, (byte)0x5D, 
            (byte)0x90, (byte)0x71, (byte)0xFB, (byte)0xD1, 
            (byte)0x52, (byte)0x26, (byte)0x88, (byte)0x90, 
            (byte)0x9D, (byte)0x0B
        })), new Integer(0x01), null
    ); 
    private static final Curve CURVE_PRIME239V2 = new Curve(
        new OctetString(new byte[] {
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0x80, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0x61, (byte)0x7F, (byte)0xAB, (byte)0x68, 
            (byte)0x32, (byte)0x57, (byte)0x6C, (byte)0xBB, 
            (byte)0xFE, (byte)0xD5, (byte)0x0D, (byte)0x99, 
            (byte)0xF0, (byte)0x24, (byte)0x9C, (byte)0x3F, 
            (byte)0xEE, (byte)0x58, (byte)0xB9, (byte)0x4B, 
            (byte)0xA0, (byte)0x03, (byte)0x8C, (byte)0x7A, 
            (byte)0xE8, (byte)0x4C, (byte)0x8C, (byte)0x83, 
            (byte)0x2F, (byte)0x2C
        }), new BitString(new byte[] {
            (byte)0xE8, (byte)0xB4, (byte)0x01, (byte)0x16, 
            (byte)0x04, (byte)0x09, (byte)0x53, (byte)0x03, 
            (byte)0xCA, (byte)0x3B, (byte)0x80, (byte)0x99, 
            (byte)0x98, (byte)0x2B, (byte)0xE0, (byte)0x9F, 
            (byte)0xCB, (byte)0x9A, (byte)0xE6, (byte)0x16
        })
    ); 
    private static final SpecifiedECDomain EC_PRIME239V2 = new SpecifiedECDomain(
        new Integer(1), FIELD_PRIME239, CURVE_PRIME239V2, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x38, (byte)0xAF, (byte)0x09, 
            (byte)0xD9, (byte)0x87, (byte)0x27, (byte)0x70, 
            (byte)0x51, (byte)0x20, (byte)0xC9, (byte)0x21, 
            (byte)0xBB, (byte)0x5E, (byte)0x9E, (byte)0x26, 
            (byte)0x29, (byte)0x6A, (byte)0x3C, (byte)0xDC, 
            (byte)0xF2, (byte)0xF3, (byte)0x57, (byte)0x57, 
            (byte)0xA0, (byte)0xEA, (byte)0xFD, (byte)0x87, 
            (byte)0xB8, (byte)0x30, (byte)0xE7
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x80, (byte)0x00, (byte)0x00, (byte)0xCF, 
            (byte)0xA7, (byte)0xE8, (byte)0x59, (byte)0x43, 
            (byte)0x77, (byte)0xD4, (byte)0x14, (byte)0xC0, 
            (byte)0x38, (byte)0x21, (byte)0xBC, (byte)0x58, 
            (byte)0x20, (byte)0x63
        })), new Integer(0x01), null
    ); 
    private static final Curve CURVE_PRIME239V3 = new Curve(
        new OctetString(new byte[] {
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0x80, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0x25, (byte)0x57, (byte)0x05, (byte)0xFA, 
            (byte)0x2A, (byte)0x30, (byte)0x66, (byte)0x54, 
            (byte)0xB1, (byte)0xF4, (byte)0xCB, (byte)0x03, 
            (byte)0xD6, (byte)0xA7, (byte)0x50, (byte)0xA3, 
            (byte)0x0C, (byte)0x25, (byte)0x01, (byte)0x02, 
            (byte)0xD4, (byte)0x98, (byte)0x87, (byte)0x17, 
            (byte)0xD9, (byte)0xBA, (byte)0x15, (byte)0xAB, 
            (byte)0x6D, (byte)0x3E
        }), new BitString(new byte[] {
            (byte)0x7D, (byte)0x73, (byte)0x74, (byte)0x16, 
            (byte)0x8F, (byte)0xFE, (byte)0x34, (byte)0x71, 
            (byte)0xB6, (byte)0x0A, (byte)0x85, (byte)0x76, 
            (byte)0x86, (byte)0xA1, (byte)0x94, (byte)0x75, 
            (byte)0xD3, (byte)0xBF, (byte)0xA2, (byte)0xFF
        })
    ); 
    private static final SpecifiedECDomain EC_PRIME239V3 = new SpecifiedECDomain(
        new Integer(1), FIELD_PRIME239, CURVE_PRIME239V3, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x67, (byte)0x68, (byte)0xAE, 
            (byte)0x8E, (byte)0x18, (byte)0xBB, (byte)0x92, 
            (byte)0xCF, (byte)0xCF, (byte)0x00, (byte)0x5C, 
            (byte)0x94, (byte)0x9A, (byte)0xA2, (byte)0xC6, 
            (byte)0xD9, (byte)0x48, (byte)0x53, (byte)0xD0, 
            (byte)0xE6, (byte)0x60, (byte)0xBB, (byte)0xF8, 
            (byte)0x54, (byte)0xB1, (byte)0xC9, (byte)0x50, 
            (byte)0x5F, (byte)0xE9, (byte)0x5A
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0x97, 
            (byte)0x5D, (byte)0xEB, (byte)0x41, (byte)0xB3, 
            (byte)0xA6, (byte)0x05, (byte)0x7C, (byte)0x3C, 
            (byte)0x43, (byte)0x21, (byte)0x46, (byte)0x52, 
            (byte)0x65, (byte)0x51
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор prime256v1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_PRIME256 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
        }))
    );
    private static final Curve CURVE_PRIME256V1 = new Curve(
        new OctetString(new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0x5A, (byte)0xC6, (byte)0x35, (byte)0xD8, 
            (byte)0xAA, (byte)0x3A, (byte)0x93, (byte)0xE7, 
            (byte)0xB3, (byte)0xEB, (byte)0xBD, (byte)0x55, 
            (byte)0x76, (byte)0x98, (byte)0x86, (byte)0xBC, 
            (byte)0x65, (byte)0x1D, (byte)0x06, (byte)0xB0, 
            (byte)0xCC, (byte)0x53, (byte)0xB0, (byte)0xF6, 
            (byte)0x3B, (byte)0xCE, (byte)0x3C, (byte)0x3E, 
            (byte)0x27, (byte)0xD2, (byte)0x60, (byte)0x4B
        }), new BitString(new byte[] {
            (byte)0xC4, (byte)0x9D, (byte)0x36, (byte)0x08, 
            (byte)0x86, (byte)0xE7, (byte)0x04, (byte)0x93, 
            (byte)0x6A, (byte)0x66, (byte)0x78, (byte)0xE1, 
            (byte)0x13, (byte)0x9D, (byte)0x26, (byte)0xB7, 
            (byte)0x81, (byte)0x9F, (byte)0x7E, (byte)0x90
        })
    ); 
    private static final SpecifiedECDomain EC_PRIME256V1 = new SpecifiedECDomain(
        new Integer(1), FIELD_PRIME256, CURVE_PRIME256V1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x6B, (byte)0x17, (byte)0xD1, 
            (byte)0xF2, (byte)0xE1, (byte)0x2C, (byte)0x42, 
            (byte)0x47, (byte)0xF8, (byte)0xBC, (byte)0xE6, 
            (byte)0xE5, (byte)0x63, (byte)0xA4, (byte)0x40, 
            (byte)0xF2, (byte)0x77, (byte)0x03, (byte)0x7D, 
            (byte)0x81, (byte)0x2D, (byte)0xEB, (byte)0x33, 
            (byte)0xA0, (byte)0xF4, (byte)0xA1, (byte)0x39, 
            (byte)0x45, (byte)0xD8, (byte)0x98, (byte)0xC2, 
            (byte)0x96
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xBC, (byte)0xE6, (byte)0xFA, (byte)0xAD, 
            (byte)0xA7, (byte)0x17, (byte)0x9E, (byte)0x84, 
            (byte)0xF3, (byte)0xB9, (byte)0xCA, (byte)0xC2, 
            (byte)0xFC, (byte)0x63, (byte)0x25, (byte)0x51
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы secp112r1, secp112r2
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECP112 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xDB, (byte)0x7C, (byte)0x2A, (byte)0xBF, 
            (byte)0x62, (byte)0xE3, (byte)0x5E, (byte)0x66, 
            (byte)0x80, (byte)0x76, (byte)0xBE, (byte)0xAD, 
            (byte)0x20, (byte)0x8B
        }))
    );
    private static final Curve CURVE_SECP112R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0xDB, (byte)0x7C, (byte)0x2A, (byte)0xBF, 
            (byte)0x62, (byte)0xE3, (byte)0x5E, (byte)0x66, 
            (byte)0x80, (byte)0x76, (byte)0xBE, (byte)0xAD, 
            (byte)0x20, (byte)0x88
        }), new OctetString(new byte[] {
            (byte)0x65, (byte)0x9E, (byte)0xF8, (byte)0xBA, 
            (byte)0x04, (byte)0x39, (byte)0x16, (byte)0xEE, 
            (byte)0xDE, (byte)0x89, (byte)0x11, (byte)0x70, 
            (byte)0x2B, (byte)0x22
        }), new BitString(new byte[] {
            (byte)0x00, (byte)0xF5, (byte)0x0B, (byte)0x02, 
            (byte)0x8E, (byte)0x4D, (byte)0x69, (byte)0x6E, 
            (byte)0x67, (byte)0x68, (byte)0x75, (byte)0x61, 
            (byte)0x51, (byte)0x75, (byte)0x29, (byte)0x04, 
            (byte)0x72, (byte)0x78, (byte)0x3F, (byte)0xB1
        })
    ); 
    private static final SpecifiedECDomain EC_SECP112R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP112, CURVE_SECP112R1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x09, (byte)0x48, (byte)0x72, 
            (byte)0x39, (byte)0x99, (byte)0x5A, (byte)0x5E, 
            (byte)0xE7, (byte)0x6B, (byte)0x55, (byte)0xF9, 
            (byte)0xC2, (byte)0xF0, (byte)0x98        
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0xDB, (byte)0x7C, (byte)0x2A, (byte)0xBF, 
            (byte)0x62, (byte)0xE3, (byte)0x5E, (byte)0x76, 
            (byte)0x28, (byte)0xDF, (byte)0xAC, (byte)0x65, 
            (byte)0x61, (byte)0xC5
        })), new Integer(0x01), null
    ); 
    private static final Curve CURVE_SECP112R2 = new Curve(
        new OctetString(new byte[] {
            (byte)0x61, (byte)0x27, (byte)0xC2, (byte)0x4C, 
            (byte)0x05, (byte)0xF3, (byte)0x8A, (byte)0x0A, 
            (byte)0xAA, (byte)0xF6, (byte)0x5C, (byte)0x0E, 
            (byte)0xF0, (byte)0x2C
        }), new OctetString(new byte[] {
            (byte)0x51, (byte)0xDE, (byte)0xF1, (byte)0x81, 
            (byte)0x5D, (byte)0xB5, (byte)0xED, (byte)0x74, 
            (byte)0xFC, (byte)0xC3, (byte)0x4C, (byte)0x85, 
            (byte)0xD7, (byte)0x09
        }), new BitString(new byte[] {
            (byte)0x00, (byte)0x27, (byte)0x57, (byte)0xA1, 
            (byte)0x11, (byte)0x4D, (byte)0x69, (byte)0x6E, 
            (byte)0x67, (byte)0x68, (byte)0x75, (byte)0x61, 
            (byte)0x51, (byte)0x75, (byte)0x53, (byte)0x16, 
            (byte)0xC0, (byte)0x5E, (byte)0x0B, (byte)0xD4
        })
    ); 
    private static final SpecifiedECDomain EC_SECP112R2 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP112, CURVE_SECP112R2, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x4B, (byte)0xA3, (byte)0x0A, 
            (byte)0xB5, (byte)0xE8, (byte)0x92, (byte)0xB4, 
            (byte)0xE1, (byte)0x64, (byte)0x9D, (byte)0xD0, 
            (byte)0x92, (byte)0x86, (byte)0x43
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x36, (byte)0xDF, (byte)0x0A, (byte)0xAF, 
            (byte)0xD8, (byte)0xB8, (byte)0xD7, (byte)0x59, 
            (byte)0x7C, (byte)0xA1, (byte)0x05, (byte)0x20, 
            (byte)0xD0, (byte)0x4B
        })), new Integer(0x04), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы secp128r1, secp128r2
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECP128 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFD, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
        }))
    );
    private static final Curve CURVE_SECP128R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFD, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0xE8, (byte)0x75, (byte)0x79, (byte)0xC1, 
            (byte)0x10, (byte)0x79, (byte)0xF4, (byte)0x3D, 
            (byte)0xD8, (byte)0x24, (byte)0x99, (byte)0x3C, 
            (byte)0x2C, (byte)0xEE, (byte)0x5E, (byte)0xD3
        }), new BitString(new byte[] {
            (byte)0x00, (byte)0x0E, (byte)0x0D, (byte)0x4D, 
            (byte)0x69, (byte)0x6E, (byte)0x67, (byte)0x68, 
            (byte)0x75, (byte)0x61, (byte)0x51, (byte)0x75, 
            (byte)0x0C, (byte)0xC0, (byte)0x3A, (byte)0x44, 
            (byte)0x73, (byte)0xD0, (byte)0x36, (byte)0x79
        })
    ); 
    private static final SpecifiedECDomain EC_SECP128R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP128, CURVE_SECP128R1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x16, (byte)0x1F, (byte)0xF7, 
            (byte)0x52, (byte)0x8B, (byte)0x89, (byte)0x9B, 
            (byte)0x2D, (byte)0x0C, (byte)0x28, (byte)0x60, 
            (byte)0x7C, (byte)0xA5, (byte)0x2C, (byte)0x5B, 
            (byte)0x86
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x75, (byte)0xA3, (byte)0x0D, (byte)0x1B, 
            (byte)0x90, (byte)0x38, (byte)0xA1, (byte)0x15
        })), new Integer(0x01), null
    ); 
    private static final Curve CURVE_SECP128R2 = new Curve(
        new OctetString(new byte[] {
            (byte)0xD6, (byte)0x03, (byte)0x19, (byte)0x98, 
            (byte)0xD1, (byte)0xB3, (byte)0xBB, (byte)0xFE, 
            (byte)0xBF, (byte)0x59, (byte)0xCC, (byte)0x9B, 
            (byte)0xBF, (byte)0xF9, (byte)0xAE, (byte)0xE1
        }), new OctetString(new byte[] {
            (byte)0x5E, (byte)0xEE, (byte)0xFC, (byte)0xA3, 
            (byte)0x80, (byte)0xD0, (byte)0x29, (byte)0x19, 
            (byte)0xDC, (byte)0x2C, (byte)0x65, (byte)0x58, 
            (byte)0xBB, (byte)0x6D, (byte)0x8A, (byte)0x5D
        }), new BitString(new byte[] {
            (byte)0x00, (byte)0x4D, (byte)0x69, (byte)0x6E, 
            (byte)0x67, (byte)0x68, (byte)0x75, (byte)0x61, 
            (byte)0x51, (byte)0x75, (byte)0x12, (byte)0xD8, 
            (byte)0xF0, (byte)0x34, (byte)0x31, (byte)0xFC, 
            (byte)0xE6, (byte)0x3B, (byte)0x88, (byte)0xF4
        })
    ); 
    private static final SpecifiedECDomain EC_SECP128R2 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP128, CURVE_SECP128R2, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x7B, (byte)0x6A, (byte)0xA5, 
            (byte)0xD8, (byte)0x5E, (byte)0x57, (byte)0x29, 
            (byte)0x83, (byte)0xE6, (byte)0xFB, (byte)0x32, 
            (byte)0xA7, (byte)0xCD, (byte)0xEB, (byte)0xC1, 
            (byte)0x40
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x3F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xBE, (byte)0x00, (byte)0x24, (byte)0x72, 
            (byte)0x06, (byte)0x13, (byte)0xB5, (byte)0xA3
        })), new Integer(0x04), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор secp160k1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECP160K1 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xAC, (byte)0x73
        }))
    );
    private static final Curve CURVE_SECP160K1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x07
        }), null
    ); 
    private static final SpecifiedECDomain EC_SECP160K1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP160K1, CURVE_SECP160K1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x3B, (byte)0x4C, (byte)0x38, 
            (byte)0x2C, (byte)0xE3, (byte)0x7A, (byte)0xA1, 
            (byte)0x92, (byte)0xA4, (byte)0x01, (byte)0x9E, 
            (byte)0x76, (byte)0x30, (byte)0x36, (byte)0xF4, 
            (byte)0xF5, (byte)0xDD, (byte)0x4D, (byte)0x7E, 
            (byte)0xBB
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x01, (byte)0xB8, 
            (byte)0xFA, (byte)0x16, (byte)0xDF, (byte)0xAB, 
            (byte)0x9A, (byte)0xCA, (byte)0x16, (byte)0xB6, 
            (byte)0xB3
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы secp160r1, secp160r2
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECP160R1 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF
        }))
    );
    private static final Curve CURVE_SECP160R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0x1C, (byte)0x97, (byte)0xBE, (byte)0xFC, 
            (byte)0x54, (byte)0xBD, (byte)0x7A, (byte)0x8B, 
            (byte)0x65, (byte)0xAC, (byte)0xF8, (byte)0x9F, 
            (byte)0x81, (byte)0xD4, (byte)0xD4, (byte)0xAD, 
            (byte)0xC5, (byte)0x65, (byte)0xFA, (byte)0x45
        }), new BitString(new byte[] {
            (byte)0x10, (byte)0x53, (byte)0xCD, (byte)0xE4, 
            (byte)0x2C, (byte)0x14, (byte)0xD6, (byte)0x96, 
            (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
            (byte)0x15, (byte)0x17, (byte)0x53, (byte)0x3B, 
            (byte)0xF3, (byte)0xF8, (byte)0x33, (byte)0x45
        })
    ); 
    private static final SpecifiedECDomain EC_SECP160R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP160R1, CURVE_SECP160R1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x4A, (byte)0x96, (byte)0xB5, 
            (byte)0x68, (byte)0x8E, (byte)0xF5, (byte)0x73, 
            (byte)0x28, (byte)0x46, (byte)0x64, (byte)0x69, 
            (byte)0x89, (byte)0x68, (byte)0xC3, (byte)0x8B, 
            (byte)0xB9, (byte)0x13, (byte)0xCB, (byte)0xFC, 
            (byte)0x82
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x01, (byte)0xF4, 
            (byte)0xC8, (byte)0xF9, (byte)0x27, (byte)0xAE, 
            (byte)0xD3, (byte)0xCA, (byte)0x75, (byte)0x22, 
            (byte)0x57
        })), new Integer(0x01), null
    ); 
    private static final FieldID FIELD_SECP160R2 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xAC, (byte)0x73
        }))
    );
    private static final Curve CURVE_SECP160R2 = new Curve(
        new OctetString(new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xAC, (byte)0x70
        }), new OctetString(new byte[] {
            (byte)0xB4, (byte)0xE1, (byte)0x34, (byte)0xD3, 
            (byte)0xFB, (byte)0x59, (byte)0xEB, (byte)0x8B, 
            (byte)0xAB, (byte)0x57, (byte)0x27, (byte)0x49, 
            (byte)0x04, (byte)0x66, (byte)0x4D, (byte)0x5A, 
            (byte)0xF5, (byte)0x03, (byte)0x88, (byte)0xBA
        }), new BitString(new byte[] {
            (byte)0xB9, (byte)0x9B, (byte)0x99, (byte)0xB0, 
            (byte)0x99, (byte)0xB3, (byte)0x23, (byte)0xE0, 
            (byte)0x27, (byte)0x09, (byte)0xA4, (byte)0xD6, 
            (byte)0x96, (byte)0xE6, (byte)0x76, (byte)0x87, 
            (byte)0x56, (byte)0x15, (byte)0x17, (byte)0x51
        })
    ); 
    private static final SpecifiedECDomain EC_SECP160R2 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP160R2, CURVE_SECP160R2, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x52, (byte)0xDC, (byte)0xB0, 
            (byte)0x34, (byte)0x29, (byte)0x3A, (byte)0x11, 
            (byte)0x7E, (byte)0x1F, (byte)0x4F, (byte)0xF1, 
            (byte)0x1B, (byte)0x30, (byte)0xF7, (byte)0x19, 
            (byte)0x9D, (byte)0x31, (byte)0x44, (byte)0xCE, 
            (byte)0x6D
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x35, 
            (byte)0x1E, (byte)0xE7, (byte)0x86, (byte)0xA8, 
            (byte)0x18, (byte)0xF3, (byte)0xA1, (byte)0xA1, 
            (byte)0x6B
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор secp192k1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECP192K1 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xEE, (byte)0x37
        }))
    );
    private static final Curve CURVE_SECP192K1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03
        }), null
    ); 
    private static final SpecifiedECDomain EC_SECP192K1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP192K1, CURVE_SECP192K1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0xDB, (byte)0x4F, (byte)0xF1, 
            (byte)0x0E, (byte)0xC0, (byte)0x57, (byte)0xE9, 
            (byte)0xAE, (byte)0x26, (byte)0xB0, (byte)0x7D, 
            (byte)0x02, (byte)0x80, (byte)0xB7, (byte)0xF4, 
            (byte)0x34, (byte)0x1D, (byte)0xA5, (byte)0xD1, 
            (byte)0xB1, (byte)0xEA, (byte)0xE0, (byte)0x6C, 
            (byte)0x7D
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0x26, (byte)0xF2, (byte)0xFC, (byte)0x17, 
            (byte)0x0F, (byte)0x69, (byte)0x46, (byte)0x6A, 
            (byte)0x74, (byte)0xDE, (byte)0xFD, (byte)0x8D
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор secp224k1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECP224K1 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xE5, (byte)0x6D
        }))
    );
    private static final Curve CURVE_SECP224K1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x05
        }), null
    ); 
    private static final SpecifiedECDomain EC_SECP224K1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP224K1, CURVE_SECP224K1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0xA1, (byte)0x45, (byte)0x5B, 
            (byte)0x33, (byte)0x4D, (byte)0xF0, (byte)0x99, 
            (byte)0xDF, (byte)0x30, (byte)0xFC, (byte)0x28, 
            (byte)0xA1, (byte)0x69, (byte)0xA4, (byte)0x67, 
            (byte)0xE9, (byte)0xE4, (byte)0x70, (byte)0x75, 
            (byte)0xA9, (byte)0x0F, (byte)0x7E, (byte)0x65, 
            (byte)0x0E, (byte)0xB6, (byte)0xB7, (byte)0xA4, 
            (byte)0x5C
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x01, (byte)0xDC, 
            (byte)0xE8, (byte)0xD2, (byte)0xEC, (byte)0x61, 
            (byte)0x84, (byte)0xCA, (byte)0xF0, (byte)0xA9, 
            (byte)0x71, (byte)0x76, (byte)0x9F, (byte)0xB1, 
            (byte)0xF7
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор secp224r1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECP224R1 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
        }))
    );
    private static final Curve CURVE_SECP224R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE
        }), new OctetString(new byte[] {
            (byte)0xB4, (byte)0x05, (byte)0x0A, (byte)0x85, 
            (byte)0x0C, (byte)0x04, (byte)0xB3, (byte)0xAB, 
            (byte)0xF5, (byte)0x41, (byte)0x32, (byte)0x56, 
            (byte)0x50, (byte)0x44, (byte)0xB0, (byte)0xB7, 
            (byte)0xD7, (byte)0xBF, (byte)0xD8, (byte)0xBA, 
            (byte)0x27, (byte)0x0B, (byte)0x39, (byte)0x43, 
            (byte)0x23, (byte)0x55, (byte)0xFF, (byte)0xB4
        }), new BitString(new byte[] {
            (byte)0xBD, (byte)0x71, (byte)0x34, (byte)0x47, 
            (byte)0x99, (byte)0xD5, (byte)0xC7, (byte)0xFC, 
            (byte)0xDC, (byte)0x45, (byte)0xB5, (byte)0x9F, 
            (byte)0xA3, (byte)0xB9, (byte)0xAB, (byte)0x8F, 
            (byte)0x6A, (byte)0x94, (byte)0x8B, (byte)0xC5
        })
    ); 
    private static final SpecifiedECDomain EC_SECP224R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP224R1, CURVE_SECP224R1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0xB7, (byte)0x0E, (byte)0x0C, 
            (byte)0xBD, (byte)0x6B, (byte)0xB4, (byte)0xBF, 
            (byte)0x7F, (byte)0x32, (byte)0x13, (byte)0x90, 
            (byte)0xB9, (byte)0x4A, (byte)0x03, (byte)0xC1, 
            (byte)0xD3, (byte)0x56, (byte)0xC2, (byte)0x11, 
            (byte)0x22, (byte)0x34, (byte)0x32, (byte)0x80, 
            (byte)0xD6, (byte)0x11, (byte)0x5C, (byte)0x1D, 
            (byte)0x21
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0x16, (byte)0xA2, 
            (byte)0xE0, (byte)0xB8, (byte)0xF0, (byte)0x3E, 
            (byte)0x13, (byte)0xDD, (byte)0x29, (byte)0x45, 
            (byte)0x5C, (byte)0x5C, (byte)0x2A, (byte)0x3D
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор secp256k1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECP256K1 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xFC, (byte)0x2F
        }))
    );
    private static final Curve CURVE_SECP256K1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x07
        }), null
    ); 
    private static final SpecifiedECDomain EC_SECP256K1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP256K1, CURVE_SECP256K1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x79, (byte)0xBE, (byte)0x66, 
            (byte)0x7E, (byte)0xF9, (byte)0xDC, (byte)0xBB, 
            (byte)0xAC, (byte)0x55, (byte)0xA0, (byte)0x62, 
            (byte)0x95, (byte)0xCE, (byte)0x87, (byte)0x0B, 
            (byte)0x07, (byte)0x02, (byte)0x9B, (byte)0xFC, 
            (byte)0xDB, (byte)0x2D, (byte)0xCE, (byte)0x28, 
            (byte)0xD9, (byte)0x59, (byte)0xF2, (byte)0x81, 
            (byte)0x5B, (byte)0x16, (byte)0xF8, (byte)0x17, 
            (byte)0x98
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xBA, (byte)0xAE, (byte)0xDC, (byte)0xE6, 
            (byte)0xAF, (byte)0x48, (byte)0xA0, (byte)0x3B, 
            (byte)0xBF, (byte)0xD2, (byte)0x5E, (byte)0x8C,
            (byte)0xD0, (byte)0x36, (byte)0x41, (byte)0x41
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор secp384r1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECP384R1 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
        }))
    );
    private static final Curve CURVE_SECP384R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0xB3, (byte)0x31, (byte)0x2F, (byte)0xA7, 
            (byte)0xE2, (byte)0x3E, (byte)0xE7, (byte)0xE4, 
            (byte)0x98, (byte)0x8E, (byte)0x05, (byte)0x6B, 
            (byte)0xE3, (byte)0xF8, (byte)0x2D, (byte)0x19, 
            (byte)0x18, (byte)0x1D, (byte)0x9C, (byte)0x6E, 
            (byte)0xFE, (byte)0x81, (byte)0x41, (byte)0x12, 
            (byte)0x03, (byte)0x14, (byte)0x08, (byte)0x8F,
            (byte)0x50, (byte)0x13, (byte)0x87, (byte)0x5A, 
            (byte)0xC6, (byte)0x56, (byte)0x39, (byte)0x8D, 
            (byte)0x8A, (byte)0x2E, (byte)0xD1, (byte)0x9D, 
            (byte)0x2A, (byte)0x85, (byte)0xC8, (byte)0xED, 
            (byte)0xD3, (byte)0xEC, (byte)0x2A, (byte)0xEF
        }), new BitString(new byte[] {
            (byte)0xA3, (byte)0x35, (byte)0x92, (byte)0x6A, 
            (byte)0xA3, (byte)0x19, (byte)0xA2, (byte)0x7A, 
            (byte)0x1D, (byte)0x00, (byte)0x89, (byte)0x6A, 
            (byte)0x67, (byte)0x73, (byte)0xA4, (byte)0x82, 
            (byte)0x7A, (byte)0xCD, (byte)0xAC, (byte)0x73
        })
    ); 
    private static final SpecifiedECDomain EC_SECP384R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP384R1, CURVE_SECP384R1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0xAA, (byte)0x87, (byte)0xCA, 
            (byte)0x22, (byte)0xBE, (byte)0x8B, (byte)0x05, 
            (byte)0x37, (byte)0x8E, (byte)0xB1, (byte)0xC7, 
            (byte)0x1E, (byte)0xF3, (byte)0x20, (byte)0xAD, 
            (byte)0x74, (byte)0x6E, (byte)0x1D, (byte)0x3B, 
            (byte)0x62, (byte)0x8B, (byte)0xA7, (byte)0x9B, 
            (byte)0x98, (byte)0x59, (byte)0xF7, (byte)0x41, 
            (byte)0xE0, (byte)0x82, (byte)0x54, (byte)0x2A, 
            (byte)0x38, (byte)0x55, (byte)0x02, (byte)0xF2, 
            (byte)0x5D, (byte)0xBF, (byte)0x55, (byte)0x29, 
            (byte)0x6C, (byte)0x3A, (byte)0x54, (byte)0x5E, 
            (byte)0x38, (byte)0x72, (byte)0x76, (byte)0x0A,
            (byte)0xB7
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xC7, (byte)0x63, (byte)0x4D, (byte)0x81,
            (byte)0xF4, (byte)0x37, (byte)0x2D, (byte)0xDF, 
            (byte)0x58, (byte)0x1A, (byte)0x0D, (byte)0xB2, 
            (byte)0x48, (byte)0xB0, (byte)0xA7, (byte)0x7A, 
            (byte)0xEC, (byte)0xEC, (byte)0x19, (byte)0x6A, 
            (byte)0xCC, (byte)0xC5, (byte)0x29, (byte)0x73
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Набор secp521r1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECP521R1 = new FieldID(
        new ObjectIdentifier(OID.X962_PRIME_FIELD), 
        new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF
        }))
    );
    private static final Curve CURVE_SECP521R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFC
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x51, (byte)0x95, (byte)0x3E, 
            (byte)0xB9, (byte)0x61, (byte)0x8E, (byte)0x1C, 
            (byte)0x9A, (byte)0x1F, (byte)0x92, (byte)0x9A, 
            (byte)0x21, (byte)0xA0, (byte)0xB6, (byte)0x85, 
            (byte)0x40, (byte)0xEE, (byte)0xA2, (byte)0xDA, 
            (byte)0x72, (byte)0x5B, (byte)0x99, (byte)0xB3, 
            (byte)0x15, (byte)0xF3, (byte)0xB8, (byte)0xB4, 
            (byte)0x89, (byte)0x91, (byte)0x8E, (byte)0xF1, 
            (byte)0x09, (byte)0xE1, (byte)0x56, (byte)0x19, 
            (byte)0x39, (byte)0x51, (byte)0xEC, (byte)0x7E, 
            (byte)0x93, (byte)0x7B, (byte)0x16, (byte)0x52, 
            (byte)0xC0, (byte)0xBD, (byte)0x3B, (byte)0xB1, 
            (byte)0xBF, (byte)0x07, (byte)0x35, (byte)0x73, 
            (byte)0xDF, (byte)0x88, (byte)0x3D, (byte)0x2C, 
            (byte)0x34, (byte)0xF1, (byte)0xEF, (byte)0x45, 
            (byte)0x1F, (byte)0xD4, (byte)0x6B, (byte)0x50, 
            (byte)0x3F, (byte)0x00
        }), new BitString(new byte[] {
            (byte)0xD0, (byte)0x9E, (byte)0x88, (byte)0x00, 
            (byte)0x29, (byte)0x1C, (byte)0xB8, (byte)0x53, 
            (byte)0x96, (byte)0xCC, (byte)0x67, (byte)0x17, 
            (byte)0x39, (byte)0x32, (byte)0x84, (byte)0xAA, 
            (byte)0xA0, (byte)0xDA, (byte)0x64, (byte)0xBA
        })
    ); 
    private static final SpecifiedECDomain EC_SECP521R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECP521R1, CURVE_SECP521R1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x00, (byte)0xC6, (byte)0x85, 
            (byte)0x8E, (byte)0x06, (byte)0xB7, (byte)0x04, 
            (byte)0x04, (byte)0xE9, (byte)0xCD, (byte)0x9E, 
            (byte)0x3E, (byte)0xCB, (byte)0x66, (byte)0x23, 
            (byte)0x95, (byte)0xB4, (byte)0x42, (byte)0x9C, 
            (byte)0x64, (byte)0x81, (byte)0x39, (byte)0x05, 
            (byte)0x3F, (byte)0xB5, (byte)0x21, (byte)0xF8, 
            (byte)0x28, (byte)0xAF, (byte)0x60, (byte)0x6B, 
            (byte)0x4D, (byte)0x3D, (byte)0xBA, (byte)0xA1, 
            (byte)0x4B, (byte)0x5E, (byte)0x77, (byte)0xEF, 
            (byte)0xE7, (byte)0x59, (byte)0x28, (byte)0xFE, 
            (byte)0x1D, (byte)0xC1, (byte)0x27, (byte)0xA2, 
            (byte)0xFF, (byte)0xA8, (byte)0xDE, (byte)0x33, 
            (byte)0x48, (byte)0xB3, (byte)0xC1, (byte)0x85, 
            (byte)0x6A, (byte)0x42, (byte)0x9B, (byte)0xF9, 
            (byte)0x7E, (byte)0x7E, (byte)0x31, (byte)0xC2, 
            (byte)0xE5, (byte)0xBD, (byte)0x66
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFA, (byte)0x51, (byte)0x86, 
            (byte)0x87, (byte)0x83, (byte)0xBF, (byte)0x2F, 
            (byte)0x96, (byte)0x6B, (byte)0x7F, (byte)0xCC, 
            (byte)0x01, (byte)0x48, (byte)0xF7, (byte)0x09, 
            (byte)0xA5, (byte)0xD0, (byte)0x3B, (byte)0xB5, 
            (byte)0xC9, (byte)0xB8, (byte)0x89, (byte)0x9C, 
            (byte)0x47, (byte)0xAE, (byte)0xBB, (byte)0x6F, 
            (byte)0xB7, (byte)0x1E, (byte)0x91, (byte)0x38, 
            (byte)0x64, (byte)0x09
        })), new Integer(0x01), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы sect113r1, sect113r2
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECT113 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(113), 
            new ObjectIdentifier(OID.X962_C2_BASIS_TP), 
            new Integer(9)
        )
    );
    private static final Curve CURVE_SECT113R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x30, (byte)0x88, (byte)0x25, 
            (byte)0x0C, (byte)0xA6, (byte)0xE7, (byte)0xC7, 
            (byte)0xFE, (byte)0x64, (byte)0x9C, (byte)0xE8, 
            (byte)0x58, (byte)0x20, (byte)0xF7
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0xE8, (byte)0xBE, (byte)0xE4, 
            (byte)0xD3, (byte)0xE2, (byte)0x26, (byte)0x07, 
            (byte)0x44, (byte)0x18, (byte)0x8B, (byte)0xE0, 
            (byte)0xE9, (byte)0xC7, (byte)0x23
        }), new BitString(new byte[] {
            (byte)0x10, (byte)0xE7, (byte)0x23, (byte)0xAB, 
            (byte)0x14, (byte)0xD6, (byte)0x96, (byte)0xE6, 
            (byte)0x76, (byte)0x87, (byte)0x56, (byte)0x15, 
            (byte)0x17, (byte)0x56, (byte)0xFE, (byte)0xBF, 
            (byte)0x8F, (byte)0xCB, (byte)0x49, (byte)0xA9
        })
    ); 
    private static final SpecifiedECDomain EC_SECT113R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT113, CURVE_SECT113R1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x00, (byte)0x9D, (byte)0x73, 
            (byte)0x61, (byte)0x6F, (byte)0x35, (byte)0xF4, 
            (byte)0xAB, (byte)0x14, (byte)0x07, (byte)0xD7, 
            (byte)0x35, (byte)0x62, (byte)0xC1, (byte)0x0F
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0xD9, (byte)0xCC, (byte)0xEC, (byte)0x8A, 
            (byte)0x39, (byte)0xE5, (byte)0x6F
        })), new Integer(0x02), null
    ); 
    private static final Curve CURVE_SECT113R2 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x68, (byte)0x99, (byte)0x18, 
            (byte)0xDB, (byte)0xEC, (byte)0x7E, (byte)0x5A, 
            (byte)0x0D, (byte)0xD6, (byte)0xDF, (byte)0xC0, 
            (byte)0xAA, (byte)0x55, (byte)0xC7
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x95, (byte)0xE9, (byte)0xA9, 
            (byte)0xEC, (byte)0x9B, (byte)0x29, (byte)0x7B, 
            (byte)0xD4, (byte)0xBF, (byte)0x36, (byte)0xE0, 
            (byte)0x59, (byte)0x18, (byte)0x4F
        }), new BitString(new byte[] {
            (byte)0x10, (byte)0xC0, (byte)0xFB, (byte)0x15, 
            (byte)0x76, (byte)0x08, (byte)0x60, (byte)0xDE, 
            (byte)0xF1, (byte)0xEE, (byte)0xF4, (byte)0xD6, 
            (byte)0x96, (byte)0xE6, (byte)0x76, (byte)0x87, 
            (byte)0x56, (byte)0x15, (byte)0x17, (byte)0x5D
        })
    ); 
    private static final SpecifiedECDomain EC_SECT113R2 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT113, CURVE_SECT113R2, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x01, (byte)0xA5, (byte)0x7A, 
            (byte)0x6A, (byte)0x7B, (byte)0x26, (byte)0xCA, 
            (byte)0x5E, (byte)0xF5, (byte)0x2F, (byte)0xCD, 
            (byte)0xB8, (byte)0x16, (byte)0x47, (byte)0x97
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, 
            (byte)0x08, (byte)0x78, (byte)0x9B, (byte)0x24, 
            (byte)0x96, (byte)0xAF, (byte)0x93
        })), new Integer(0x02), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы sect131r1, sect131r2
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECT131 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(131), 
            new ObjectIdentifier(OID.X962_C2_BASIS_PP), 
            new Pentanomial(new Integer(2), new Integer(3), new Integer(8))
        )
    );
    private static final Curve CURVE_SECT131R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x07, (byte)0xA1, (byte)0x1B, (byte)0x09, 
            (byte)0xA7, (byte)0x6B, (byte)0x56, (byte)0x21, 
            (byte)0x44, (byte)0x41, (byte)0x8F, (byte)0xF3, 
            (byte)0xFF, (byte)0x8C, (byte)0x25, (byte)0x70, 
            (byte)0xB8
        }), new OctetString(new byte[] {
            (byte)0x02, (byte)0x17, (byte)0xC0, (byte)0x56, 
            (byte)0x10, (byte)0x88, (byte)0x4B, (byte)0x63, 
            (byte)0xB9, (byte)0xC6, (byte)0xC7, (byte)0x29, 
            (byte)0x16, (byte)0x78, (byte)0xF9, (byte)0xD3, 
            (byte)0x41
        }), new BitString(new byte[] {
            (byte)0x4D, (byte)0x69, (byte)0x6E, (byte)0x67, 
            (byte)0x68, (byte)0x75, (byte)0x61, (byte)0x51, 
            (byte)0x75, (byte)0x98, (byte)0x5B, (byte)0xD3, 
            (byte)0xAD, (byte)0xBA, (byte)0xDA, (byte)0x21, 
            (byte)0xB4, (byte)0x3A, (byte)0x97, (byte)0xE2
        })
    ); 
    private static final SpecifiedECDomain EC_SECT131R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT131, CURVE_SECT131R1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x00, (byte)0x81, (byte)0xBA, 
            (byte)0xF9, (byte)0x1F, (byte)0xDF, (byte)0x98, 
            (byte)0x33, (byte)0xC4, (byte)0x0F, (byte)0x9C, 
            (byte)0x18, (byte)0x13, (byte)0x43, (byte)0x63, 
            (byte)0x83, (byte)0x99
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x02, (byte)0x31, (byte)0x23, (byte)0x95, 
            (byte)0x3A, (byte)0x94, (byte)0x64, (byte)0xB5, 
            (byte)0x4D
        })), new Integer(0x02), null
    ); 
    private static final Curve CURVE_SECT131R2 = new Curve(
        new OctetString(new byte[] {
            (byte)0x03, (byte)0xE5, (byte)0xA8, (byte)0x89, 
            (byte)0x19, (byte)0xD7, (byte)0xCA, (byte)0xFC, 
            (byte)0xBF, (byte)0x41, (byte)0x5F, (byte)0x07, 
            (byte)0xC2, (byte)0x17, (byte)0x65, (byte)0x73, 
            (byte)0xB2
        }), new OctetString(new byte[] {
            (byte)0x04, (byte)0xB8, (byte)0x26, (byte)0x6A, 
            (byte)0x46, (byte)0xC5, (byte)0x56, (byte)0x57, 
            (byte)0xAC, (byte)0x73, (byte)0x4C, (byte)0xE3, 
            (byte)0x8F, (byte)0x01, (byte)0x8F, (byte)0x21, 
            (byte)0x92
        }), new BitString(new byte[] {
            (byte)0x98, (byte)0x5B, (byte)0xD3, (byte)0xAD, 
            (byte)0xBA, (byte)0xD4, (byte)0xD6, (byte)0x96, 
            (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
            (byte)0x15, (byte)0x17, (byte)0x5A, (byte)0x21, 
            (byte)0xB4, (byte)0x3A, (byte)0x97, (byte)0xE3
        })
    ); 
    private static final SpecifiedECDomain EC_SECT131R2 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT131, CURVE_SECT131R2, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x03, (byte)0x56, (byte)0xDC, 
            (byte)0xD8, (byte)0xF2, (byte)0xF9, (byte)0x50, 
            (byte)0x31, (byte)0xAD, (byte)0x65, (byte)0x2D, 
            (byte)0x23, (byte)0x95, (byte)0x1B, (byte)0xB3, 
            (byte)0x66, (byte)0xA8
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x01, (byte)0x69, (byte)0x54, (byte)0xA2, 
            (byte)0x33, (byte)0x04, (byte)0x9B, (byte)0xA9, 
            (byte)0x8F
        })), new Integer(0x02), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы sect163k1, sect163r1, sect163r2
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECT163 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(163), 
            new ObjectIdentifier(OID.X962_C2_BASIS_PP), 
            new Pentanomial(new Integer(3), new Integer(6), new Integer(7))
        )
    );
    private static final Curve CURVE_SECT163K1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x01
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x01
        }), null
    ); 
    private static final SpecifiedECDomain EC_SECT163K1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT163, CURVE_SECT163K1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x02, (byte)0xFE, (byte)0x13, 
            (byte)0xC0, (byte)0x53, (byte)0x7B, (byte)0xBC, 
            (byte)0x11, (byte)0xAC, (byte)0xAA, (byte)0x07, 
            (byte)0xD7, (byte)0x93, (byte)0xDE, (byte)0x4E, 
            (byte)0x6D, (byte)0x5E, (byte)0x5C, (byte)0x94, 
            (byte)0xEE, (byte)0xE8
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x01, 
            (byte)0x08, (byte)0xA2, (byte)0xE0, (byte)0xCC, 
            (byte)0x0D, (byte)0x99, (byte)0xF8, (byte)0xA5, 
            (byte)0xEF
        })), new Integer(0x02), null
    ); 
    private static final Curve CURVE_SECT163R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x07, (byte)0xB6, (byte)0x88, (byte)0x2C, 
            (byte)0xAA, (byte)0xEF, (byte)0xA8, (byte)0x4F, 
            (byte)0x95, (byte)0x54, (byte)0xFF, (byte)0x84, 
            (byte)0x28, (byte)0xBD, (byte)0x88, (byte)0xE2, 
            (byte)0x46, (byte)0xD2, (byte)0x78, (byte)0x2A, 
            (byte)0xE2
        }), new OctetString(new byte[] {
            (byte)0x07, (byte)0x13, (byte)0x61, (byte)0x2D, 
            (byte)0xCD, (byte)0xDC, (byte)0xB4, (byte)0x0A, 
            (byte)0xAB, (byte)0x94, (byte)0x6B, (byte)0xDA, 
            (byte)0x29, (byte)0xCA, (byte)0x91, (byte)0xF7, 
            (byte)0x3A, (byte)0xF9, (byte)0x58, (byte)0xAF, 
            (byte)0xD9
        }), new BitString(new byte[] {
            (byte)0x24, (byte)0xB7, (byte)0xB1, (byte)0x37, 
            (byte)0xC8, (byte)0xA1, (byte)0x4D, (byte)0x69, 
            (byte)0x6E, (byte)0x67, (byte)0x68, (byte)0x75, 
            (byte)0x61, (byte)0x51, (byte)0x75, (byte)0x6F, 
            (byte)0xD0, (byte)0xDA, (byte)0x2E, (byte)0x5C
        })
    ); 
    private static final SpecifiedECDomain EC_SECT163R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT163, CURVE_SECT163R1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x03, (byte)0x69, (byte)0x97, 
            (byte)0x96, (byte)0x97, (byte)0xAB, (byte)0x43, 
            (byte)0x89, (byte)0x77, (byte)0x89, (byte)0x56, 
            (byte)0x67, (byte)0x89, (byte)0x56, (byte)0x7F, 
            (byte)0x78, (byte)0x7A, (byte)0x78, (byte)0x76, 
            (byte)0xA6, (byte)0x54
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x03, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x48, 
            (byte)0xAA, (byte)0xB6, (byte)0x89, (byte)0xC2, 
            (byte)0x9C, (byte)0xA7, (byte)0x10, (byte)0x27, 
            (byte)0x9B
        })), new Integer(0x02), null
    ); 
    private static final Curve CURVE_SECT163R2 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x01
        }), new OctetString(new byte[] {
            (byte)0x02, (byte)0x0A, (byte)0x60, (byte)0x19, 
            (byte)0x07, (byte)0xB8, (byte)0xC9, (byte)0x53, 
            (byte)0xCA, (byte)0x14, (byte)0x81, (byte)0xEB, 
            (byte)0x10, (byte)0x51, (byte)0x2F, (byte)0x78, 
            (byte)0x74, (byte)0x4A, (byte)0x32, (byte)0x05, 
            (byte)0xFD
        }), new BitString(new byte[] {
            (byte)0x85, (byte)0xE2, (byte)0x5B, (byte)0xFE, 
            (byte)0x5C, (byte)0x86, (byte)0x22, (byte)0x6C, 
            (byte)0xDB, (byte)0x12, (byte)0x01, (byte)0x6F, 
            (byte)0x75, (byte)0x53, (byte)0xF9, (byte)0xD0, 
            (byte)0xE6, (byte)0x93, (byte)0xA2, (byte)0x68
        })
    ); 
    private static final SpecifiedECDomain EC_SECT163R2 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT163, CURVE_SECT163R2, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x03, (byte)0xF0, (byte)0xEB, 
            (byte)0xA1, (byte)0x62, (byte)0x86, (byte)0xA2, 
            (byte)0xD5, (byte)0x7E, (byte)0xA0, (byte)0x99, 
            (byte)0x11, (byte)0x68, (byte)0xD4, (byte)0x99, 
            (byte)0x46, (byte)0x37, (byte)0xE8, (byte)0x34, 
            (byte)0x3E, (byte)0x36
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x92, 
            (byte)0xFE, (byte)0x77, (byte)0xE7, (byte)0x0C, 
            (byte)0x12, (byte)0xA4, (byte)0x23, (byte)0x4C, 
            (byte)0x33
        })), new Integer(0x02), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы sect193r1, sect193r2
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECT193 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(193), 
            new ObjectIdentifier(OID.X962_C2_BASIS_TP), 
            new Integer(15)
        )
    );
    private static final Curve CURVE_SECT193R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x17, (byte)0x85, (byte)0x8F, 
            (byte)0xEB, (byte)0x7A, (byte)0x98, (byte)0x97, 
            (byte)0x51, (byte)0x69, (byte)0xE1, (byte)0x71, 
            (byte)0xF7, (byte)0x7B, (byte)0x40, (byte)0x87, 
            (byte)0xDE, (byte)0x09, (byte)0x8A, (byte)0xC8, 
            (byte)0xA9, (byte)0x11, (byte)0xDF, (byte)0x7B, 
            (byte)0x01
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0xFD, (byte)0xFB, (byte)0x49, 
            (byte)0xBF, (byte)0xE6, (byte)0xC3, (byte)0xA8, 
            (byte)0x9F, (byte)0xAC, (byte)0xAD, (byte)0xAA, 
            (byte)0x7A, (byte)0x1E, (byte)0x5B, (byte)0xBC, 
            (byte)0x7C, (byte)0xC1, (byte)0xC2, (byte)0xE5, 
            (byte)0xD8, (byte)0x31, (byte)0x47, (byte)0x88, 
            (byte)0x14
        }), new BitString(new byte[] {
            (byte)0x10, (byte)0x3F, (byte)0xAE, (byte)0xC7, 
            (byte)0x4D, (byte)0x69, (byte)0x6E, (byte)0x67, 
            (byte)0x68, (byte)0x75, (byte)0x61, (byte)0x51, 
            (byte)0x75, (byte)0x77, (byte)0x7F, (byte)0xC5, 
            (byte)0xB1, (byte)0x91, (byte)0xEF, (byte)0x30
        })
    ); 
    private static final SpecifiedECDomain EC_SECT193R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT193, CURVE_SECT193R1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x01, (byte)0xF4, (byte)0x81, 
            (byte)0xBC, (byte)0x5F, (byte)0x0F, (byte)0xF8, 
            (byte)0x4A, (byte)0x74, (byte)0xAD, (byte)0x6C, 
            (byte)0xDF, (byte)0x6F, (byte)0xDE, (byte)0xF4, 
            (byte)0xBF, (byte)0x61, (byte)0x79, (byte)0x62, 
            (byte)0x53, (byte)0x72, (byte)0xD8, (byte)0xC0, 
            (byte)0xC5, (byte)0xE1
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0xC7, (byte)0xF3, (byte)0x4A, 
            (byte)0x77, (byte)0x8F, (byte)0x44, (byte)0x3A, 
            (byte)0xCC, (byte)0x92, (byte)0x0E, (byte)0xBA, 
            (byte)0x49
        })), new Integer(0x02), null
    ); 
    private static final Curve CURVE_SECT193R2 = new Curve(
        new OctetString(new byte[] {
            (byte)0x01, (byte)0x63, (byte)0xF3, (byte)0x5A, 
            (byte)0x51, (byte)0x37, (byte)0xC2, (byte)0xCE, 
            (byte)0x3E, (byte)0xA6, (byte)0xED, (byte)0x86, 
            (byte)0x67, (byte)0x19, (byte)0x0B, (byte)0x0B, 
            (byte)0xC4, (byte)0x3E, (byte)0xCD, (byte)0x69, 
            (byte)0x97, (byte)0x77, (byte)0x02, (byte)0x70, 
            (byte)0x9B
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0xC9, (byte)0xBB, (byte)0x9E, 
            (byte)0x89, (byte)0x27, (byte)0xD4, (byte)0xD6, 
            (byte)0x4C, (byte)0x37, (byte)0x7E, (byte)0x2A, 
            (byte)0xB2, (byte)0x85, (byte)0x6A, (byte)0x5B, 
            (byte)0x16, (byte)0xE3, (byte)0xEF, (byte)0xB7, 
            (byte)0xF6, (byte)0x1D, (byte)0x43, (byte)0x16, 
            (byte)0xAE
        }), new BitString(new byte[] {
            (byte)0x10, (byte)0xB7, (byte)0xB4, (byte)0xD6, 
            (byte)0x96, (byte)0xE6, (byte)0x76, (byte)0x87, 
            (byte)0x56, (byte)0x15, (byte)0x17, (byte)0x51, 
            (byte)0x37, (byte)0xC8, (byte)0xA1, (byte)0x6F, 
            (byte)0xD0, (byte)0xDA, (byte)0x22, (byte)0x11
        })
    ); 
    private static final SpecifiedECDomain EC_SECT193R2 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT193, CURVE_SECT193R2, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x00, (byte)0xD9, (byte)0xB6, 
            (byte)0x7D, (byte)0x19, (byte)0x2E, (byte)0x03, 
            (byte)0x67, (byte)0xC8, (byte)0x03, (byte)0xF3, 
            (byte)0x9E, (byte)0x1A, (byte)0x7E, (byte)0x82, 
            (byte)0xCA, (byte)0x14, (byte)0xA6, (byte)0x51, 
            (byte)0x35, (byte)0x0A, (byte)0xAE, (byte)0x61, 
            (byte)0x7E, (byte)0x8F
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x01, (byte)0x5A, (byte)0xAB, (byte)0x56, 
            (byte)0x1B, (byte)0x00, (byte)0x54, (byte)0x13, 
            (byte)0xCC, (byte)0xD4, (byte)0xEE, (byte)0x99, 
            (byte)0xD5
        })), new Integer(0x02), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы sect233k1, sect233r1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECT233 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(233), 
            new ObjectIdentifier(OID.X962_C2_BASIS_TP), 
            new Integer(74)
        )
    );
    private static final Curve CURVE_SECT233K1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x01
        }), null
    ); 
    private static final SpecifiedECDomain EC_SECT233K1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT233, CURVE_SECT233K1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x01, (byte)0x72, (byte)0x32, 
            (byte)0xBA, (byte)0x85, (byte)0x3A, (byte)0x7E, 
            (byte)0x73, (byte)0x1A, (byte)0xF1, (byte)0x29, 
            (byte)0xF2, (byte)0x2F, (byte)0xF4, (byte)0x14, 
            (byte)0x95, (byte)0x63, (byte)0xA4, (byte)0x19, 
            (byte)0xC2, (byte)0x6B, (byte)0xF5, (byte)0x0A, 
            (byte)0x4C, (byte)0x9D, (byte)0x6E, (byte)0xEF, 
            (byte)0xAD, (byte)0x61, (byte)0x26
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x06, (byte)0x9D, 
            (byte)0x5B, (byte)0xB9, (byte)0x15, (byte)0xBC, 
            (byte)0xD4, (byte)0x6E, (byte)0xFB, (byte)0x1A, 
            (byte)0xD5, (byte)0xF1, (byte)0x73, (byte)0xAB, 
            (byte)0xDF
        })), new Integer(0x04), null
    ); 
    private static final Curve CURVE_SECT233R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x01
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x66, (byte)0x64, (byte)0x7E, 
            (byte)0xDE, (byte)0x6C, (byte)0x33, (byte)0x2C, 
            (byte)0x7F, (byte)0x8C, (byte)0x09, (byte)0x23, 
            (byte)0xBB, (byte)0x58, (byte)0x21, (byte)0x3B, 
            (byte)0x33, (byte)0x3B, (byte)0x20, (byte)0xE9, 
            (byte)0xCE, (byte)0x42, (byte)0x81, (byte)0xFE, 
            (byte)0x11, (byte)0x5F, (byte)0x7D, (byte)0x8F, 
            (byte)0x90, (byte)0xAD
        }), new BitString(new byte[] {
            (byte)0x74, (byte)0xD5, (byte)0x9F, (byte)0xF0, 
            (byte)0x7F, (byte)0x6B, (byte)0x41, (byte)0x3D, 
            (byte)0x0E, (byte)0xA1, (byte)0x4B, (byte)0x34, 
            (byte)0x4B, (byte)0x20, (byte)0xA2, (byte)0xDB, 
            (byte)0x04, (byte)0x9B, (byte)0x50, (byte)0xC3
        })
    ); 
    private static final SpecifiedECDomain EC_SECT233R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT233, CURVE_SECT233R1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x00, (byte)0xFA, (byte)0xC9, 
            (byte)0xDF, (byte)0xCB, (byte)0xAC, (byte)0x83, 
            (byte)0x13, (byte)0xBB, (byte)0x21, (byte)0x39, 
            (byte)0xF1, (byte)0xBB, (byte)0x75, (byte)0x5F, 
            (byte)0xEF, (byte)0x65, (byte)0xBC, (byte)0x39, 
            (byte)0x1F, (byte)0x8B, (byte)0x36, (byte)0xF8, 
            (byte)0xF8, (byte)0xEB, (byte)0x73, (byte)0x71, 
            (byte)0xFD, (byte)0x55, (byte)0x8B
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x13, 
            (byte)0xE9, (byte)0x74, (byte)0xE7, (byte)0x2F, 
            (byte)0x8A, (byte)0x69, (byte)0x22, (byte)0x03, 
            (byte)0x1D, (byte)0x26, (byte)0x03, (byte)0xCF, 
            (byte)0xE0, (byte)0xD7
        })), new Integer(0x02), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы sect233k1, sect233r1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECT239 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(239), 
            new ObjectIdentifier(OID.X962_C2_BASIS_TP), 
            new Integer(158)
        )
    );
    private static final Curve CURVE_SECT239K1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x01
        }), null
    ); 
    private static final SpecifiedECDomain EC_SECT239K1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT239, CURVE_SECT239K1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x29, (byte)0xA0, (byte)0xB6, 
            (byte)0xA8, (byte)0x87, (byte)0xA9, (byte)0x83, 
            (byte)0xE9, (byte)0x73, (byte)0x09, (byte)0x88, 
            (byte)0xA6, (byte)0x87, (byte)0x27, (byte)0xA8, 
            (byte)0xB2, (byte)0xD1, (byte)0x26, (byte)0xC4, 
            (byte)0x4C, (byte)0xC2, (byte)0xCC, (byte)0x7B, 
            (byte)0x2A, (byte)0x65, (byte)0x55, (byte)0x19, 
            (byte)0x30, (byte)0x35, (byte)0xDC
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x5A, 
            (byte)0x79, (byte)0xFE, (byte)0xC6, (byte)0x7C, 
            (byte)0xB6, (byte)0xE9, (byte)0x1F, (byte)0x1C, 
            (byte)0x1D, (byte)0xA8, (byte)0x00, (byte)0xE4, 
            (byte)0x78, (byte)0xA5
        })), new Integer(0x04), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы sect283k1, sect283r1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECT283 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(283), 
            new ObjectIdentifier(OID.X962_C2_BASIS_PP), 
            new Pentanomial(new Integer(5), new Integer(7), new Integer(12))
        )
    );
    private static final Curve CURVE_SECT283K1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
        }), null
    ); 
    private static final SpecifiedECDomain EC_SECT283K1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT283, CURVE_SECT283K1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x05, (byte)0x03, (byte)0x21, 
            (byte)0x3F, (byte)0x78, (byte)0xCA, (byte)0x44, 
            (byte)0x88, (byte)0x3F, (byte)0x1A, (byte)0x3B, 
            (byte)0x81, (byte)0x62, (byte)0xF1, (byte)0x88, 
            (byte)0xE5, (byte)0x53, (byte)0xCD, (byte)0x26, 
            (byte)0x5F, (byte)0x23, (byte)0xC1, (byte)0x56, 
            (byte)0x7A, (byte)0x16, (byte)0x87, (byte)0x69, 
            (byte)0x13, (byte)0xB0, (byte)0xC2, (byte)0xAC, 
            (byte)0x24, (byte)0x58, (byte)0x49, (byte)0x28, 
            (byte)0x36
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xE9, (byte)0xAE, 
            (byte)0x2E, (byte)0xD0, (byte)0x75, (byte)0x77, 
            (byte)0x26, (byte)0x5D, (byte)0xFF, (byte)0x7F, 
            (byte)0x94, (byte)0x45, (byte)0x1E, (byte)0x06, 
            (byte)0x1E, (byte)0x16, (byte)0x3C, (byte)0x61
        })), new Integer(0x04), null
    ); 
    private static final Curve CURVE_SECT283R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
        }), new OctetString(new byte[] {
            (byte)0x02, (byte)0x7B, (byte)0x68, (byte)0x0A, 
            (byte)0xC8, (byte)0xB8, (byte)0x59, (byte)0x6D, 
            (byte)0xA5, (byte)0xA4, (byte)0xAF, (byte)0x8A, 
            (byte)0x19, (byte)0xA0, (byte)0x30, (byte)0x3F, 
            (byte)0xCA, (byte)0x97, (byte)0xFD, (byte)0x76, 
            (byte)0x45, (byte)0x30, (byte)0x9F, (byte)0xA2, 
            (byte)0xA5, (byte)0x81, (byte)0x48, (byte)0x5A,
            (byte)0xF6, (byte)0x26, (byte)0x3E, (byte)0x31, 
            (byte)0x3B, (byte)0x79, (byte)0xA2, (byte)0xF5
        }), new BitString(new byte[] {
            (byte)0x77, (byte)0xE2, (byte)0xB0, (byte)0x73, 
            (byte)0x70, (byte)0xEB, (byte)0x0F, (byte)0x83, 
            (byte)0x2A, (byte)0x6D, (byte)0xD5, (byte)0xB6, 
            (byte)0x2D, (byte)0xFC, (byte)0x88, (byte)0xCD, 
            (byte)0x06, (byte)0xBB, (byte)0x84, (byte)0xBE
        })
    ); 
    private static final SpecifiedECDomain EC_SECT283R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT283, CURVE_SECT283R1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x05, (byte)0xF9, (byte)0x39, 
            (byte)0x25, (byte)0x8D, (byte)0xB7, (byte)0xDD, 
            (byte)0x90, (byte)0xE1, (byte)0x93, (byte)0x4F, 
            (byte)0x8C, (byte)0x70, (byte)0xB0, (byte)0xDF, 
            (byte)0xEC, (byte)0x2E, (byte)0xED, (byte)0x25, 
            (byte)0xB8, (byte)0x55, (byte)0x7E, (byte)0xAC, 
            (byte)0x9C, (byte)0x80, (byte)0xE2, (byte)0xE1, 
            (byte)0x98, (byte)0xF8, (byte)0xCD, (byte)0xBE, 
            (byte)0xCD, (byte)0x86, (byte)0xB1, (byte)0x20, 
            (byte)0x53
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x03, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xEF, (byte)0x90, 
            (byte)0x39, (byte)0x96, (byte)0x60, (byte)0xFC, 
            (byte)0x93, (byte)0x8A, (byte)0x90, (byte)0x16, 
            (byte)0x5B, (byte)0x04, (byte)0x2A, (byte)0x7C, 
            (byte)0xEF, (byte)0xAD, (byte)0xB3, (byte)0x07
        })), new Integer(0x02), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы sect409k1, sect409r1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECT409 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(409), 
            new ObjectIdentifier(OID.X962_C2_BASIS_TP), 
            new Integer(87)
        )
    );
    private static final Curve CURVE_SECT409K1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
        }), null
    ); 
    private static final SpecifiedECDomain EC_SECT409K1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT409, CURVE_SECT409K1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x00, (byte)0x60, (byte)0xF0, 
            (byte)0x5F, (byte)0x65, (byte)0x8F, (byte)0x49, 
            (byte)0xC1, (byte)0xAD, (byte)0x3A, (byte)0xB1, 
            (byte)0x89, (byte)0x0F, (byte)0x71, (byte)0x84, 
            (byte)0x21, (byte)0x0E, (byte)0xFD, (byte)0x09, 
            (byte)0x87, (byte)0xE3, (byte)0x07, (byte)0xC8, 
            (byte)0x4C, (byte)0x27, (byte)0xAC, (byte)0xCF, 
            (byte)0xB8, (byte)0xF9, (byte)0xF6, (byte)0x7C, 
            (byte)0xC2, (byte)0xC4, (byte)0x60, (byte)0x18, 
            (byte)0x9E, (byte)0xB5, (byte)0xAA, (byte)0xAA, 
            (byte)0x62, (byte)0xEE, (byte)0x22, (byte)0x2E, 
            (byte)0xB1, (byte)0xB3, (byte)0x55, (byte)0x40, 
            (byte)0xCF, (byte)0xE9, (byte)0x02, (byte)0x37, 
            (byte)0x46
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFE, (byte)0x5F, (byte)0x83, 
            (byte)0xB2, (byte)0xD4, (byte)0xEA, (byte)0x20, 
            (byte)0x40, (byte)0x0E, (byte)0xC4, (byte)0x55, 
            (byte)0x7D, (byte)0x5E, (byte)0xD3, (byte)0xE3, 
            (byte)0xE7, (byte)0xCA, (byte)0x5B, (byte)0x4B, 
            (byte)0x5C, (byte)0x83, (byte)0xB8, (byte)0xE0, 
            (byte)0x1E, (byte)0x5F, (byte)0xCF
        })), new Integer(0x04), null
    ); 
    private static final Curve CURVE_SECT409R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x21, (byte)0xA5, (byte)0xC2, 
            (byte)0xC8, (byte)0xEE, (byte)0x9F, (byte)0xEB, 
            (byte)0x5C, (byte)0x4B, (byte)0x9A, (byte)0x75, 
            (byte)0x3B, (byte)0x7B, (byte)0x47, (byte)0x6B, 
            (byte)0x7F, (byte)0xD6, (byte)0x42, (byte)0x2E, 
            (byte)0xF1, (byte)0xF3, (byte)0xDD, (byte)0x67, 
            (byte)0x47, (byte)0x61, (byte)0xFA, (byte)0x99, 
            (byte)0xD6, (byte)0xAC, (byte)0x27, (byte)0xC8, 
            (byte)0xA9, (byte)0xA1, (byte)0x97, (byte)0xB2, 
            (byte)0x72, (byte)0x82, (byte)0x2F, (byte)0x6C, 
            (byte)0xD5, (byte)0x7A, (byte)0x55, (byte)0xAA, 
            (byte)0x4F, (byte)0x50, (byte)0xAE, (byte)0x31, 
            (byte)0x7B, (byte)0x13, (byte)0x54, (byte)0x5F
        }), new BitString(new byte[] {
            (byte)0x40, (byte)0x99, (byte)0xB5, (byte)0xA4, 
            (byte)0x57, (byte)0xF9, (byte)0xD6, (byte)0x9F, 
            (byte)0x79, (byte)0x21, (byte)0x3D, (byte)0x09, 
            (byte)0x4C, (byte)0x4B, (byte)0xCD, (byte)0x4D, 
            (byte)0x42, (byte)0x62, (byte)0x21, (byte)0x0B
        })
    ); 
    private static final SpecifiedECDomain EC_SECT409R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT409, CURVE_SECT409R1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x01, (byte)0x5D, (byte)0x48, 
            (byte)0x60, (byte)0xD0, (byte)0x88, (byte)0xDD, 
            (byte)0xB3, (byte)0x49, (byte)0x6B, (byte)0x0C, 
            (byte)0x60, (byte)0x64, (byte)0x75, (byte)0x62, 
            (byte)0x60, (byte)0x44, (byte)0x1C, (byte)0xDE, 
            (byte)0x4A, (byte)0xF1, (byte)0x77, (byte)0x1D, 
            (byte)0x4D, (byte)0xB0, (byte)0x1F, (byte)0xFE, 
            (byte)0x5B, (byte)0x34, (byte)0xE5, (byte)0x97, 
            (byte)0x03, (byte)0xDC, (byte)0x25, (byte)0x5A, 
            (byte)0x86, (byte)0x8A, (byte)0x11, (byte)0x80, 
            (byte)0x51, (byte)0x56, (byte)0x03, (byte)0xAE, 
            (byte)0xAB, (byte)0x60, (byte)0x79, (byte)0x4E, 
            (byte)0x54, (byte)0xBB, (byte)0x79, (byte)0x96, 
            (byte)0xA7
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x01, (byte)0xE2, 
            (byte)0xAA, (byte)0xD6, (byte)0xA6, (byte)0x12, 
            (byte)0xF3, (byte)0x33, (byte)0x07, (byte)0xBE, 
            (byte)0x5F, (byte)0xA4, (byte)0x7C, (byte)0x3C, 
            (byte)0x9E, (byte)0x05, (byte)0x2F, (byte)0x83, 
            (byte)0x81, (byte)0x64, (byte)0xCD, (byte)0x37, 
            (byte)0xD9, (byte)0xA2, (byte)0x11, (byte)0x73
        })), new Integer(0x02), null
    ); 
    ////////////////////////////////////////////////////////////////////////////
    // Наборы sect571k1, sect571r1
    ////////////////////////////////////////////////////////////////////////////
    private static final FieldID FIELD_SECT571 = new FieldID(
        new ObjectIdentifier(OID.X962_C2_FIELD), 
        new CharacteristicTwo(new Integer(571), 
            new ObjectIdentifier(OID.X962_C2_BASIS_PP), 
            new Pentanomial(new Integer(2), new Integer(5), new Integer(10))
        )
    );
    private static final Curve CURVE_SECT571K1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }), new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
        }), null
    ); 
    private static final SpecifiedECDomain EC_SECT571K1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT571, CURVE_SECT571K1, 
        new OctetString(new byte[] {
            (byte)0x02, (byte)0x02, (byte)0x6E, (byte)0xB7, 
            (byte)0xA8, (byte)0x59, (byte)0x92, (byte)0x3F, 
            (byte)0xBC, (byte)0x82, (byte)0x18, (byte)0x96, 
            (byte)0x31, (byte)0xF8, (byte)0x10, (byte)0x3F, 
            (byte)0xE4, (byte)0xAC, (byte)0x9C, (byte)0xA2, 
            (byte)0x97, (byte)0x00, (byte)0x12, (byte)0xD5, 
            (byte)0xD4, (byte)0x60, (byte)0x24, (byte)0x80, 
            (byte)0x48, (byte)0x01, (byte)0x84, (byte)0x1C, 
            (byte)0xA4, (byte)0x43, (byte)0x70, (byte)0x95, 
            (byte)0x84, (byte)0x93, (byte)0xB2, (byte)0x05, 
            (byte)0xE6, (byte)0x47, (byte)0xDA, (byte)0x30, 
            (byte)0x4D, (byte)0xB4, (byte)0xCE, (byte)0xB0, 
            (byte)0x8C, (byte)0xBB, (byte)0xD1, (byte)0xBA, 
            (byte)0x39, (byte)0x49, (byte)0x47, (byte)0x76, 
            (byte)0xFB, (byte)0x98, (byte)0x8B, (byte)0x47, 
            (byte)0x17, (byte)0x4D, (byte)0xCA, (byte)0x88, 
            (byte)0xC7, (byte)0xE2, (byte)0x94, (byte)0x52, 
            (byte)0x83, (byte)0xA0, (byte)0x1C, (byte)0x89, 
            (byte)0x72
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x13, (byte)0x18, (byte)0x50, (byte)0xE1, 
            (byte)0xF1, (byte)0x9A, (byte)0x63, (byte)0xE4, 
            (byte)0xB3, (byte)0x91, (byte)0xA8, (byte)0xDB, 
            (byte)0x91, (byte)0x7F, (byte)0x41, (byte)0x38, 
            (byte)0xB6, (byte)0x30, (byte)0xD8, (byte)0x4B,
            (byte)0xE5, (byte)0xD6, (byte)0x39, (byte)0x38, 
            (byte)0x1E, (byte)0x91, (byte)0xDE, (byte)0xB4, 
            (byte)0x5C, (byte)0xFE, (byte)0x77, (byte)0x8F, 
            (byte)0x63, (byte)0x7C, (byte)0x10, (byte)0x01
        })), new Integer(0x04), null
    ); 
    private static final Curve CURVE_SECT571R1 = new Curve(
        new OctetString(new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
        }), new OctetString(new byte[] {
            (byte)0x02, (byte)0xF4, (byte)0x0E, (byte)0x7E, 
            (byte)0x22, (byte)0x21, (byte)0xF2, (byte)0x95, 
            (byte)0xDE, (byte)0x29, (byte)0x71, (byte)0x17, 
            (byte)0xB7, (byte)0xF3, (byte)0xD6, (byte)0x2F, 
            (byte)0x5C, (byte)0x6A, (byte)0x97, (byte)0xFF, 
            (byte)0xCB, (byte)0x8C, (byte)0xEF, (byte)0xF1, 
            (byte)0xCD, (byte)0x6B, (byte)0xA8, (byte)0xCE, 
            (byte)0x4A, (byte)0x9A, (byte)0x18, (byte)0xAD, 
            (byte)0x84, (byte)0xFF, (byte)0xAB, (byte)0xBD, 
            (byte)0x8E, (byte)0xFA, (byte)0x59, (byte)0x33, 
            (byte)0x2B, (byte)0xE7, (byte)0xAD, (byte)0x67, 
            (byte)0x56, (byte)0xA6, (byte)0x6E, (byte)0x29, 
            (byte)0x4A, (byte)0xFD, (byte)0x18, (byte)0x5A, 
            (byte)0x78, (byte)0xFF, (byte)0x12, (byte)0xAA, 
            (byte)0x52, (byte)0x0E, (byte)0x4D, (byte)0xE7, 
            (byte)0x39, (byte)0xBA, (byte)0xCA, (byte)0x0C, 
            (byte)0x7F, (byte)0xFE, (byte)0xFF, (byte)0x7F, 
            (byte)0x29, (byte)0x55, (byte)0x72, (byte)0x7A
        }), new BitString(new byte[] {
            (byte)0x2A, (byte)0xA0, (byte)0x58, (byte)0xF7, 
            (byte)0x3A, (byte)0x0E, (byte)0x33, (byte)0xAB, 
            (byte)0x48, (byte)0x6B, (byte)0x0F, (byte)0x61, 
            (byte)0x04, (byte)0x10, (byte)0xC5, (byte)0x3A, 
            (byte)0x7F, (byte)0x13, (byte)0x23, (byte)0x10
        })
    ); 
    private static final SpecifiedECDomain EC_SECT571R1 = new SpecifiedECDomain(
        new Integer(1), FIELD_SECT571, CURVE_SECT571R1, 
        new OctetString(new byte[] {
            (byte)0x03, (byte)0x03, (byte)0x03, (byte)0x00, 
            (byte)0x1D, (byte)0x34, (byte)0xB8, (byte)0x56, 
            (byte)0x29, (byte)0x6C, (byte)0x16, (byte)0xC0, 
            (byte)0xD4, (byte)0x0D, (byte)0x3C, (byte)0xD7, 
            (byte)0x75, (byte)0x0A, (byte)0x93, (byte)0xD1, 
            (byte)0xD2, (byte)0x95, (byte)0x5F, (byte)0xA8, 
            (byte)0x0A, (byte)0xA5, (byte)0xF4, (byte)0x0F, 
            (byte)0xC8, (byte)0xDB, (byte)0x7B, (byte)0x2A, 
            (byte)0xBD, (byte)0xBD, (byte)0xE5, (byte)0x39, 
            (byte)0x50, (byte)0xF4, (byte)0xC0, (byte)0xD2, 
            (byte)0x93, (byte)0xCD, (byte)0xD7, (byte)0x11, 
            (byte)0xA3, (byte)0x5B, (byte)0x67, (byte)0xFB, 
            (byte)0x14, (byte)0x99, (byte)0xAE, (byte)0x60, 
            (byte)0x03, (byte)0x86, (byte)0x14, (byte)0xF1, 
            (byte)0x39, (byte)0x4A, (byte)0xBF, (byte)0xA3, 
            (byte)0xB4, (byte)0xC8, (byte)0x50, (byte)0xD9, 
            (byte)0x27, (byte)0xE1, (byte)0xE7, (byte)0x76, 
            (byte)0x9C, (byte)0x8E, (byte)0xEC, (byte)0x2D, 
            (byte)0x19
        }), new Integer(new BigInteger(1, new byte[] {
            (byte)0x03, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
            (byte)0xE6, (byte)0x61, (byte)0xCE, (byte)0x18, 
            (byte)0xFF, (byte)0x55, (byte)0x98, (byte)0x73, 
            (byte)0x08, (byte)0x05, (byte)0x9B, (byte)0x18, 
            (byte)0x68, (byte)0x23, (byte)0x85, (byte)0x1E, 
            (byte)0xC7, (byte)0xDD, (byte)0x9C, (byte)0xA1, 
            (byte)0x16, (byte)0x1D, (byte)0xE9, (byte)0x3D, 
            (byte)0x51, (byte)0x74, (byte)0xD6, (byte)0x6E, 
            (byte)0x83, (byte)0x82, (byte)0xE9, (byte)0xBB, 
            (byte)0x2F, (byte)0xE8, (byte)0x4E, (byte)0x47
        })), new Integer(0x02), null
    ); 
	// таблица именованных параметров
	private static final Map<String, SpecifiedECDomain> set = 
		new HashMap<String, SpecifiedECDomain>(); 
	static {
        set.put(OID.X962_CURVES_C2PNB163V1, EC_C2PNB163V1); 
        set.put(OID.X962_CURVES_C2PNB163V2, EC_C2PNB163V2);
        set.put(OID.X962_CURVES_C2PNB163V3, EC_C2PNB163V3);
        set.put(OID.X962_CURVES_C2PNB176W1, EC_C2PNB176W1);
        set.put(OID.X962_CURVES_C2TNB191V1, EC_C2TNB191V1);
        set.put(OID.X962_CURVES_C2TNB191V2, EC_C2TNB191V2);
        set.put(OID.X962_CURVES_C2TNB191V3, EC_C2TNB191V3);
        set.put(OID.X962_CURVES_C2ONB191V4, EC_C2ONB191V4);
        set.put(OID.X962_CURVES_C2ONB191V5, EC_C2ONB191V5);
        set.put(OID.X962_CURVES_C2PNB208W1, EC_C2PNB208W1); 
        set.put(OID.X962_CURVES_C2TNB239V1, EC_C2TNB239V1); 
        set.put(OID.X962_CURVES_C2TNB239V2, EC_C2TNB239V2); 
        set.put(OID.X962_CURVES_C2TNB239V3, EC_C2TNB239V3); 
        set.put(OID.X962_CURVES_C2ONB239V4, EC_C2ONB239V4); 
        set.put(OID.X962_CURVES_C2ONB239V5, EC_C2ONB239V5); 
        set.put(OID.X962_CURVES_C2PNB272W1, EC_C2PNB272W1); 
        set.put(OID.X962_CURVES_C2PNB304W1, EC_C2PNB304W1); 
        set.put(OID.X962_CURVES_C2TNB359V1, EC_C2TNB359V1);
        set.put(OID.X962_CURVES_C2PNB368W1, EC_C2PNB368W1);
        set.put(OID.X962_CURVES_C2TNB431R1, EC_C2TNB431R1);
        set.put(OID.X962_CURVES_PRIME192V1, EC_PRIME192V1);
        set.put(OID.X962_CURVES_PRIME192V2, EC_PRIME192V2);
        set.put(OID.X962_CURVES_PRIME192V3, EC_PRIME192V3);
        set.put(OID.X962_CURVES_PRIME239V1, EC_PRIME239V1);
        set.put(OID.X962_CURVES_PRIME239V2, EC_PRIME239V2);
        set.put(OID.X962_CURVES_PRIME239V3, EC_PRIME239V3);
        set.put(OID.X962_CURVES_PRIME256V1, EC_PRIME256V1); 
        
        set.put(OID.CERTICOM_CURVES_SECP112R1, EC_SECP112R1); 
        set.put(OID.CERTICOM_CURVES_SECP112R2, EC_SECP112R2); 
        set.put(OID.CERTICOM_CURVES_SECP128R1, EC_SECP128R1); 
        set.put(OID.CERTICOM_CURVES_SECP128R2, EC_SECP128R2); 
        set.put(OID.CERTICOM_CURVES_SECP160K1, EC_SECP160K1); 
        set.put(OID.CERTICOM_CURVES_SECP160R1, EC_SECP160R1); 
        set.put(OID.CERTICOM_CURVES_SECP160R2, EC_SECP160R2); 
        set.put(OID.CERTICOM_CURVES_SECP192K1, EC_SECP192K1); 
        set.put(OID.CERTICOM_CURVES_SECP224K1, EC_SECP224K1); 
        set.put(OID.CERTICOM_CURVES_SECP224R1, EC_SECP224R1); 
        set.put(OID.CERTICOM_CURVES_SECP256K1, EC_SECP256K1); 
        set.put(OID.CERTICOM_CURVES_SECP384R1, EC_SECP384R1); 
        set.put(OID.CERTICOM_CURVES_SECP521R1, EC_SECP521R1); 
        set.put(OID.CERTICOM_CURVES_SECT113R1, EC_SECT113R1); 
        set.put(OID.CERTICOM_CURVES_SECT113R2, EC_SECT113R2); 
        set.put(OID.CERTICOM_CURVES_SECT131R1, EC_SECT131R1); 
        set.put(OID.CERTICOM_CURVES_SECT131R2, EC_SECT131R2); 
        set.put(OID.CERTICOM_CURVES_SECT163K1, EC_SECT163K1); 
        set.put(OID.CERTICOM_CURVES_SECT163R1, EC_SECT163R1); 
        set.put(OID.CERTICOM_CURVES_SECT163R2, EC_SECT163R2); 
        set.put(OID.CERTICOM_CURVES_SECT193R1, EC_SECT193R1); 
        set.put(OID.CERTICOM_CURVES_SECT193R2, EC_SECT193R2); 
        set.put(OID.CERTICOM_CURVES_SECT233K1, EC_SECT233K1); 
        set.put(OID.CERTICOM_CURVES_SECT233R1, EC_SECT233R1); 
        set.put(OID.CERTICOM_CURVES_SECT239K1, EC_SECT239K1); 
        set.put(OID.CERTICOM_CURVES_SECT283K1, EC_SECT283K1); 
        set.put(OID.CERTICOM_CURVES_SECT283R1, EC_SECT283R1); 
        set.put(OID.CERTICOM_CURVES_SECT409K1, EC_SECT409K1); 
        set.put(OID.CERTICOM_CURVES_SECT409R1, EC_SECT409R1); 
        set.put(OID.CERTICOM_CURVES_SECT571K1, EC_SECT571K1); 
        set.put(OID.CERTICOM_CURVES_SECT571R1, EC_SECT571R1); 
	}
	// получить именованные параметры
	public static SpecifiedECDomain parameters(String oid) { return set.get(oid); } 
}
