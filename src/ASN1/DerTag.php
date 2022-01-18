<?php
namespace Jazor\ASN1;

class DerTag
{
    const Boolean = 0x01;
    const Integer = 0x02;
    const BitString = 0x03;
    const OctetString = 0x04;
    const Null = 0x05;
    const ObjectIdentifier = 0x06;
    const Enumerated = 0x0a;
    const UTF8String = 0x0c;
    const Sequence = 0x10;
    const Set = 0x11;
    const NumericString = 0x12;
    const PrintableString = 0x13;
    const T61String = 0x14;
    const IA5String = 0x16;
    const UTCTime = 0x17;
    const GeneralizedTime = 0x18;
    const VisibleString = 0x1a;
    const GeneralString = 0x1b;
    const BMPString = 0x1e;
    const TagNumberMask = 0x1f;
    const ConstructedFlag = 0x20;
    const ConstructedSequence = 0x30;
    const ConstructedSet = 0x31;
    const ContextSpecificTagFlag = 0x80;
    const ContextSpecificConstructedTag0 = 0xa0;
    const ContextSpecificConstructedTag1 = 0xa1;
    const ContextSpecificConstructedTag2 = 0xa2;
    const ContextSpecificConstructedTag3 = 0xa3;
    const TagClassMask = 0xc0;

//    const ClassUniversal = 0x00;
//    const ClassApplication = 0x40;
//    const ClassContextSpecific = 0x80;
//    const ClassPrivate = 0xa0;

    private static ?array $constants = null;
    public static function getName($tag){
        if($tag == DerTag::Sequence || $tag == DerTag::ConstructedSequence) return 'Sequence';
        if($tag == DerTag::Set || $tag == DerTag::ConstructedSet) return 'Set';
        $context = ($tag & DerTag::ContextSpecificTagFlag) > 0;
        if($context){
            return sprintf('Context[%s]', $tag & 0x0f);
        }
        if(self::$constants === null){
            $class = new \ReflectionClass(self::class);
            self::$constants = array_flip($class->getConstants());
        }
        return  self::$constants[$tag] ?? $tag;
    }
}
