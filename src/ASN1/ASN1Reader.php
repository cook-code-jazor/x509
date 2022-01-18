<?php

namespace Jazor\ASN1;

use Jazor\ASN1\Objects\ASN1BitString;
use Jazor\ASN1\Objects\ASN1BMPString;
use Jazor\ASN1\Objects\ASN1Boolean;
use Jazor\ASN1\Objects\ASN1Context;
use Jazor\ASN1\Objects\ASN1Enumerated;
use Jazor\ASN1\Objects\ASN1GeneralizedTime;
use Jazor\ASN1\Objects\ASN1GeneralString;
use Jazor\ASN1\Objects\ASN1IA5String;
use Jazor\ASN1\Objects\ASN1NumericString;
use Jazor\ASN1\Objects\ASN1Object;
use Jazor\ASN1\Objects\ASN1ObjectIdentifier;
use Jazor\ASN1\Objects\ASN1Integer;
use Jazor\ASN1\Objects\ASN1Null;
use Jazor\ASN1\Objects\ASN1OctetString;
use Jazor\ASN1\Objects\ASN1PrintableString;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\ASN1\Objects\ASN1T61String;
use Jazor\ASN1\Objects\ASN1UTCTime;
use Jazor\ASN1\Objects\ASN1UTF8String;
use Jazor\ASN1\Objects\ASN1VisibleString;
use Jazor\UnexpectedException;
use Jazor\X509\PemReader;

class ASN1Reader
{

    /**
     * @param $file
     * @return ASN1BitString|ASN1BMPString|ASN1Context|ASN1GeneralizedTime|ASN1GeneralString|ASN1Integer|ASN1Null|ASN1NumericString|ASN1Object|ASN1ObjectIdentifier|ASN1OctetString|ASN1PrintableString|ASN1Sequence|ASN1UTCTime|ASN1UTF8String|ASN1VisibleString
     * @throws \Exception
     */
    public static function readFile($file){
        $contents = PemReader::getPemContents(file_get_contents($file), $name, false);
        if(!$contents){
            throw new UnexpectedException('except a pem file');
        }
        return self::read($contents);
    }

    /**
     * @param string $contents
     * @return ASN1BitString|ASN1BMPString|ASN1Context|ASN1GeneralizedTime|ASN1GeneralString|ASN1Integer|ASN1Null|ASN1NumericString|ASN1Object|ASN1ObjectIdentifier|ASN1OctetString|ASN1PrintableString|ASN1Sequence|ASN1UTCTime|ASN1UTF8String|ASN1VisibleString
     * @throws \Exception
     */
    public static function read(string $contents){
        $reader = DerSequenceReader::fromPayload($contents);
        return self::readFromSecquenceReader($reader);
    }

    /**
     * @param DerSequenceReader $reader
     * @param int $level
     * @return ASN1Object
     * @throws \Exception
     */
    private static function readFromSecquenceReader(DerSequenceReader $reader, int $level = 0)
    {
        $tag = $reader->peekTag();
        switch ($tag) {
            case DerTag::BitString:
                $padding = 0;
                $data = $reader->readBitString($padding);
                return new ASN1BitString($data, $padding);
            case DerTag::BMPString:
                return new ASN1BMPString($reader->readBMPString());
            case DerTag::IA5String:
                return new ASN1IA5String($reader->readIA5String());
            case DerTag::UTF8String:
                return new ASN1UTF8String($reader->readUtf8String());
            case DerTag::T61String:
                return new ASN1T61String($reader->readT61String());
            case DerTag::PrintableString:
                return new ASN1PrintableString($reader->readPrintableString());
            case DerTag::NumericString:
                return new ASN1NumericString($reader->readNumericString());
            case DerTag::VisibleString:
                return new ASN1VisibleString($reader->readString($tag));
            case DerTag::GeneralString:
                return new ASN1GeneralString($reader->readString($tag));
            case DerTag::OctetString:
                return new ASN1OctetString($reader->readOctetString());
            case DerTag::Integer:
                return new ASN1Integer($reader->readIntegerBytes());
            case DerTag::Enumerated:
                return new ASN1Enumerated($reader->readIntegerBytes(DerTag::Enumerated));
            case DerTag::Boolean:
                return new ASN1Boolean($reader->readBoolean());
            case DerTag::UTCTime:
                return new ASN1UTCTime($reader->readUtcTime());
            case DerTag::ObjectIdentifier:
                return new ASN1ObjectIdentifier($reader->readOidAsString());
            case DerTag::GeneralizedTime:
                return new ASN1GeneralizedTime($reader->readGeneralizedTime());
            case DerTag::Null:
                $reader->skipValue();
                return new ASN1Null();
            default:
                if (DerTag::Sequence == $tag || DerTag::Set == $tag || ($tag & DerTag::ConstructedFlag) == DerTag::ConstructedFlag) {
                    return self::readSequence($reader->readCollectionWithTag($tag), $tag, $level);
                }
                if(($tag & DerTag::ContextSpecificTagFlag) == DerTag::ContextSpecificTagFlag){
                    return new ASN1Context($tag & 0x1f, $reader->readNextContent());
                }
        }
        throw new \Exception('Unknown Tag[0x' . bin2hex(chr($tag)) . ']');
    }

    /**
     * @param DerSequenceReader $reader
     * @param int $tag
     * @param int $level
     * @return ASN1Sequence
     * @throws \Exception
     */
    private static function readSequence(DerSequenceReader $reader, int $tag, int $level = 0){
        $sequence = new ASN1Sequence($tag, $reader);
        while ($reader->hasData()){
            $sequence->addElement(self::readFromSecquenceReader($reader, $level + 1));
        }
        return $sequence;
    }
}
