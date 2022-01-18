<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\DerTag;

class ExtendedKeyUsage implements ASN1Encodable
{

    public static string $ServerAuth = "1.3.6.1.5.5.7.3.1";
    public static string $ClientAuth = "1.3.6.1.5.5.7.3.2";
    public static string $CodeSigning = "1.3.6.1.5.5.7.3.3";
    public static string $EmailProtection = "1.3.6.1.5.5.7.3.4";
    public static string $IpsecEndSystem = "1.3.6.1.5.5.7.3.5";
    public static string $IpsecTunnel = "1.3.6.1.5.5.7.3.6";
    public static string $IpsecUser = "1.3.6.1.5.5.7.3.7";
    public static string $TimeStamping = "1.3.6.1.5.5.7.3.8";
    public static string $OCSPSigning = "1.3.6.1.5.5.7.3.9";
    public static string $Wireless = "1.3.6.1.5.5.7.3.19";

    private static ?array $ExKeyUsagesMap = null;

    private static function initialize()
    {
        if (self::$ExKeyUsagesMap !== null) return;
        self::$ExKeyUsagesMap = [
            "1.3.6.1.5.5.7.3.1" => "ServerAuth",
            "1.3.6.1.5.5.7.3.2" => "ClientAuth",
            "1.3.6.1.5.5.7.3.3" => "CodeSigning",
            "1.3.6.1.5.5.7.3.4" => "EmailProtection",
            "1.3.6.1.5.5.7.3.5" => "IpsecEndSystem",
            "1.3.6.1.5.5.7.3.6" => "IpsecTunnel",
            "1.3.6.1.5.5.7.3.7" => "IpsecUser",
            "1.3.6.1.5.5.7.3.8" => "TimeStamping",
            "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
            "1.3.6.1.5.5.7.3.19" => "Wireless",
        ];
    }

    private array $usages = [];
    public function __construct(array $usages)
    {
        self::initialize();

        $this->usages = $usages;
    }

    public function getEncoded()
    {
        $seq = ASN1SequenceGenerator::create();
        foreach ($this->usages as $usage){
            $seq->ObjectIdentifier($usage);
        }
        return $seq->generate();
    }

    public function __toString()
    {
        $result = [];

        foreach ($this->usages as $usage){
            $result[] = self::$ExKeyUsagesMap[$usage] . '(' . $usage . ")";
        }
        return implode("\r\n", $result);
    }

    public static function getInstance($binary){
        self::initialize();
        $asn1 = ASN1Reader::read($binary);

        $elements = $asn1->getElements();
        $usages = [];
        for($i = 0; $i < count($elements); $i++){
            $usages[] = $elements[$i]->getValue();
        }
        return new static($usages);
    }
}
