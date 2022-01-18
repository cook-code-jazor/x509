<?php

namespace Jazor\X509;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1BMPString;
use Jazor\ASN1\Objects\ASN1IA5String;
use Jazor\ASN1\Objects\ASN1NumericString;
use Jazor\ASN1\Objects\ASN1Object;
use Jazor\ASN1\Objects\ASN1PrintableString;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\ASN1\Objects\ASN1UTF8String;
use Jazor\Console;
use Jazor\Security\Oid\Oid;
use Jazor\UnexpectedException;

class X509Name implements ASN1Encodable
{

    public static array $KnownNames = [
        '2.5.4.3' => 'CN',
        '2.5.4.4' => 'Surname',
        '2.5.4.5' => 'SerialNumber',
        '2.5.4.6' => 'C',
        '2.5.4.7' => 'L',
        '2.5.4.8' => 'ST',
        '2.5.4.9' => 'Street',
        '2.5.4.10' => 'O',
        '2.5.4.11' => 'OU',
        '2.5.4.12' => 'T',
        '2.5.4.13' => 'Description',
        '2.5.4.15' => 'BusinessCategory',
        '2.5.4.16' => 'PostalAddress',
        '2.5.4.17' => 'PostalCode',
        '2.5.4.20' => 'TelephoneNumber',
        '2.5.4.41' => 'Name',
        '2.5.4.42' => 'GivenName',
        '2.5.4.43' => 'Initials',
        '2.5.4.44' => 'Generation',
        '2.5.4.45' => 'UniqueIdentifier',
        '2.5.4.46' => 'DnQualifier',
        '2.5.4.54' => 'DmdName',
        '2.5.4.65' => 'Pseudonym',
        '2.5.4.97' => 'OrganizationIdentifier',
        '1.3.6.1.5.5.7.9.1' => 'DateOfBirth',
        '1.3.6.1.5.5.7.9.2' => 'PlaceOfBirth',
        '1.3.6.1.5.5.7.9.3' => 'Gender',
        '1.3.6.1.5.5.7.9.4' => 'CountryOfCitizenship',
        '1.3.6.1.5.5.7.9.5' => 'CountryOfResidence',
        '1.3.36.8.3.14' => 'NameAtBirth',
        '1.2.840.113549.1.9.1' => 'E',
        '1.2.840.113549.1.9.2' => 'UnstructuredName',
        '1.2.840.113549.1.9.8' => 'UnstructuredAddress',
        '0.9.2342.19200300.100.1.25' => 'DC',
        '0.9.2342.19200300.100.1.1' => 'UID',
    ];

    private static $NameOidMap = null;
    private $names = [];

    public function __construct()
    {
        if(self::$NameOidMap == null){
            self::$NameOidMap = [];
            foreach (self::$KnownNames as $oid => $name){
                self::$NameOidMap[$name] = $oid;
            }
        }
    }
    /**
     * @param string $oid
     * @param ASN1Encodable|string $value
     */
    public function setName(string $oid, $value){
        if(is_string($value)){
            $value = $this->getOidValue($oid, $value);
        }
        if(!isset($this->names[$oid])){
            $this->names[$oid] = [];
        }
        $this->names[$oid][] = $value;
    }

    /**
     * @param $oid
     * @param $value
     * @return ASN1Object
     */
    private function getOidValue($oid, $value): ASN1Object
    {
        switch ($oid){
            case '1.2.840.113549.1.9.1': return new ASN1IA5String($value);
            case '2.5.4.6':
            case '2.5.4.3':
            case '2.5.4.10':
            return new ASN1PrintableString($value);
        }
        return new ASN1UTF8String($value);
    }
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        foreach ($this->names as $oid => $values){
            foreach ($values as $value) {
                $gen->Set()->Sequence(function (ASN1SequenceGenerator $gen) use ($oid, $value) {
                    $gen->ObjectIdentifier($oid);
                    $gen->Object($value);
                });
            }
        }
        return $gen->generate();
    }


    /**
     * @param ASN1Sequence $sequence
     * @return X509Name
     */
    public static function getInstance(ASN1Sequence $sequence)
    {
        $subject = new X509Name();
        foreach ($sequence->getElements() as $element){
            $x509Name = $element[0];

            $oid = $x509Name[0]->getValue();
            $value = $x509Name[1];
            $subject->setName($oid, $value);
        }
        return $subject;
    }

    /**
     * @return array
     */
    public function getNames(): array
    {
        return $this->names;
    }

    public function __toString()
    {
        $result = [];
        foreach ($this->names as $oid => $values){
            foreach ($values as $value) {
                $str = $value->getContents();
                //if(strpos($str, ',') !== false) $str = '"' . $str . '"';
                $result[] = sprintf("%s = %s", self::$KnownNames[$oid] ?? $oid, $str);
            }
        }
        return implode("\r\n", $result);
    }

}
