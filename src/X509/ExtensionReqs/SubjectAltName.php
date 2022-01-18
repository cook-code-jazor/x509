<?php

namespace Jazor\X509\ExtensionReqs;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\X509\ExtensionReq;

class SubjectAltName implements ASN1Encodable
{

    const OID = '2.5.29.17';
    private string $type;
    private array $names;
    public function __construct(string $type)
    {
        if($type != self::OID) throw new \Exception('oid not match, expect: ' . self::OID);
        $this->type = $type;
        $this->names = [];
    }

    public function addName(string $name){
        array_push($this->names, $name);
    }

    private function genNames(){
        $gen = ASN1SequenceGenerator::create();
        foreach ($this->names as $name) {
            $gen->Context(2, $name);
        }
        return $gen->generate();
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->ObjectIdentifier(self::OID);
        $gen->OctetString($this->genNames());
        return $gen->generate();
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
        return sprintf("(SubjectAltName[%s])\r\n  Names = %s", $this->type, implode(', ', $this->names));
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }
}
