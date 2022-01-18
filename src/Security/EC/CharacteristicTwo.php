<?php


namespace Jazor\Security\EC;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\NotSupportedException;

class CharacteristicTwo implements ASN1Encodable
{

    private $m;
    private $basis;
    private $parameters;

    public function __construct($m, $basis, $parameters)
    {
        $this->m = $m;
        $this->basis = $basis;
        $this->parameters = $parameters;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Integer($this->m);
        $gen->ObjectIdentifier($this->basis);
        switch ($this->basis){
            case ECFieldID::CHARACTERISTIC_TWO_GN_BASIS:
                $gen->Null();
                break;
            case ECFieldID::CHARACTERISTIC_TWO_TP_BASIS:
                $gen->Integer($this->parameters);
                break;
            case ECFieldID::CHARACTERISTIC_TWO_PP_BASIS:
                $gen->Object($this->parameters);
                break;
            default:
                throw new NotSupportedException();
        }
        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $seq){
        $basis = $seq[1]->getValue();
        $parameters = null;

        switch ($basis){
            case ECFieldID::CHARACTERISTIC_TWO_GN_BASIS:
                $parameters = null;
                break;
            case ECFieldID::CHARACTERISTIC_TWO_TP_BASIS:
                $parameters = $seq[2]->getContents();
                break;
            case ECFieldID::CHARACTERISTIC_TWO_PP_BASIS:
                $parameters = Pentanomial::getInstance($seq[2]);
                break;

            default:
                throw new NotSupportedException();
        }

        return new static($seq[0]->getContents(), $basis, $parameters);
    }
}
