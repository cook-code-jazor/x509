<?php


namespace Jazor\Security\EC;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\NotSupportedException;

class ECFieldID implements ASN1Encodable
{
    const PRIME_FIELD = '1.2.840.10045.1.1';
    const CHARACTERISTIC_TWO_FIELD = '1.2.840.10045.1.2';
    const CHARACTERISTIC_TWO_BASIS = '1.2.840.10045.1.2.1';
    const CHARACTERISTIC_TWO_GN_BASIS = '1.2.840.10045.1.2.1.1';
    const CHARACTERISTIC_TWO_TP_BASIS = '1.2.840.10045.1.2.1.2';
    const CHARACTERISTIC_TWO_PP_BASIS = '1.2.840.10045.1.2.1.3';

    private string $type;
    private ?ASN1Encodable $parameters;

    /**
     * ECFieldID constructor.
     * @param string $type
     * @param null $parameters
     */
    public function __construct(string $type, $parameters = null)
    {
        $this->type = $type;
        $this->parameters = $parameters;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->ObjectIdentifier($this->type);

        switch ($this->type){
            case self::PRIME_FIELD:
                $gen->Integer($this->parameters);
                break;
            case self::CHARACTERISTIC_TWO_FIELD:
                $gen->Object($this->parameters);
                break;
            default:
                throw new NotSupportedException();
        }

        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $seq){
        $oid = $seq[0]->getValue();
        $parameters = null;
        switch ($oid){
            case self::PRIME_FIELD:
                $parameters = $seq[1]->getContents();
                break;
            case self::CHARACTERISTIC_TWO_FIELD:
                $parameters = CharacteristicTwo::getInstance($seq[1]);
                break;
            default:
                throw new NotSupportedException();
        }
        return new ECFieldID(
            $oid,
            $parameters
        );
    }

    /**
     * @return ECFieldID|string
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * @return null
     */
    public function getParameters()
    {
        return $this->parameters;
    }
}
