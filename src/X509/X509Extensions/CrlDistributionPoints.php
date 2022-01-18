<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Console;
use Jazor\UnexpectedException;
use Jazor\X509\X509Extensions\CrlDistributionPoints\DistributionPoint;

class CrlDistributionPoints implements ASN1Encodable
{

    private array $distributionPoints = [];

    /**
     * CrlDistributionPoints constructor.
     * @param array $distributionPoints
     */
    public function __construct(array $distributionPoints)
    {
        $this->distributionPoints = $distributionPoints;
    }
    /**
     * @inheritDoc
     * @throws \Exception
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        foreach ($this->distributionPoints as $distributionPoint){
            $gen->Object($distributionPoint);
        }
        return $gen->generate();
    }

    /**
     * @return string
     */
    public function __toString()
    {
        $result = '';
        $idx = 0;
        foreach ($this->distributionPoints as $distributionPoint){
            $result .= 'DistributionPoint[' . $idx++ . "]\r\n";
            $result .= indent($distributionPoint, 2) . "\r\n";
        }
        return rtrim($result);
    }

    /**
     * @param $binary
     * @return static
     * @throws UnexpectedException|\Exception
     */
    public static function getInstance($binary){
        $seq = ASN1Reader::read($binary);
        if (!($seq instanceof ASN1Sequence)) throw new UnexpectedException('expect \'ASN1Sequence\'');

        $distributionPoints = [];
        $elements = $seq->getElements();

        foreach ($elements as $element){
            $distributionPoints[] = DistributionPoint::getInstance($element);
        }
        return new static($distributionPoints);
    }

    /**
     * @return array
     */
    public function getDistributionPoints(): array
    {
        return $this->distributionPoints;
    }
}
