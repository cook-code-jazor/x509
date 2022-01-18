<?php


namespace Jazor\Security\EC;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;

class ECParameters implements ASN1Encodable
{
    private int $version = 1;
    private ECFieldID $fieldID;
    private ECCurve $curve;
    private string $base;
    private string $order;
    private ?string $cofactor;

    /**
     * ECParameters constructor.
     * @param int $version
     * @param ECFieldID $fieldID
     * @param ECCurve $curve
     * @param string $base
     * @param string $order
     * @param string|null $cofactor
     */
    public function __construct(int $version, ECFieldID $fieldID, ECCurve $curve, string $base, string $order, ?string $cofactor)
    {
        $this->version = $version;
        $this->fieldID = $fieldID;
        $this->curve = $curve;
        $this->base = $base;
        $this->order = $order;
        $this->cofactor = $cofactor;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Integer($this->version);
        $gen->Object($this->fieldID);
        $gen->Object($this->curve);
        $gen->OctetString($this->base);
        $gen->Integer($this->order);

        if($this->cofactor != null) {
            $gen->Integer($this->cofactor);
        }


        return $gen->generate();
    }

    public static function getInstance(ASN1Sequence $seq){
        return new ECParameters(
            $seq[0]->getInteger(),
            ECFieldID::getInstance($seq[1]),
            ECCurve::getInstance($seq[2]),
            $seq[3]->getContents(),
            $seq[4]->getContents(),
            isset($seq[5]) ? $seq[5]->getContents() : null
        );
    }
}
