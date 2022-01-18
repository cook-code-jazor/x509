<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\Objects\ASN1BitString;
use Jazor\Console;
use Jazor\UnexpectedException;

class KeyUsage implements ASN1Encodable
{
    const DigitalSignature = 128;
    const NonRepudiation = 64;
    const KeyEncipherment = 32;
    const DataEncipherment = 16;
    const KeyAgreement = 8;
    const KeyCertSign = 4;
    const CrlSign = 2;
    const EncipherOnly = 1;
    const DecipherOnly = 32768;


    private int $keyUsage = 0;

    private ?ASN1BitString $obj = null;
    /**
     * KeyUsage constructor.
     * @param ASN1BitString|int $keyUsage
     */
    public function __construct($keyUsage)
    {
        if($keyUsage instanceof ASN1BitString){
            $this->obj = $keyUsage;
            $contents = $keyUsage->getContents();
            if(strlen($contents) == 1){
                $this->keyUsage = ord($contents[0]);
            }else{
                $this->keyUsage = ord($contents[0]) | (ord($contents[1]) << 8);
            }
            return;
        }
        if(is_int($keyUsage)) throw new UnexpectedException('expect int');
        $this->keyUsage = $keyUsage;

        if($keyUsage > 256){
            $contents = chr($keyUsage & 0xff) . chr($keyUsage >> 8);
            $this->obj = new ASN1BitString($contents, 7);
        }else {

            //
            $nBits = 0;
            $val = $keyUsage;
            while ($val > 0){
                if(($val & 0x1) == 1){
                    break;
                }
                $nBits++;
                $val >>= 1;
            }
            $contents = chr($keyUsage & 0xff);
            $this->obj = new ASN1BitString($contents, $nBits);
        }
    }

    public function getEncoded()
    {
        return $this->obj->getEncoded();
    }

    public function __toString()
    {
        $result = [];

        if(($this->keyUsage & self::DigitalSignature) > 0) $result[] = 'DigitalSignature';
        if(($this->keyUsage & self::NonRepudiation) > 0) $result[] = 'NonRepudiation';
        if(($this->keyUsage & self::KeyEncipherment) > 0) $result[] = 'KeyEncipherment';
        if(($this->keyUsage & self::DataEncipherment) > 0) $result[] = 'DataEncipherment';
        if(($this->keyUsage & self::KeyAgreement) > 0) $result[] = 'KeyAgreement';
        if(($this->keyUsage & self::KeyCertSign) > 0) $result[] = 'KeyCertSign';
        if(($this->keyUsage & self::CrlSign) > 0) $result[] = 'CrlSign';
        if(($this->keyUsage & self::EncipherOnly) > 0) $result[] = 'EncipherOnly';
        if(($this->keyUsage & self::DecipherOnly) > 0) $result[] = 'DecipherOnly';

        return sprintf('%s (0x%s)', implode(', ', $result), bin2hex($this->obj->getContents()));
    }

    public static function getInstance($binary){
        $reader = ASN1Reader::read($binary);
        if(!($reader instanceof ASN1BitString)) throw new \Exception('expect \'ASN1BitString\'');
        return new static($reader);
    }
}
