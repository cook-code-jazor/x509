<?php


namespace Jazor\ASN1;


use Jazor\ASN1\Objects\ASN1BitString;
use Jazor\ASN1\Objects\ASN1BMPString;
use Jazor\ASN1\Objects\ASN1Object;
use Jazor\ASN1\Objects\ASN1Sequence;

/**
 * Class ASN1SequenceGenerator
 * @package Jazor\ASN1
 * @method ASN1SequenceGenerator BMPString($contents = null, $contentsEncoding = null, $callback = null)
 * @method ASN1SequenceGenerator BitString($contents = null, $callback = null)
 * @method ASN1SequenceGenerator Boolean($value = null, $callback = null)
 * @method ASN1SequenceGenerator ConstructedContext($flag = 0, $callback = null)
 * @method ASN1SequenceGenerator ConstructedSequence($sequence = null, $callback = null)
 * @method ASN1SequenceGenerator ConstructedSet($sequence = null, $callback = null)
 * @method ASN1SequenceGenerator Context(int $flag = 0, $contents = null, $callback = null)
 * @method ASN1SequenceGenerator GeneralizedTime($contents = null, $callback = null)
 * @method ASN1SequenceGenerator IA5String($contents = null, $callback = null)
 * @method ASN1SequenceGenerator Integer(mixed $value = null, $callback = null)
 * @method ASN1SequenceGenerator Null()
 * @method ASN1SequenceGenerator NumericString($contents = null, $callback = null)
 * @method ASN1SequenceGenerator ObjectIdentifier($oidString, $callback = null)
 * @method ASN1SequenceGenerator OctetString($contents = null, $callback = null)
 * @method ASN1SequenceGenerator PrintableString($contents = null, $callback = null)
 * @method ASN1SequenceGenerator Utf8String($contents = null, $callback = null)
 * @method ASN1SequenceGenerator UTCTime($contents = null, $callback = null)
 * @method ASN1SequenceGenerator Set($sequence = null, $callback = null)
 * @method ASN1SequenceGenerator Sequence($sequence = null, $callback = null)
 * @method ASN1SequenceGenerator Object(ASN1Encodable $object)
 */
class ASN1SequenceGenerator
{

    private ASN1Sequence $sequence;

    /**
     * ASN1SequenceGenerator constructor.
     * @param ASN1Sequence|null $sequence
     */
    public function __construct(?ASN1Sequence $sequence = null)
    {
        $this->sequence = $sequence ?? new ASN1Sequence();
    }

    public static function create($sequence = null){
        return new static($sequence);
    }

    /**
     * @param $name
     * @param $arguments
     * @return ASN1SequenceGenerator|ASN1Encodable
     * @throws \ReflectionException
     */
    public function __call($name, $arguments)
    {
        $argsCount = count($arguments);
        if($argsCount > 0 && $arguments[0] instanceof ASN1Encodable){
            $this->sequence->addElement($arguments[0]);
            return $arguments[0];
        }
        $name = ucfirst($name);
        $class = new \ReflectionClass('Jazor\ASN1\Objects\ASN1' . $name);

        $callback = null;
        if($argsCount > 0 && $arguments[$argsCount - 1] instanceof \Closure){
            $callback = array_pop($arguments);
        }

        /**
         * @var ASN1Object $instance;
         */
        $instance = $class->newInstanceArgs($arguments);
        $return = $this;
        if ($instance instanceof ASN1Sequence){
            $return = new ASN1SequenceGenerator($instance);
            if($callback) $callback($return);
        }else{
            if($callback) $callback($instance);
        }

        $this->sequence->addElement($instance);
        return $return;
    }

    /**
     * @param string $contents
     */
    public function Raw(string $contents){
        $this->sequence->addElement(new ASN1Raw($contents));
    }

    /**
     * @param ASN1Encodable $object
     */
    public function addElement(ASN1Encodable $object){
        $this->sequence->addElement($object);
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function generate(){
        return $this->sequence->getEncoded();
    }

    /**
     * @return ASN1Sequence
     */
    public function getSequence(): ASN1Sequence
    {
        return $this->sequence;
    }
}
