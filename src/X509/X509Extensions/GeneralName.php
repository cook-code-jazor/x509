<?php


namespace Jazor\X509\X509Extensions;


use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\DerTag;
use Jazor\ASN1\Objects\ASN1Context;
use Jazor\ASN1\Objects\ASN1IA5String;
use Jazor\ASN1\Objects\ASN1ObjectIdentifier;
use Jazor\ASN1\Objects\ASN1OctetString;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Console;
use Jazor\NotImplementedException;
use Jazor\NotSupportedException;
use Jazor\X509\TBSCertificate;
use Jazor\X509\X509Name;

class GeneralName implements ASN1Encodable
{
    public const OtherName = 0;
    public const Rfc822Name = 1;
    public const DnsName = 2;
    public const X400Address = 3;
    public const DirectoryName = 4;
    public const EdiPartyName = 5;
    public const UniformResourceIdentifier = 6;
    public const IPAddress = 7;
    public const RegisteredID = 8;

    public static $tagNames = ['OtherName','Rfc822Name','DnsName','X400Address','DirectoryName','EdiPartyName','UniformResourceIdentifier','IPAddress','RegisteredID',];

    private int $tag;
    private ASN1Encodable $obj;
    public function __construct(int $tag, $name)
    {
        $this->tag = $tag;
        if(is_string($name)){

            switch ($tag){
                case self::Rfc822Name:
                case self::DnsName:
                case self::UniformResourceIdentifier:
                    $this->obj = new ASN1IA5String($name);
                    return;
                case self::RegisteredID:
                    $this->obj = new ASN1ObjectIdentifier($name);
                    return;
                case self::DirectoryName:
                    throw new NotImplementedException();
                case self::IPAddress:
                    $this->obj = new ASN1OctetString(self::getIpBinary($name));
                    return;
                default:
                    throw new NotSupportedException('can\'t process string for tag: ' . $tag);
            }
        }
        if($name instanceof ASN1Encodable){
            $this->obj = $name;
            return;
        }
        throw new NotSupportedException('unknown tag\''. $tag .'\'');
    }

    /**
     * @return ASN1Encodable|ASN1IA5String|ASN1ObjectIdentifier|ASN1OctetString|mixed|string|null
     * @throws NotImplementedException
     */
    public function getValue(){
        switch ($this->tag){
            case self::Rfc822Name:
            case self::DnsName:
            case self::UniformResourceIdentifier:
            case self::IPAddress:
                return $this->obj->getContents();
            case self::RegisteredID:
                return $this->obj->getValue();
            case self::DirectoryName:
                throw new NotImplementedException();
            default:
                return $this->obj;
        }
    }

    public function getEncoded()
    {
        $value = $this->obj->getEncoded();
        if($this->tag == self::DirectoryName){
            $value[0] = chr($this->tag | DerTag::ContextSpecificTagFlag | DerTag::ConstructedFlag);
        }else{
            $value[0] = chr($this->tag | DerTag::ContextSpecificTagFlag);
        }
        return $value;
    }

    public function __toString()
    {
        if($this->tag === self::DirectoryName){
            return sprintf("%s%s", self::$tagNames[$this->tag], $this->obj);
        }else{
            return sprintf("%s = %s", self::$tagNames[$this->tag], $this->obj);
        }
    }

    /**
     * @param ASN1Sequence|ASN1Context $context
     * @return static
     * @throws NotImplementedException
     * @throws NotSupportedException
     */
    public static function getInstance($context){
        $tag = $context->getTag() & 0x0f;

        if($tag == self::DirectoryName){
            $seq = new ASN1Sequence();
            $value = X509Name::getInstance($context[0]);
            $seq->addElement($value);
            return new static($tag, $seq);
        }
        $bianry = $context->getContents();

        $value = $bianry;
        switch ($tag){
            case self::Rfc822Name:
            case self::DnsName:
            case self::UniformResourceIdentifier:
                $value = new ASN1IA5String($bianry);
            break;
            case self::RegisteredID:
                $value = ASN1ObjectIdentifier::decode($bianry, 0, strlen($bianry));
                break;
            case self::IPAddress:
                $value = new ASN1OctetString($bianry);
                break;
            case self::EdiPartyName:
            case self::OtherName:
            case self::X400Address:
                $value = ASN1Reader::read($bianry);
        }

        return new static($tag, $value);
    }

    /**
     * @return int
     */
    public function getTag(): int
    {
        return $this->tag;
    }

    private static function getIpBinary($ip){
        //should do much more form check
        if(strpos($ip, ':') !== false){
            return self::getIpV6Binary($ip);
        }
        return self::getIpV4Binary($ip);
    }

    private static function getIpV6Binary($ip){
        $idx = strpos($ip, '/');
        if($idx === false){
            $ipv6Int = self::parseIPv6($ip);
            $bytes = array_new(16);
            self::copyInts($ipv6Int, $bytes, 0);
            return arr2bin($bytes);
        }
        $ipv6Int = self::parseIPv6(substr($ip, 0, $idx));
        $bytes = array_new(32);
        self::copyInts($ipv6Int, $bytes, 0);

        $mask = substr($ip, $idx + 1);
        if(strpos($mask, ':') !== false){
            $ipv6Int = self::parseIPv6($mask);
        }else{
            $ipv6Int = self::parseIPv6Mask($mask);
        }
        self::copyInts($ipv6Int, $bytes, 16);
        return arr2bin($bytes);
    }

    private static function parseIPv6Mask($mask){
        $res = array_new(8);
		$maskVal = intval($mask);

        for ($i = 0; $i != $maskVal; $i++)
        {
            $res[floor($i / 16)] |= 1 << ($i % 16);
        }
        return $res;
    }

    private static function parseIPv6($ip)
    {
        if (substr($ip, 0, 2) === '::') {
            $ip = substr($ip, 1);
        } else if (substr($ip, -2) === '::') {
            $ip = substr($ip, 0, -1);
        }

        $items = explode(':', $ip);

        $index = 0;
        $val = array_new(8);

        $doubleColon = -1;

        foreach ($items as $e) {

            if (strlen($e) == 0) {
                $doubleColon = $index;
                $val[$index++] = 0;
            } else {
                if (strpos($e, '.') === false) {
                    $val[$index++] = intval($e, 16);
                } else {
                    $tokens = explode('.', $e);
                    $val[$index++] = (intval($tokens[0]) << 8) | intval($tokens[1]);
                    $val[$index++] = (intval($tokens[2]) << 8) | intval($tokens[3]);
                }
            }
        }

        if ($index != 8) {
            $len = $index - $doubleColon;
            array_copy($val, $doubleColon, $val, 8 - $len, $len);
            for ($i = $doubleColon; $i != 8 - $len; $i++) {
                $val[$i] = 0;
            }
        }
        return $val;
    }

    private static function copyInts(array $source, array &$dest, int $offset = 0){

        for ($i = 0; $i != count($source); $i++)
			{
                $dest[($i * 2) + $offset] =  ($source[$i] >> 8) & 0xff;
                $dest[($i * 2 + 1) + $offset] = $source[$i] & 0xff;
			}
    }

    private static function getIpV4Binary($ip){
        $idx = strpos($ip, '/');
        if($idx === false){
            $bytes = array_new(4);
            self::parseIPV4($ip, $bytes);
            return arr2bin($bytes);
        }
        $bytes = array_new(8);
        self::parseIPV4(substr($ip, 0, $idx), $bytes);

        $mask = substr($ip, $idx + 1);
        if(strpos($mask, ':') !== false){
            self::parseIPV4($mask, $bytes, 4);
        }else{
            self::parseIPv4Mask($mask, $bytes, 4);
        }
        return arr2bin($bytes);
    }

    private static function parseIPV4($ip, &$addr, $offset = 0){
        $items = explode('.', $ip);
        foreach ($items as $item){
            $addr[$offset++] = intval($item);
        }
    }

    private static function parseIPv4Mask($mask, &$addr, $offset = 0){
        $maskVal = intval($mask);

        for ($i = 0; $i != $maskVal; $i++)
        {
            $addr[floor($i / 8) + $offset] |= 1 << ($i % 8);
        }
    }
}
