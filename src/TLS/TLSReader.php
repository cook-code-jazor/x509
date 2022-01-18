<?php


namespace Jazor\TLS;


class TLSReader
{
    private $data;
    private $orginPosition = 0;
    private $position = 0;
    private $end = 0;

    /**
     * TLSReader constructor.
     * @param string $binary
     * @param int $offset
     * @param int $length
     */
    public function __construct(string $binary, int $offset, int $length)
    {
        if($offset + $length > strlen($binary)) throw new \InvalidArgumentException('offset exceed');
        $this->data = $binary;
        $this->orginPosition = $offset;
        $this->position = $offset;
        $this->end = $offset + $length;
    }

    /**
     * @return int
     * @throws \Exception
     */
    private function eatLength(): int{
        if($this->position + 2 > $this->end) throw new \Exception('invalid data');
        $high = ord($this->data[$this->position++]);
        $low = ord($this->data[$this->position++]);
        $length = ($high << 8) | $low;

        if($length > 0 && $this->position + $length > $this->end) throw new \Exception('invalid data');
        return $length;
    }

    public function hasData()
    {
        return $this->position < $this->end;
    }

    /**
     * @param $length
     * @throws \Exception
     */
    private function checkData($length){
        if($this->position + $length > $this->end) throw new \Exception('invalid data');
    }

    /**
     * @throws \Exception
     */
    public function readVariable(){
        $length = $this->eatLength();
        if($length == 0) return null;
        $instance = new static($this->data, $this->position, $length);
        $this->position += $length;
        return $instance;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function readByte(){
        $this->checkData(1);
        return ord($this->data[$this->position++]);
    }

    /**
     * @param $length
     * @return false|string
     * @throws \Exception
     */
    public function readBuffer($length){
        if($length === 0){
            $data = substr($this->data, $this->position, $this->end - $this->position);
            $this->position = $this->end;
            return $data;
        }
        $this->checkData($length);
        $data = substr($this->data, $this->position, $length);
        $this->position += $length;
        return $data;
    }

    public function readInt64(){
        $data = $this->readBuffer(8);
        $result = 0;
        $idx = 0;
        while ($idx < 8){
            $result <<= 8;
            $result |= ord($data[$idx++]);
        }
        return $result;
    }



    public static function fromPayload(string $binary){
        return new static($binary, 0, strlen($binary));
    }
}
