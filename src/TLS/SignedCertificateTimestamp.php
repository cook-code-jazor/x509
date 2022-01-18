<?php


namespace Jazor\TLS;


class SignedCertificateTimestamp
{

    private int $version = 0;
    private string $logID;
    private int $timestamp;
    private array $extensions = [];
    private DigitallySigned $digitallySigned;


    public function getEncoded(){
        $result = chr($this->version);
        $result .= $this->logID;
        $result .= pack('J', $this->timestamp);
        $result .= "\x00\x00";
        $result .= $this->digitallySigned->getEncoded();

        $len = strlen($result);

        $lenBytes = chr($len >> 8) . chr($len & 0xff);

        return $lenBytes . $result;
    }

    public function __toString()
    {
        return sprintf("Version = %s\r\nLogID = %s\r\nDateTime = %s\r\n%s",
            $this->version,
            bin2hex($this->logID),
            date('Y-m-d H:i:s', floor($this->timestamp / 1000)),
            (string)$this->digitallySigned
        );
    }

    /**
     * @return int
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * @param int $version
     */
    public function setVersion(int $version): void
    {
        $this->version = $version;
    }

    /**
     * @return string
     */
    public function getLogID(): string
    {
        return $this->logID;
    }

    /**
     * @param string $logID
     */
    public function setLogID(string $logID): void
    {
        $this->logID = $logID;
    }

    /**
     * @return int
     */
    public function getTimestamp(): int
    {
        return $this->timestamp;
    }

    /**
     * @param int $timestamp
     */
    public function setTimestamp(int $timestamp): void
    {
        $this->timestamp = $timestamp;
    }

    /**
     * @return DigitallySigned
     */
    public function getDigitallySigned(): DigitallySigned
    {
        return $this->digitallySigned;
    }

    /**
     * @param DigitallySigned $digitallySigned
     */
    public function setDigitallySigned(DigitallySigned $digitallySigned): void
    {
        $this->digitallySigned = $digitallySigned;
    }
}
