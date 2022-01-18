<?php
namespace Jazor\Security\Oid;

class KnownECCurves
{
    const AnsiX962 = '1.2.840.10045';

    const EllipticCurve = self::AnsiX962 . '.3';
    const CTwoCurve = self::EllipticCurve . '.0';
    const C2Pnb163v1 = self::CTwoCurve . '.1';
    const C2Pnb163v2 = self::CTwoCurve . '.2';
    const C2Pnb163v3 = self::CTwoCurve . '.3';
    const C2Pnb176w1 = self::CTwoCurve . '.4';
    const C2Tnb191v1 = self::CTwoCurve . '.5';
    const C2Tnb191v2 = self::CTwoCurve . '.6';
    const C2Tnb191v3 = self::CTwoCurve . '.7';
    const C2Onb191v4 = self::CTwoCurve . '.8';
    const C2Onb191v5 = self::CTwoCurve . '.9';
    const C2Pnb208w1 = self::CTwoCurve . '.10';
    const C2Tnb239v1 = self::CTwoCurve . '.11';
    const C2Tnb239v2 = self::CTwoCurve . '.12';
    const C2Tnb239v3 = self::CTwoCurve . '.13';
    const C2Onb239v4 = self::CTwoCurve . '.14';
    const C2Onb239v5 = self::CTwoCurve . '.15';
    const C2Pnb272w1 = self::CTwoCurve . '.16';
    const C2Pnb304w1 = self::CTwoCurve . '.17';
    const C2Tnb359v1 = self::CTwoCurve . '.18';
    const C2Pnb368w1 = self::CTwoCurve . '.19';
    const C2Tnb431r1 = self::CTwoCurve . '.20';

    const PrimeCurve = self::EllipticCurve . '.1';
    const Prime192v1 = self::PrimeCurve . '.1';
    const Prime192v2 = self::PrimeCurve . '.2';
    const Prime192v3 = self::PrimeCurve . '.3';
    const Prime239v1 = self::PrimeCurve . '.4';
    const Prime239v2 = self::PrimeCurve . '.5';
    const Prime239v3 = self::PrimeCurve . '.6';
    const Prime256v1 = self::PrimeCurve . '.7';


    const SecP192R1 = self::PrimeCurve;
    const SecP256R1 = self::EllipticCurve . '.7';


    const CerticomCurve = '1.3.132.0';
    const SecT163K1 = self::CerticomCurve . '.1';
    const SecT163R2 = self::CerticomCurve . '.15';
    const SecT283K1 = self::CerticomCurve . '.16';
    const SecT283R1 = self::CerticomCurve . '.17';
    const SecT233K1 = self::CerticomCurve . '.26';
    const SecT233R1 = self::CerticomCurve . '.27';
    const SecP224R1 = self::CerticomCurve . '.33';
    const SecP384R1 = self::CerticomCurve . '.34';
    const SecP521R1 = self::CerticomCurve . '.35';
    const SecT409K1 = self::CerticomCurve . '.36';
    const SecT409R1 = self::CerticomCurve . '.37';
    const SecT571K1 = self::CerticomCurve . '.38';
    const SecT571R1 = self::CerticomCurve . '.39';
}
