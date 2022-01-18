<?php


namespace Jazor\Math;


interface IBigInteger
{
    public function Add($x);

    public function Subtract($x);

    public function Multiply($x);

    public function Divide($x);

    public function Remainder($x);

    public function DivideAndRemainder($x): array;

    public function Mod($x);

    public function Min($x);

    public function Max($x);

    public function And($x);

    public function Or($x);

    public function Xor($x);

    public function ShiftLeft(int $bit);

    public function ShiftRight(int $bit);

    public function CompareTo($x): int;

    public function Equals($x): bool;

    public function Pow(int $exp);

    public function Not();

    public function Abs();

    public function Negate();

    public function Square();

    public function ModInverse($x);

    public function Inc();

    public function Gcd($x);

    public function getBinary(bool $unsigned = false);

    public function getSign(): int;
}
