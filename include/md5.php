<?php

class MD5
{
    // Refer to the RFC (https://www.ietf.org/rfc/rfc1321.txt):
    //    This step uses a 64-element table T[1 ... 64] constructed from the
    //    sine function. Let T[i] denote the i-th element of the table, which
    //    is equal to the integer part of 4294967296 times abs(sin(i)), where i
    //    is in radians. The elements of the table are given in the appendix.
    // Check RFC page 12 fo rthe values.
    private const K = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, //round 1 FF
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, //round 2 GG
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, // round 3 HH
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391, // round 4, II
    ];

    // Helper functions
    private function F($x, $y, $z)
    {
        return ($x & $y) | ((~$x) & $z);
    }
    private function G($x, $y, $z)
    {
        return ($x & $z) | ($y & (~$z));
    }
    private function H($x, $y, $z)
    {
        return $x ^ $y ^ $z;
    }
    private function I($x, $y, $z)
    {
        return $y ^ ($x | (~$z));
    }
    private function leftrotate($x, $c)
    {
        return (($x << $c) | ($x >> (32 - $c))) & 0xFFFFFFFF;
    }

    /**
     * This function pads a given block with a given "guess" secret length.
     * Pads the input following MD5 algorithm. Assumes the block is no longer than 512 bits.
     *
     * When we use this for length extension attacks., we can wrap it with urlencode() ;)
     *
     * @param
     * @param $lengthOfSecretInBytes One character in PHP is 1 byte, check https://www.php.net/manual/en/language.types.string.php.
     */
    public function padInput($knownInput, $lengthOfSecretInBytes)
    {
        $fakeSecret = str_repeat('x', $lengthOfSecretInBytes); // Easier to work with if i create a fake secret
        $knownInput = $fakeSecret . $knownInput;
        $originalLen = strlen($knownInput);
        $bitLen = $originalLen * 8;
        $knownInput .= chr(0x80); //Add a single bit "1", per MD5 spec

        // Pad 0s
        while ((strlen($knownInput) % 64) != 56) { //known input + guessed input + the padded 1, 56 because the last 8 is for length.
            $knownInput .= chr(0x00);
        }
        // MD5 needs the length to be in the front, followed by 0s. Also, needs to be little endian.
        $knownInput .= pack('V', $bitLen);  // little-endian 32-bit representation of bit length
        $knownInput .= pack('V', 0); // upper 32-bits, zeroed out

        // Remove the fake input prefix
        return substr($knownInput, $lengthOfSecretInBytes);
    }

    /**
     * Convert little-endian to big-endian
     */
    public function convertToBE($a0, $b0, $c0, $d0)
    {
        return $this->convertEndianness($a0, $b0, $c0, $d0);
    }
    /**
     * Convert to little-endian. I'm pretty sure i can use the same endianness function.
     */
    public function convertToLE($a0, $b0, $c0, $d0)
    {
        return $this->convertEndianness($a0, $b0, $c0, $d0);
    }
    private function convertEndianness($a0, $b0, $c0, $d0)
    {
        return sprintf(
            '%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x',
            $a0 & 0xFF,
            ($a0 >> 8) & 0xFF,
            ($a0 >> 16) & 0xFF,
            ($a0 >> 24) & 0xFF,
            $b0 & 0xFF,
            ($b0 >> 8) & 0xFF,
            ($b0 >> 16) & 0xFF,
            ($b0 >> 24) & 0xFF,
            $c0 & 0xFF,
            ($c0 >> 8) & 0xFF,
            ($c0 >> 16) & 0xFF,
            ($c0 >> 24) & 0xFF,
            $d0 & 0xFF,
            ($d0 >> 8) & 0xFF,
            ($d0 >> 16) & 0xFF,
            ($d0 >> 24) & 0xFF
        );
    }

    public function hash($input)
    {
        // Constants for MD5
        $s = array(
            array(7, 12, 17, 22), array(5, 9, 14, 20), array(4, 11, 16, 23), array(6, 10, 15, 21)
        );

        // 64-element table. RFC page 4.
        $K = self::K;

        // Initialize variables, magic!
        $a0 = 0x67452301;
        $b0 = 0xefcdab89;
        $c0 = 0x98badcfe;
        $d0 = 0x10325476;

        // Pre-processing: padding the input
        $originalLen = strlen($input);
        $bitLen = $originalLen * 8;
        $input .= chr(0x80); //Add a single bit "1", per MD5 spec
        while ((strlen($input) % 64) != 56) {
            $input .= chr(0x00);
        }
        // MD5 needs the length to be in the front, followed by 0s. Also, needs to be little endian.
        $input .= pack('V', $bitLen);  // little-endian 32-bit representation of bit length
        $input .= pack('V', 0);         // upper 32-bits, zeroed out

        // Process the input in 512-bit chunks
        $chunks = str_split($input, 64);
        foreach ($chunks as $chunk) {
            $M = array_values(unpack('V16', $chunk));

            $A = $a0;
            $B = $b0;
            $C = $c0;
            $D = $d0;

            for ($i = 0; $i < 64; $i++) {
                if ($i < 16) {
                    $F = $this->F($B, $C, $D);
                    $g = $i;
                } elseif ($i < 32) {
                    $F = $this->G($B, $C, $D);
                    $g = (5 * $i + 1) % 16;
                } elseif ($i < 48) {
                    $F = $this->H($B, $C, $D);
                    $g = (3 * $i + 5) % 16;
                } else {
                    $F = $this->I($B, $C, $D);
                    $g = (7 * $i) % 16;
                }

                $temp = $D;
                $D = $C;
                $C = $B;
                $B = ($B + $this->leftrotate(($A + $F + $K[$i] + $M[$g]) & 0xFFFFFFFF, $s[intdiv($i, 16)][$i % 4])) & 0xFFFFFFFF;
                $A = $temp;
            }

            $a0 = ($a0 + $A) & 0xFFFFFFFF;
            $b0 = ($b0 + $B) & 0xFFFFFFFF;
            $c0 = ($c0 + $C) & 0xFFFFFFFF;
            $d0 = ($d0 + $D) & 0xFFFFFFFF;

            // This outputs debugging step so we know what the hex are before turning them into little endian.
            printf(
                "Chunk step: %08x %08x %08x %08x\n",
                $a0,
                $b0,
                $c0,
                $d0
            );
        }

        // Produce the final hash value (little-endian)
        return $this->convertToLE($a0, $b0, $c0, $d0);
    }

    /**
     * This function only calculate the "next" hash based on an existing hash. It does not tell you how many
     * padding you need.
     *
     * @param
     * @param
     * @param
     * @param
     * @param $knowData this is the know data to us
     * @param $guessedSecretLength The total length of the secret we guessed, in Bytes. Rmb PHP 1 character = 1 byte
     * @param $newString The new data we are adding as a new block
     */
    public function next($a0, $b0, $c0, $d0, $knownData, $guessedSecretLength, $newString)
    {
        $fakeInput = "1234567890123456789012345678901234567890123456789012345678901234"; // a 512 bit input
        $fakeInput .= $newString;

        // Constants for MD5
        $s = array(
            array(7, 12, 17, 22), array(5, 9, 14, 20), array(4, 11, 16, 23), array(6, 10, 15, 21)
        );

        // 64-element table. RFC page 4.
        $K = self::K;

        // Calculate data length. We need to calculate how many blocks the provided hash used. This can be found
        // by dividing the (secret . data) by 64 bytes (64 byes = 512 bit). Then we ceil() it up and that's
        // amount of blocked the hash used. Then we will add our string on top and that will be our new length.
        $numberOfBlocks = ceil(($guessedSecretLength + strlen($knownData)) / 64);
        $dataLength = $numberOfBlocks * 64 + strlen($newString);

        // Pre-processing: padding the input
        $bitLen = $dataLength * 8; // Set this to be the hacked length.
        $fakeInput .= chr(0x80); //Add a single bit "1", per MD5 spec
        while ((strlen($fakeInput) % 64) != 56) {
            $fakeInput .= chr(0x00);
        }
        // MD5 needs the length to be in the front, followed by 0s. Also, needs to be little endian.
        $fakeInput .= pack('V', $bitLen);  // little-endian 32-bit representation of bit length
        $fakeInput .= pack('V', 0);         // upper 32-bits, zeroed out

        // Process the input in 512-bit chunks
        $chunks = str_split($fakeInput, 64);

        // Ignore the first chunk because we are pretending to start from there
        $chunk = $chunks[1];
        // Set the intermediate states
        $A = $a0;
        $B = $b0;
        $C = $c0;
        $D = $d0;

        $M = array_values(unpack('V16', $chunk));

        // Run the algorithm on this block once.
        for ($i = 0; $i < 64; $i++) {
            if ($i < 16) {
                $F = $this->F($B, $C, $D);
                $g = $i;
            } elseif ($i < 32) {
                $F = $this->G($B, $C, $D);
                $g = (5 * $i + 1) % 16;
            } elseif ($i < 48) {
                $F = $this->H($B, $C, $D);
                $g = (3 * $i + 5) % 16;
            } else {
                $F = $this->I($B, $C, $D);
                $g = (7 * $i) % 16;
            }

            $temp = $D;
            $D = $C;
            $C = $B;
            $B = ($B + $this->leftrotate(($A + $F + $K[$i] + $M[$g]) & 0xFFFFFFFF, $s[intdiv($i, 16)][$i % 4])) & 0xFFFFFFFF;
            $A = $temp;
        }

        $a0 = ($a0 + $A) & 0xFFFFFFFF;
        $b0 = ($b0 + $B) & 0xFFFFFFFF;
        $c0 = ($c0 + $C) & 0xFFFFFFFF;
        $d0 = ($d0 + $D) & 0xFFFFFFFF;

        printf(
            "New chunk step: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
            $a0 & 0xFF,
            ($a0 >> 8) & 0xFF,
            ($a0 >> 16) & 0xFF,
            ($a0 >> 24) & 0xFF,
            $b0 & 0xFF,
            ($b0 >> 8) & 0xFF,
            ($b0 >> 16) & 0xFF,
            ($b0 >> 24) & 0xFF,
            $c0 & 0xFF,
            ($c0 >> 8) & 0xFF,
            ($c0 >> 16) & 0xFF,
            ($c0 >> 24) & 0xFF,
            $d0 & 0xFF,
            ($d0 >> 8) & 0xFF,
            ($d0 >> 16) & 0xFF,
            ($d0 >> 24) & 0xFF
        );

        // Produce the final hash value (little-endian)
        return $this->convertToLE($a0, $b0, $c0, $d0);
    }
}
