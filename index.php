<?php
require_once('./include/md5.php');

$secret = 'this is a secret'; // length: 16
$data = 'A good cup of coffee!';
$evilData = 'A bad cup of coffee!'; // This is the attack.

$md5 = new MD5();
// Example: Known hash: b620508e7902df26b3ba659aa0e6ea2c, both of these should give us the same result.
// echo md5($secret . $data) . "\n";
// echo $md5->hash($secret . $data) . "\n";

// Step 1) Find the padding and generate the padded string. Note this does not include the "secret" and the "evil data".
// The function does include the original data though.
// echo $md5->padInput($data, 16); // output as string
// echo bin2hex($md5->padInput($data, 16)); // output hex if you wanna see the hex string
// echo urlencode($md5->padInput($data, 16)); // useful to attack via querystring.

// Step 2) Take the known hash and get the big endian form.
// Split MD5 128-bit output into 4 parts, 32-bit each. (4 bytes or 8 hexadecimal)
// b620508e7902df26b3ba659aa0e6ea2c becomes:
//   b620508e
//   7902df26
//   b3ba659a
//   a0e6ea2c
// The output represent the state before the next block.
// echo $md5->convertToBE(0xb620508e, 0x7902df26, 0xb3ba659a, 0xa0e6ea2c); // 8e5020b6 26df0279 9a65bab3 2ceae6a0

// Step 3), call next() by using the big endian above.
$md5Hash = $md5->next(
    0x8e5020b6,
    0x26df0279,
    0x9a65bab3,
    0x2ceae6a0,
    $data,
    16, // we need to guess this or bruteforce. This is the strlen($secret).
    $evilData,
); // output abfc294b5a5eab1256ed5646f36c4de2

// Step 4) Verify attack
// If you are attacking, you don't know the secret, but you have original data, padded string, new string, and the new hash that will verify!
// What we know: (original data) . (padded string) . (your new string), and the new hash!
// What the server will do, server will now run md5( (original data) .  (padded string) . (your new string)). Which should give us the same hash!
$serverHash = md5($secret . $md5->padInput($data, 16) . $evilData);
echo "The hash we calculate is: $md5Hash\n";
echo "The hash the server calculates is: $serverHash\n";
