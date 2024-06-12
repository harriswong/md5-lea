## Description

A project to demonstrate md5 length extension attack. 

## Getting Started
Please read `index.php` for some examples. You can run this with `php index.php`.

### Getting the padded string include the original text:
```
`$md5->padInput($data, 16); //16 is the guessed length of the secret.`
```

### Injecting the hash into md5() and then run the next block output
Check `index.php` for more info.
```
// Take the known hash and get the big endian form, write this down
$md5->convertToBE(0xb620508e, 0x7902df26, 0xb3ba659a, 0xa0e6ea2c); 
// Put those hash in next() with all the info you already know
$md5Hash = $md5->next(
    0x8e5020b6,
    0x26df0279,
    0x9a65bab3,
    0x2ceae6a0,
    $data,
    16, // we need to guess this or bruteforce. This is the strlen($secret).
    $evilData,
);
// The output is your next hash: abfc294b5a5eab1256ed5646f36c4de2
```

## Help
Checkout this blog post for more info. https://harriswong.blog/2024/06/11/learning-the-length-extension-attack/

## Authors

Contributors names and contact info

@harriswong

## License

This project is licensed under the MIT License - see the LICENSE.md file for details

## Acknowledgments

Inspiration, code snippets, etc.
* [MD5 RFC](https://www.ietf.org/rfc/rfc1321.txt)
* [Length extension attack wiki](https://en.wikipedia.org/wiki/Length_extension_attack)
* [Skullsecurity's blog post - Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
* [How does MD5 work in very simple terms](https://www.reddit.com/r/cryptography/comments/q5ry44/how_does_md5_work_in_very_simple_terms/)
